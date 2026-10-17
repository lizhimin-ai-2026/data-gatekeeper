#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据隔离守门员 (data-gatekeeper) — 核心脚本

统一数据入口守卫：对每一次数据库访问请求执行
  「来源双标识 → 白名单函数 → 最小权限(SELECT-only)」三步校验，
默认拒绝、只拦不删。判定事件按 16 列契约双写（本地 +  审计底座）。

铁律：
  · 默认拒绝 —— 白名单之外一律拒；最小权限（只读、必要表）。
  · 只拦不删 —— 拦截 = 拒绝访问，绝不触碰 / 修改 / 删除任何库数据。
  · 脱敏零落盘 —— token 值 / 参数值 / 密钥值绝不落盘，只落 SHA256 指纹。
  · 人工终审 —— 写操作放行须人工书面点名（override + 原因），留痕可审。

Python 3.11+ 标准库，无第三方依赖。
"""

import argparse
import csv
import hashlib
import json
import os
import secrets
import shutil
import sys
from datetime import datetime, timezone, timedelta

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RULES_PATH = os.path.join(SKILL_DIR, "assets", "gatekeeper_rules.json")
SCHEMA_VERSION = "1.0"

# 16 列契约（对齐  审计底座，唯一、不可增删列）
EVENT_COLUMNS = [
    "ts", "source", "event_type", "actor", "action", "target", "result",
    "severity", "rule_id", "evidence_hash", "ref_id", "human_decision",
    "undo_ref", "note", "status", "schema_version",
]

# 运行期数据根目录（selftest 会临时改写，避免污染包内数据）
ROOT = SKILL_DIR
# 审计底座覆盖路径（selftest 指向临时副本，避免污染真实  包）
AUDIT_PKG_OVERRIDE = None


def paths():
    """所有数据路径集中解析，便于 selftest 隔离。"""
    return {
        "assets": os.path.join(ROOT, "assets"),
        "events": os.path.join(ROOT, "assets", "events"),
        "sessions": os.path.join(ROOT, "assets", "sessions"),
        "overrides": os.path.join(ROOT, "assets", "overrides.json"),
        "rules": RULES_PATH,
    }


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------
def load_rules():
    with open(paths()["rules"], "r", encoding="utf-8") as f:
        return json.load(f)


def utc_now():
    return datetime.now(timezone.utc)


def utc_now_iso():
    return utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_evidence(*parts):
    """对判定依据做指纹（不落敏感值，只落 hash）。"""
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def hash_token(token):
    """token 值只在会话存储里落 hash；明文不出本进程之外。"""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def gen_token():
    return secrets.token_hex(16)


# --------------------------------------------------------------------------
# 会话 token（来源双标识之一）
# --------------------------------------------------------------------------
def load_sessions():
    p = paths()["sessions"]
    if not os.path.isdir(p):
        os.makedirs(p, exist_ok=True)
    fp = os.path.join(p, "sessions.json")
    if not os.path.isfile(fp):
        return []
    with open(fp, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []


def save_sessions(sessions):
    p = paths()["sessions"]
    os.makedirs(p, exist_ok=True)
    with open(os.path.join(p, "sessions.json"), "w", encoding="utf-8") as f:
        json.dump(sessions, f, ensure_ascii=False, indent=2)


def issue_token(rules, caller, ttl_seconds):
    """签发一个会话 token（明文仅本次返回，存储只落 hash）。"""
    token = gen_token()
    now = utc_now()
    expires_at = now + timedelta(seconds=ttl_seconds)
    sessions = load_sessions()
    # 同一调用方只保留最新会话
    sessions = [s for s in sessions if s.get("caller") != caller]
    sessions.append({
        "caller": caller,
        "token_hash": hash_token(token),
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ttl_seconds": ttl_seconds,
    })
    save_sessions(sessions)
    return token


def session_state(caller, token):
    """
    校验调用方 + token 双标识。
    返回 (ok, reason)。reason ∈ {ok, unknown, invalid, expired}
    """
    if not caller:
        return False, "unknown"
    if not token:
        return False, "unknown"
    sessions = load_sessions()
    match = None
    for s in sessions:
        if s.get("caller") == caller and s.get("token_hash") == hash_token(token):
            match = s
            break
    if match is None:
        # 调用方存在但 token 不对 → invalid；完全无记录 → unknown
        if any(s.get("caller") == caller for s in sessions):
            return False, "invalid"
        return False, "unknown"
    expires = datetime.strptime(match["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    if utc_now() > expires:
        return False, "expired"
    return True, "ok"


# --------------------------------------------------------------------------
# 写操作 override（人工终审）
# --------------------------------------------------------------------------
def load_overrides():
    fp = paths()["overrides"]
    if not os.path.isfile(fp):
        return []
    with open(fp, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []


def save_overrides(items):
    with open(paths()["overrides"], "w", encoding="utf-8") as f:
        json.dump(items, f, ensure_ascii=False, indent=2)


def grant_override(caller, function, operation, table, reason, ttl_seconds=0):
    """人工书面点名放行一条写操作（或越表访问）。返回 override 记录。"""
    now = utc_now()
    rec = {
        "caller": caller,
        "function": function,
        "operation": operation,
        "table": table if table is not None else "",
        "reason": reason,
        "granted_by": "human_final",  # 人工终审
        "granted_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now + timedelta(seconds=ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ") if ttl_seconds > 0 else "",
    }
    items = load_overrides()
    items.append(rec)
    save_overrides(items)
    return rec


def override_active(caller, function, operation, table):
    """查找是否有一条生效中的 override 命中本次请求。"""
    now = utc_now()
    for o in load_overrides():
        if o.get("caller") != caller:
            continue
        if o.get("function") != function:
            continue
        if o.get("operation") != operation:
            continue
        if (o.get("table") or "") != (table or ""):
            continue
        exp = o.get("expires_at")
        if exp:
            exp_dt = datetime.strptime(exp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if now > exp_dt:
                continue
        return True
    return False


# --------------------------------------------------------------------------
# 三步校验核心判定
# --------------------------------------------------------------------------
def decide(rules, caller, token, function, operation, table):
    """
    三步校验，返回 (result, severity, rule_id, note, human_decision)。
    判定可复算，所有阈值/白名单来自 rules JSON。
    """
    # ① 来源双标识
    ok, reason = session_state(caller, token)
    if not ok:
        label = {"unknown": "来源不可识别（无会话）",
                 "invalid": "会话 token 无效",
                 "expired": "会话 token 已过期"}.get(reason, "来源不可识别")
        rid = {"unknown": "source-unknown",
               "invalid": "token-invalid",
               "expired": "token-expired"}.get(reason, "source-unknown")
        return "DENY", "CRIT", rid, label, ""

    # ② 白名单函数校验
    if function not in rules.get("whitelist_functions", []):
        return "DENY", "CRIT", "fn-not-whitelisted", f"目标函数不在白名单: {function}", ""

    # ③ 最小权限：操作
    if operation not in rules.get("allowed_operations", ["SELECT"]):
        # 写操作 / 越权操作 → 检查是否有人工书面点名 override
        if override_active(caller, function, operation, table):
            return "ALLOW", "WARN", "allow-override", \
                f"人工书面点名放行(写操作): {function}/{operation}->{table}", "override"
        return "DENY", "WARN", "op-not-allowed", \
            f"操作越权(仅允许{rules.get('allowed_operations')}): {operation}", ""

    # ③ 最小权限：表
    allowed_tables = rules.get("allowed_tables", {}).get(function, [])
    if table is not None and table not in allowed_tables:
        if override_active(caller, function, operation, table):
            return "ALLOW", "WARN", "allow-override", \
                f"人工书面点名放行(越表): {function}->{table}", "override"
        return "DENY", "WARN", "table-not-allowed", f"越表访问: {function}->{table}", ""

    return "ALLOW", "INFO", "allow", f"白名单函数放行: {function}", ""


# --------------------------------------------------------------------------
# 事件落盘（16 列契约双写：本地 +  审计底座）
# --------------------------------------------------------------------------
def append_local_event(event):
    d = paths()["events"]
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "access_events.csv")
    write_header = not os.path.isfile(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=EVENT_COLUMNS)
        if write_header:
            w.writeheader()
        w.writerow(event)


def build_event(caller, function, operation, table, result, severity, rule_id, note, human_decision=""):
    ts = utc_now_iso()
    # 脱敏：evidence_hash 只取判定依据指纹，绝不取 token/参数值
    evidence = hash_evidence(caller or "", function or "", operation or "", table or "")
    return {
        "ts": ts,
        "source": "gatekeeper",
        "event_type": "access.allow" if result == "ALLOW" else "access.deny",
        "actor": caller or "unknown",
        "action": operation or "",
        "target": f"{function or ''}:{table or ''}",
        "result": result,
        "severity": severity,
        "rule_id": rule_id,
        "evidence_hash": evidence,
        "ref_id": "",
        "human_decision": human_decision,
        "undo_ref": "",
        "note": note,
        "status": "recorded",
        "schema_version": SCHEMA_VERSION,
    }


def push_to_audit(event):
    """尝试把事件推给  审计底座；不可达时优雅降级（只留本地）。"""
    try:
        import audit_bridge
        rules = load_rules()
        cfg = rules.get("audit_bridge", {})
        if not cfg.get("enabled", False):
            return False, "disabled"
        pkg = AUDIT_PKG_OVERRIDE or cfg.get("pkg_dir") or os.environ.get("AUDIT_PKG_DIR")
        ok, msg = audit_bridge.push_event(event, pkg_dir=pkg)
        return ok, msg
    except Exception as e:  # 审计底座不可达不应阻断守门
        sys.stderr.write(f"[warn] audit bridge 降级: {e}\n")
        return False, str(e)


def record_decision(caller, token, function, operation, table):
    rules = load_rules()
    result, severity, rule_id, note, hd = decide(rules, caller, token, function, operation, table)
    event = build_event(caller, function, operation, table, result, severity, rule_id, note, hd)
    append_local_event(event)
    push_to_audit(event)
    return result, severity, rule_id, note, hd, event


# --------------------------------------------------------------------------
# 查询 / 统计 / 导出
# --------------------------------------------------------------------------
def read_events():
    path = os.path.join(paths()["events"], "access_events.csv")
    if not os.path.isfile(path):
        return []
    with open(path, "r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def query_events(caller=None, function=None, result=None, date_from=None, date_to=None, limit=None):
    rows = read_events()
    out = []
    for r in rows:
        if caller and r.get("actor") != caller:
            continue
        if function and function not in r.get("target", ""):
            continue
        if result and r.get("result") != result:
            continue
        if date_from and r.get("ts", "") < date_from:
            continue
        if date_to and r.get("ts", "") > date_to:
            continue
        out.append(r)
    if limit:
        out = out[-int(limit):]
    return out


def stats_events(date_from=None, date_to=None):
    rows = query_events(date_from=date_from, date_to=date_to)
    total = len(rows)
    denied = sum(1 for r in rows if r.get("result") == "DENY")
    allowed = total - denied
    by_function = {}
    by_severity = {}
    for r in rows:
        fn = r.get("target", "").split(":")[0] or "unknown"
        by_function[fn] = by_function.get(fn, 0) + 1
        sev = r.get("severity", "INFO")
        by_severity[sev] = by_severity.get(sev, 0) + 1
    return {
        "total": total,
        "allowed": allowed,
        "denied": denied,
        "interception_rate": (denied / total) if total else 0.0,
        "by_function": by_function,
        "by_severity": by_severity,
    }


def export_events(fmt, out_path, date_from=None, date_to=None):
    rows = query_events(date_from=date_from, date_to=date_to)
    if fmt == "json":
        content = json.dumps(rows, ensure_ascii=False, indent=2)
    elif fmt == "csv":
        import io
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=EVENT_COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in EVENT_COLUMNS})
        content = buf.getvalue()
    else:  # md
        lines = ["# 数据隔离守门员 · 访问审计导出", "", f"- 事件数: {len(rows)}", ""]
        lines.append("| ts | actor | target | result | severity | rule_id | human_decision |")
        lines.append("|---|---|---|---|---|---|---|")
        for r in rows:
            lines.append("| {ts} | {actor} | {target} | {result} | {severity} | {rule_id} | {human_decision} |".format(**r))
        content = "\n".join(lines)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(content)
    else:
        print(content)
    return out_path or "<stdout>"


# --------------------------------------------------------------------------
# CLI 子命令实现
# --------------------------------------------------------------------------
def cmd_check(args):
    result, severity, rule_id, note, hd, event = record_decision(
        args.source, args.token, args.function, args.operation, args.table
    )
    print(f"{result} | {severity} | {rule_id} | {note}")
    print(f"event -> {os.path.join(paths()['events'], 'access_events.csv')}")
    return 0 if result == "ALLOW" else 1


def cmd_issue_token(args):
    rules = load_rules()
    token = issue_token(rules, args.source, args.ttl_seconds)
    print(f"ISSUED token for {args.source} (ttl={args.ttl_seconds}s):")
    print(token)
    print("[注意] token 明文仅此处展示一次；会话存储只保留其 hash，明文不落盘。")
    return 0


def cmd_override(args):
    rec = grant_override(args.source, args.function, args.operation, args.table, args.reason, args.ttl_seconds)
    print(f"OVERRIDE granted: {rec['caller']} {rec['function']}/{rec['operation']}->{rec['table']}")
    print(f"reason: {rec['reason']}  (human_final)")
    return 0


def cmd_query(args):
    rows = query_events(args.source, args.function, args.result, args.date_from, args.date_to, args.limit)
    for r in rows:
        print(f"{r.get('ts')} | {r.get('actor')} | {r.get('target')} | {r.get('result')} | {r.get('severity')} | {r.get('rule_id')} | {r.get('human_decision')}")
    print(f"-- {len(rows)} 条")
    return 0


def cmd_stats(args):
    s = stats_events(args.date_from, args.date_to)
    print(json.dumps(s, ensure_ascii=False, indent=2))
    return 0


def cmd_export(args):
    p = export_events(args.format, args.out, args.date_from, args.date_to)
    print(f"EXPORT -> {p}")
    return 0


def cmd_push_audit(args):
    rows = read_events()
    ok = 0
    for r in rows:
        good, msg = push_to_audit(r)
        if good:
            ok += 1
    print(f"PUSH-AUDIT: {ok}/{len(rows)} 成功汇入  审计底座")
    return 0


# --------------------------------------------------------------------------
# selftest（U8：旧 6 + 新 ≥8，全绿门禁）
# --------------------------------------------------------------------------
def _selftest_decide_cases(rules):
    """返回 (caller, token_or_None, function, operation, table, expected_result)。从规则动态派生，跨版本通用。"""
    fns = rules.get("whitelist_functions", [])
    tables = rules.get("allowed_tables", {})
    fn0 = fns[0] if fns else "read_catalog"
    t0 = (tables.get(fn0) or ["public_catalog"])[0]
    fn1 = fns[1] if len(fns) > 1 else None
    t1 = (tables.get(fn1) or [t0])[0] if fn1 else t0
    over_tbl = "secret_table_not_allowed"
    tok = issue_token(rules, "self-test-app", 3600)
    expired_tok = issue_token(rules, "self-test-expired", 0)  # 立即过期
    cases = []
    cases.append(("self-test-app", tok, fn0, "SELECT", t0, "ALLOW"))
    if fn1:
        cases.append(("self-test-app", tok, fn1, "SELECT", t1, "ALLOW"))
    cases += [
        ("self-test-app", tok, fn0, "SELECT", over_tbl, "DENY"),     # 越表
        ("self-test-app", tok, "evil-ai", "SELECT", t0, "DENY"),     # 非白名单
        ("self-test-app", tok, fn0, "INSERT", t0, "DENY"),            # 写操作
        ("", None, fn0, "SELECT", t0, "DENY"),                        # 来源不可识别
        ("self-test-app", None, fn0, "SELECT", t0, "DENY"),            # 缺 token
        ("self-test-expired", expired_tok, fn0, "SELECT", t0, "DENY"),  # token 过期
        ("self-test-app", "wrong-token", fn0, "SELECT", t0, "DENY"),    # token 无效
    ]
    return cases


def redaction_check(rules):
    """U7：注入含敏感值的事件，断言产物 0 敏感值落盘。"""
    sentinel = "SK-SECRET-VALUE-9f3a2b1c"  # 模拟 token/参数明文
    # 用 sentinel 当 token 跑一次判定（应当被拦截，但即便放行也不得落明文）
    issue_token(rules, "redact-probe", 3600)
    result, severity, rule_id, note, hd = decide(rules, "redact-probe", sentinel,
                                                 "syncKnowledge", "SELECT", "knowledge_base")
    event = build_event("redact-probe", "syncKnowledge", "SELECT", "knowledge_base",
                        result, severity, rule_id, note, hd)
    append_local_event(event)
    # 断言：任何字段都不得包含 sentinel 明文
    leak = any(sentinel in str(v) for v in event.values())
    # 额外断言：token 值不出现在 evidence_hash（指纹≠明文）
    hash_leak = sentinel in event["evidence_hash"]
    return (not leak) and (not hash_leak)


def run_selftest():
    global ROOT, AUDIT_PKG_OVERRIDE
    import tempfile
    rules = load_rules()
    # 隔离数据，避免污染包内 assets
    ROOT = tempfile.mkdtemp(prefix="gk-selftest-")
    # 准备临时审计底座副本：优先复制真实包，缺失时写最小可用桩（自包含验证桥接，绝不污染真实包）
    AUDIT_STUB = (
        "import argparse, csv, json, os, sys, datetime\n"
        "COLS=[\"ts\",\"source\",\"event_type\",\"actor\",\"action\",\"target\",\"result\","
        "\"severity\",\"rule_id\",\"evidence_hash\",\"ref_id\",\"human_decision\",\"undo_ref\",\"note\",\"status\",\"schema_version\"]\n"
        "def main():\n"
        "    p=argparse.ArgumentParser(); p.add_argument(\"cmd\"); p.add_argument(\"--event\")\n"
        "    a=p.parse_args()\n"
        "    if a.cmd==\"ingest\":\n"
        "        ev=json.loads(a.event)\n"
        "        for c in COLS:\n"
        "            if c not in ev: raise SystemExit(\"missing \"+c)\n"
        "        d=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),\"logs\")\n"
        "        os.makedirs(d, exist_ok=True)\n"
        "        _n=datetime.datetime.now(datetime.timezone.utc)\n"
        "        _q=f\"{_n.year}Q{(_n.month-1)//3+1}\"\n"
        "        path=os.path.join(d,f\"events_{_q}.csv\")\n"
        "        w=csv.DictWriter(open(path,\"a\",newline=\"\",encoding=\"utf-8\"),fieldnames=COLS)\n"
        "        if not os.path.exists(path): w.writeheader()\n"
        "        w.writerow(ev); print(\"INGEST OK -> \"+path)\n"
        "if __name__==\"__main__\": main()\n"
    )
    tmp_audit = os.path.join(ROOT, "audit_test_pkg")
    os.makedirs(os.path.join(tmp_audit, "assets", "scripts"), exist_ok=True)
    os.makedirs(os.path.join(tmp_audit, "assets"), exist_ok=True)
    real_audit = rules.get("audit_bridge", {}).get("pkg_dir")
    built = False
    if real_audit and os.path.isfile(os.path.join(os.path.normpath(real_audit), "assets", "scripts", "audit_core.py")):
        try:
            shutil.copy(os.path.join(os.path.normpath(real_audit), "assets", "scripts", "audit_core.py"),
                        os.path.join(tmp_audit, "assets", "scripts", "audit_core.py"))
            shutil.copy(os.path.join(os.path.normpath(real_audit), "assets", "audit_rules.json"),
                        os.path.join(tmp_audit, "assets", "audit_rules.json"))
            built = True
        except Exception:
            built = False
    if not built:
        with open(os.path.join(tmp_audit, "assets", "scripts", "audit_core.py"), "w", encoding="utf-8") as f:
            f.write(AUDIT_STUB)
        with open(os.path.join(tmp_audit, "assets", "audit_rules.json"), "w", encoding="utf-8") as f:
            f.write('{"event_columns": ["ts","source","event_type","actor","action","target","result","severity","rule_id","evidence_hash","ref_id","human_decision","undo_ref","note","status","schema_version"]}')
    AUDIT_PKG_OVERRIDE = tmp_audit
    # 从规则动态派生白名单函数/表，selftest 跨版本通用
    fns = rules.get("whitelist_functions", [])
    fn0 = fns[0] if fns else "read_catalog"
    t0 = (rules.get("allowed_tables", {}).get(fn0) or ["public_catalog"])[0]
    passed = 0
    total = 0

    def check(ok, desc):
        nonlocal passed, total
        total += 1
        passed += 1 if ok else 0
        print(f"[{'PASS' if ok else 'FAIL'}] {desc}")

    # --- 旧 6 + 新 3 = 9 条判定用例 ---
    for caller, token, fn, op, tbl, expected in _selftest_decide_cases(rules):
        res, sev, rid, note, hd = decide(rules, caller, token, fn, op, tbl)
        check(res == expected, f"判定 {caller or '<none>'}/{fn}/{op}/{tbl} -> {res} (期望 {expected})")

    # --- U1 网关接入：包装层默认拒绝未授权 ---
    try:
        import gateway_wrapper as gw
        import gatekeeper as _gk
        _gk.ROOT = ROOT
        gw_inst = gw.DataEntryGateway()
        r = gw_inst.handle({"caller": "rogue", "token": "", "function": "evil", "operation": "SELECT", "table": "x"})
        check(r["result"] == "DENY", "网关接入：未授权访问被默认拒绝")
        tok = issue_token(rules, "gw-app", 3600)
        r2 = gw_inst.handle({"caller": "gw-app", "token": tok, "function": fn0, "operation": "SELECT", "table": t0})
        check(r2["result"] == "ALLOW", "网关接入：白名单调用被放行")
    except Exception as e:
        check(False, f"网关接入测试异常: {e}")

    # --- U3 override 放行写操作 ---
    grant_override("self-test-app", fn0, "INSERT", t0, "人工点名：初始化回填", 600)
    res, sev, rid, note, hd = decide(rules, "self-test-app",
                                     issue_token(rules, "self-test-app", 3600),
                                     fn0, "INSERT", t0)
    check(res == "ALLOW" and hd == "override", "override：人工点名放行写操作并留痕")

    # --- U4 事件汇入（桥接到临时审计底座副本，验证真实 ingest）---
    ev = build_event("self-test-app", "syncKnowledge", "SELECT", "knowledge_base", "ALLOW", "INFO", "allow", "t", "")
    good, msg = push_to_audit(ev)
    now = utc_now()
    q = f"{now.year}Q{(now.month - 1) // 3 + 1}"
    audit_log = os.path.join(AUDIT_PKG_OVERRIDE or "", "assets", "logs", f"events_{q}.csv")
    ingested = os.path.isfile(audit_log)
    check(bool(good) and ingested, f"事件汇入审计底座成功 (msg={msg})")

    # --- U7 脱敏自检 ---
    check(redaction_check(rules), "脱敏自检：注入含敏感值事件，产物 0 敏感值落盘")

    # --- U6 query / stats 可用 ---
    # 写入两条可查询事件（使用 record_decision 才会落盘）
    for fn, op, tbl in [(fn0, "SELECT", t0), ("evil-ai", "SELECT", t0)]:
        t = issue_token(rules, f"q-{fn}", 3600)
        record_decision(f"q-{fn}", t, fn, op, tbl)
    rows = query_events(caller=f"q-{fn0}")
    check(len(rows) >= 1, "query：可按调用方过滤事件")
    s = stats_events()
    check("interception_rate" in s and s["total"] >= 1, "stats：可统计拦截率")

    print(f"\nselftest: {passed}/{total} 通过")
    return 0 if passed == total else 1


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(description="数据隔离守门员 (data-gatekeeper)")
    # 兼容旧 CLI：直接 python gatekeeper.py --source ... --token ... --function ... --operation ... [--table]
    p.add_argument("--source")
    p.add_argument("--token")
    p.add_argument("--function")
    p.add_argument("--operation")
    p.add_argument("--table")
    p.add_argument("--selftest", action="store_true", help="运行自检")
    sub = p.add_subparsers(dest="cmd")

    pc = sub.add_parser("check", help="校验一次访问请求并记录事件")
    pc.add_argument("--source", required=True)
    pc.add_argument("--token", required=True)
    pc.add_argument("--function", required=True)
    pc.add_argument("--operation", required=True)
    pc.add_argument("--table")

    pi = sub.add_parser("issue-token", help="签发会话 token（明文仅返回一次）")
    pi.add_argument("--source", required=True)
    pi.add_argument("--ttl-seconds", type=int, default=3600)

    po = sub.add_parser("override", help="人工书面点名放行写操作/越表（人工终审）")
    po.add_argument("--source", required=True)
    po.add_argument("--function", required=True)
    po.add_argument("--operation", required=True)
    po.add_argument("--table", default="")
    po.add_argument("--reason", required=True)
    po.add_argument("--ttl-seconds", type=int, default=0)

    pq = sub.add_parser("query", help="过滤查询拦截/放行记录")
    pq.add_argument("--source")
    pq.add_argument("--function")
    pq.add_argument("--result")
    pq.add_argument("--date-from")
    pq.add_argument("--date-to")
    pq.add_argument("--limit")

    ps = sub.add_parser("stats", help="按函数/结果/严重度/时间段统计")
    ps.add_argument("--date-from")
    ps.add_argument("--date-to")

    pe = sub.add_parser("export", help="导出审计报告 (md/json/csv)")
    pe.add_argument("--format", default="md", choices=["md", "json", "csv"])
    pe.add_argument("--out")
    pe.add_argument("--date-from")
    pe.add_argument("--date-to")

    pp = sub.add_parser("push-audit", help="把本地事件重放汇入  审计底座")

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.selftest:
        return run_selftest()

    if args.cmd == "check":
        return cmd_check(args)
    if args.cmd == "issue-token":
        return cmd_issue_token(args)
    if args.cmd == "override":
        return cmd_override(args)
    if args.cmd == "query":
        return cmd_query(args)
    if args.cmd == "stats":
        return cmd_stats(args)
    if args.cmd == "export":
        return cmd_export(args)
    if args.cmd == "push-audit":
        return cmd_push_audit(args)

    # 兼容旧调用：未给子命令但给了 --source → 视为 check
    if args.source:
        class _A:
            pass
        a = _A()
        a.source = args.source
        a.token = args.token
        a.function = args.function
        a.operation = args.operation
        a.table = args.table
        return cmd_check(a)

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
