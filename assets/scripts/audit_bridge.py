#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据隔离守门员 ·  审计底座桥接 (audit_bridge)

把一条 16 列契约事件推给  审计底座（audit_core.py ingest）。
审计底座不可达时优雅降级：只保留守门员本地事件，不阻断守门。

可复算：审计包路径来自 rules.audit_bridge.pkg_dir 或环境变量 AUDIT_PKG_DIR。
"""

import json
import os
import subprocess
import sys


def find_audit_core(pkg_dir=None):
    """定位 audit_core.py；显式 pkg_dir 优先，其次环境变量。"""
    candidates = []
    if pkg_dir:
        candidates.append(os.path.join(pkg_dir, "assets", "scripts", "audit_core.py"))
    env = os.environ.get("AUDIT_PKG_DIR")
    if env:
        candidates.append(os.path.join(env, "assets", "scripts", "audit_core.py"))
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def push_event(event, pkg_dir=None, python=None):
    """
    推送一条 16 列契约事件到  审计底座。
    返回 (ok: bool, msg: str)。
    任何失败都返回 (False, reason)，由调用方决定降级（不抛异常、不阻断守门）。
    """
    if python is None:
        python = sys.executable or "python3"
    core = find_audit_core(pkg_dir)
    if not core:
        return False, "audit-core-not-found"
    event_json = json.dumps(event, ensure_ascii=False)
    try:
        proc = subprocess.run(
            [python, core, "ingest", "--event", event_json],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode == 0:
            return True, (proc.stdout.strip() or "ingested")
        return False, (proc.stderr.strip() or "ingest-failed")[:200]
    except Exception as e:  # 超时 / 进程异常 → 降级
        return False, str(e)


if __name__ == "__main__":
    # 自测：无  包时应优雅降级
    demo = {"ts": "2026-10-17T00:00:00Z", "source": "gatekeeper",
            "event_type": "access.allow", "actor": "demo", "action": "SELECT",
            "target": "syncKnowledge:knowledge_base", "result": "ALLOW",
            "severity": "INFO", "rule_id": "allow", "evidence_hash": "deadbeef",
            "ref_id": "", "human_decision": "", "undo_ref": "", "note": "t",
            "status": "recorded", "schema_version": "1.0"}
    print(push_event(demo))
