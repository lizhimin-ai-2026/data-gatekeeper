# 数据隔离守门员 · 核心脚本

## 概述

`gatekeeper.py` 是统一数据入口（云函数包装层）的守卫逻辑：  
对每一次数据库访问请求执行 **三步校验**（来源双标识 → 白名单函数 → 最小权限），  
输出放行/拦截判定，并将事件按  审计 16 列契约**双写**（本地 `assets/events/` +  审计底座）。

**只拦不删**：本脚本不触碰、不修改、不删除任何数据库数据，仅做访问控制判定与留痕。

## 依赖

- Python 3.11+（标准库，无第三方依赖）

## 子命令

```bash
# 校验一次访问请求并写事件
python gatekeeper.py check --source <调用方名称> --token <会话token> \
    --function <目标函数> --operation <SELECT|INSERT|...> [--table <库表名>]

# 签发会话 token（明文仅返回一次，会话存储只落 hash）
python gatekeeper.py issue-token --source <调用方名称> --ttl-seconds 3600

# 人工书面点名放行写操作/越表（人工终审留痕）
python gatekeeper.py override --source <调用方> --function <fn> \
    --operation <op> --table <t> --reason "<点名原因>"

# 查询拦截/放行记录
python gatekeeper.py query [--source X] [--function F] [--result DENY] \
    [--date-from 2026-10-01] [--date-to 2026-10-17] [--limit 20]

# 统计（拦截率、白名单使用频率）
python gatekeeper.py stats [--date-from ...] [--date-to ...]

# 导出审计报告
python gatekeeper.py export --format md|json|csv [--out report.md]

# 重放本地事件汇入  审计底座
python gatekeeper.py push-audit

# 自检（16 用例全绿门禁）
python gatekeeper.py --selftest
```

## 判定逻辑（可复算）

| 条件 | 判定 | rule_id |
| --- | --- | --- |
| 来源不可识别（缺 source/token） | `DENY · CRIT` | source-unknown |
| token 无效 / 过期 | `DENY · CRIT` | token-invalid / token-expired |
| 目标函数 ∉ 白名单 | `DENY · CRIT` | fn-not-whitelisted |
| 目标函数 ∈ 白名单 但操作 ∉ {SELECT} 且无 override | `DENY · WARN` | op-not-allowed |
| 目标表 ∉ 该函数允许表 且无 override | `DENY · WARN` | table-not-allowed |
| 人工书面点名 override | `ALLOW · WARN` | allow-override |
| 以上全部通过 | `ALLOW · INFO` | allow |

## 事件契约（对齐  审计 16 列）

```
ts,source,event_type,actor,action,target,result,severity,rule_id,evidence_hash,ref_id,human_decision,undo_ref,note,status,schema_version
```

脱敏红线：日志只记函数名/来源/操作类型/表名，**绝不记录** token 明文 / 参数值 / 密钥 / 证件值；`evidence_hash` 仅取判定依据 SHA256 指纹。

## 配套模块

- `gateway_wrapper.py`：云函数包装模板 / 装饰器（U1）—— 宿主直接引用，拦截点前置。
- `audit_bridge.py`： 审计底座桥接（U4）—— 审计底座不可达时优雅降级（只留本地），不阻断守门。

## 红线

1. 默认拒绝（白名单之外一律拒）。
2. 只拦不删（拦截=拒绝访问，不触碰数据）。
3. 敏感值零落盘（复用 bug-sweep 脱敏红线）。
4. 人工终审（AI 只拦；放行须人工逐项确认，human_decision=override + note 留痕）。
