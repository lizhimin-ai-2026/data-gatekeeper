# Data Isolation Gatekeeper

> A zero-dependency, drop-in **data-access gateway** for AI agents — deny-by-default, whitelist-only, read-only least privilege, and full audit trail.
> *(Open-source release; the project was previously known only by an internal codename.)*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org)
[![Self-test](https://img.shields.io/badge/selftest-16%2F16%20passing-brightgreen.svg)]()

---

## Why

AI agents should **never** get a blank check on your database. This skill puts a *unified entry point* in front of every query: only whitelisted functions may read, only the necessary tables, only `SELECT`, and **every decision is recorded** to an audit sink. No AI can delete or over-reach — it can only be blocked, or (with a human's explicit sign-off) allowed.

**Core principle:** default deny → three-step validation → block only, never delete → human final review.

## Features

- **Deny by default** — anything outside the whitelist is rejected; least privilege (read-only, necessary tables).
- **Dual-identification** — caller name + session token; missing / invalid / expired → block. Token plaintext is returned once and **never persisted**.
- **Least privilege (SELECT-only)** — writes denied by default; explicit human override required.
- **Unified entry wrapper** — cloud-function template / decorator / FaaS handler; blocks *before* any data is returned.
- **Audit bridge** — 16-column event contract, dual-written to local + any 16-column audit sink; **degrades gracefully** when the sink is unreachable.
- **Query / stats / export** — CLI subcommands, no UI dependency, callable by both voice and click channels.
- **Zero dependencies** — pure Python 3.11+ standard library.

## Quick start

```bash
# 0) issue a session token (plaintext returned once; the store keeps only its hash)
python assets/scripts/gatekeeper.py issue-token --source my-app --ttl-seconds 3600

# 1) validate one access request (whitelisted + valid token -> ALLOW)
python assets/scripts/gatekeeper.py check --source my-app --token <tok> \
    --function read_catalog --operation SELECT --table public_catalog

# 2) human explicit grant for a write operation
python assets/scripts/gatekeeper.py override --source my-app --function read_catalog \
    --operation INSERT --table public_catalog --reason "operator: backfill initialization"

# self-test (16 cases, green gate)
python assets/scripts/gatekeeper.py --selftest
```

### As a cloud-function / FaaS wrapper

```python
from assets.scripts.gateway_wrapper import DataEntryGateway

def handler(event, context=None):   # AWS Lambda / any FaaS shape
    return DataEntryGateway().handle(event)
```

### As a decorator

```python
from assets.scripts.gateway_wrapper import gatekeep

@gatekeep("read_catalog", "SELECT", "public_catalog")
def read_catalog(request_context, *args, **kwargs):
    return db.query(...)
```

## Configuration

All behavior is **computable** from `assets/gatekeeper_rules.json` — change the rules, not the code.

| Field | Meaning |
|---|---|
| `whitelist_functions` | Allowed function whitelist |
| `allowed_tables` | Tables each whitelisted function may access |
| `allowed_operations` | Allowed ops (default `SELECT` only) |
| `denied_operations` | Explicitly denied ops (`INSERT`/`UPDATE`/`DELETE`/`DROP`…) |
| `token_validation` | Token mode / default TTL / dual-id notes |
| `overrides` | Human-grant config (max TTL / require human final) |
| `audit_bridge` | Audit-sink bridge (`enabled` + `pkg_dir` or env `AUDIT_PKG_DIR`) |

## Red lines (non-negotiable)

1. **Default deny** — anything outside the whitelist is rejected; least privilege.
2. **Block only, never delete** — blocking = refusing access; the gateway never touches underlying data.
3. **Zero sensitive values on disk** — only function / source / operation / table names; token plaintext, parameters, and secrets are never persisted.
4. **Human final review** — write-operation allows require an explicit human decision (`human_decision=override` + `note`), fully auditable.

## Project layout

```
data-gatekeeper/
├── SKILL.md
├── README.md
├── LICENSE
└── assets/
    ├── gatekeeper_rules.json       # whitelist / tables / least-privilege / token / audit bridge
    └── scripts/
        ├── gatekeeper.py           # gateway core (CLI subcommands)
        ├── gateway_wrapper.py      # cloud-function wrapper / decorator
        └── audit_bridge.py         # external audit-sink bridge (graceful degradation)
```

## License

MIT — see [LICENSE](LICENSE).
