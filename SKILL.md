# Data Isolation Gatekeeper (data-gatekeeper)

## Overview

A universal **data-access gateway** skill: a unified entry point that enforces "deny by default" for any
database access. Only whitelisted functions are allowed, and only with the least privilege (read-only,
necessary tables). Unauthorized or over-privileged access is blocked before any data is returned — the
gateway never touches, modifies, or deletes the underlying data.

**Core principle**: default deny → three-step validation → block only, never delete → human final review.
The AI has no power to fix mistakes, only to block or allow.

## When to use

- Any AI / program initiates a database access (triggered automatically at the unified entry point)
- A whitelisted function is invoked (its access scope is validated)
- A non-whitelisted function or over-privileged access (wrong table / write operation) is attempted

## Four-step contract (trigger → validate → block → record)

```
Any AI / program initiates a DB access
      │ trigger
      ▼
┌──────────────────────────────┐
│  Unified Entry (data-gatekeeper) │
│  ① source check (caller name + session token) │
│  ② whitelist check (target fn ∈ whitelist)   │
│  ③ least privilege (SELECT-only + allowed tbl) │
│  → allow / block (→ audit sink)               │
└──────────────────────────────┘
```

| Step | Check | Decision |
|---|---|---|
| ① Source | caller name + session token both identifiable | unidentifiable / invalid / expired → block (CRIT) |
| ② Whitelist | target function ∈ whitelist | not in list → block (CRIT) |
| ③ Least privilege | scope = necessary tables/fields, SELECT-only | over-table / write op → block (WARN), human override allowed |

## CLI subcommands (no UI dependency; callable by both voice and click channels)

| Subcommand | Purpose | Key args |
|---|---|---|
| `check` | validate one access request and record the event | `--source --token --function --operation [--table]` |
| `issue-token` | issue a session token (plaintext returned once; store keeps only hash) | `--source --ttl-seconds` |
| `override` | human explicit grant for a write/over-table op (auditable) | `--source --function --operation --table --reason [--ttl-seconds]` |
| `query` | filter and list block/allow records | `--source --function --result --date-from --date-to --limit` |
| `stats` | aggregate by function/result/severity/time (block rate, whitelist usage) | `[--date-from --date-to]` |
| `export` | export audit report (md/json/csv) | `--format md\|json\|csv --out [--date-from --date-to]` |
| `push-audit` | replay local events into an external 16-column audit sink | — |
| `--selftest` | self-test (16 cases, green gate) | — |

## Unified entry wrapper (U1)

`assets/scripts/gateway_wrapper.py` provides a drop-in cloud-function wrapper / decorator. The host
(your application / cloud function / FaaS) imports it directly; the block point is前置 (before any data
is returned):

```python
from gateway_wrapper import DataEntryGateway, gatekeep

gw = DataEntryGateway()
decision = gw.handle({"caller": "app", "token": "<tok>", "function": "read_catalog",
                     "operation": "SELECT", "table": "public_catalog"})
# decision = {"result": "ALLOW"/"DENY", "allowed": bool, "decision": "PASS"/"BLOCK", ...}

@gatekeep("read_catalog", "SELECT", "public_catalog")
def read_catalog(request_context, *args, **kwargs):
    return db.query(...)

def handler(event, context=None):   # AWS Lambda / any FaaS shape
    return DataEntryGateway().handle(event)
```

## Event recording (16-column contract, dual-write)

Every decision is recorded under a **16-column contract**, dual-written:
1. Local fallback: `assets/events/access_events.csv`
2. External audit sink (if `audit_bridge.enabled=true` and an audit package is reachable)

If the audit sink is unreachable, the gateway **degrades gracefully** — local events are kept, the gateway
is never blocked. See `assets/scripts/audit_bridge.py`.

| Event type | result | severity | audit fields |
|---|---|---|---|
| Whitelist allow | access.allow | INFO | source=gatekeeper, target=fn |
| Unidentified source | access.deny | CRIT | actor=unknown |
| Non-whitelisted fn | access.deny | CRIT | target=fn |
| Over-privilege (table/write) | access.deny | WARN | rule_id=least-privilege / op-not-allowed |
| Human override allow | access.allow | WARN | human_decision=override, note=reason |

## Red lines (always enforced)

1. **Default deny**: anything outside the whitelist is rejected; least privilege (read-only, necessary tables).
2. **Block only, never delete**: blocking = refusing access; the gateway never touches underlying data.
3. **Zero sensitive values on disk**: only function names / sources / operations / table names are logged;
   token plaintext / parameters / secrets are never persisted (redaction red line).
4. **Human final review**: write-operation allows require an explicit human decision
   (`human_decision=override` + `note`), fully auditable.

## Rule file

- `assets/gatekeeper_rules.json`: whitelist functions / allowed tables / least-privilege / token TTL /
  override config / audit bridge path (computable, single source of truth).
- `assets/scripts/gatekeeper.py`: the gateway core (validate + block + record + dual-write).
- `assets/scripts/gateway_wrapper.py`: cloud-function wrapper / decorator.
- `assets/scripts/audit_bridge.py`: external audit-sink bridge (graceful degradation).

## Conventions

- Python 3.11+ standard library only (no third-party dependencies).
- Every invocation appends an event to `assets/events/` (16-column contract, zero sensitive values).
- `--selftest`: 16 cases (6 legacy + 10 new) green gate.
- This skill only blocks; it performs no deletion.
