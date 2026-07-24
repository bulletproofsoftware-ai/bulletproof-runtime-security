# Overview

`bulletproof-runtime-security` is a FastAPI service that watches AI agents at
runtime and produces the forensic evidence a security program needs. It
provisions short-lived agent identities, baselines and monitors behavior,
detects threats and data exfiltration, verifies memory-write integrity, scores
inter-agent coordination, and keeps an append-only audit trail — fronted by a
guardian agent that can act at an advisory, semi-autonomous, or fully-autonomous
level.

The service listens on port **8093** and exposes a JSON API under
`/api/security/*`, a live WebSocket feed, and an HTML dashboard at `/`.

## Components

The app orchestrates six components (see `app/components/`), backed by an audit
bus (`app/audit.py`), a compliance-report module (`app/compliance.py`), and a
SQLite persistence layer (`app/db.py`).

| Component | Module | Role |
|-----------|--------|------|
| **Identity lifecycle** | `identity_lifecycle.py` | Issues time-scoped, non-reusable JWT session credentials through a `PROVISION → AUTHENTICATE → AUTHORIZE → MONITOR → SUSPEND → REVOKE` state machine. Supports rotation without interruption and enforces per-session scope on every access check. |
| **Behavioral monitor** | `behavioral_monitor.py` | Builds per-agent baselines (mean/stddev/p95) via a running (Welford-style) update, then flags z-score anomalies once enough samples are collected. Also detects outbound volume spikes and new-host destinations. |
| **Memory integrity** | `memory_integrity.py` | Runs a 4-stage write pipeline (semantic consistency → fact verification → provenance → anomaly score). Writes that fail are **quarantined or rejected**, not silently dropped; operators promote or reject quarantined writes. |
| **Coordination scorer** | `coordination_scorer.py` | Records Component Synergy Score (CSS) for agent pairs and Tool Utilization Efficacy (TUE) per agent, triggering review/isolation when thresholds are breached. |
| **Threat detection** | `threat_detection.py` | Five detectors: prompt injection (signature), memory poisoning, tool abuse (frequency), privilege escalation (scope), and data exfiltration (volume + new host). |
| **Guardian agent** | `guardian_agent.py` | Consumes signals from the other components and applies a decision matrix at the configured autonomy level. |
| **Audit** | `audit.py` | Append-only forensic event log mirrored (at-least-once, with retry) into a governance audit-bus database. Supports session/agent forensic replay. |
| **Compliance** | `compliance.py` | Generates SOC 2 Type II evidence reports from the recorded events. |

## Guardian autonomy levels

The guardian's behavior is set by `GUARDIAN_AUTONOMY`:

- **`advisory`** (default) — log only; an operator must review before any action
  is taken.
- **`semi_autonomous`** — low-impact actions (observe / warn / throttle) run
  automatically; suspend / terminate are recommended but require an operator.
- **`fully_autonomous`** — all actions are automated; the operator is notified
  (target latency `GUARDIAN_NOTIFY_WITHIN_SEC`).

## Data flow

1. A caller provisions a session for an agent → a JWT + `session_id` are issued.
2. As the agent runs, callers post behavioral samples, outbound observations,
   memory-write checks, coordination scores, and injection checks to the API.
3. Each detector emits structured events to the forensic log and, when a threat
   or anomaly is found, escalates to the **guardian**.
4. The guardian decides an action per its autonomy level and records it.
5. Every event is mirrored to the audit bus for tamper-evident retention and
   later forensic replay or SOC 2 reporting.

## Storage

- **SQLite** (`SQLITE_PATH`, default `/security/runtime_security.sqlite`) — all
  operational tables (sessions, baselines, threats, guardian actions, memory
  integrity events, coordination scores, forensic events, compliance reports).
  Schema is in `app/db.py`.
- **Audit bus SQLite** (`AUDIT_DB_PATH`) — the mirrored, append-only governance
  event stream.
- **Qdrant** (`QDRANT_URL`) — referenced by configuration for memory-integrity
  centroid-distance checks. The bundled memory-integrity stages operate on
  supplied `centroid_distance` values and heuristics; a live Qdrant connection
  is not required to run the service.

See [OVERVIEW of endpoints and usage](HOW-TO-USE.md), [INSTALL](INSTALL.md), and
the [ADMINISTRATOR guide](ADMINISTRATOR.md).

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
