# How to use

This service exposes a JSON API under `/api/security/*` on port **8093**, a
WebSocket feed, and an HTML dashboard at `/`. All request/response bodies are
JSON. Endpoints below are grouped by component; the FastAPI source of truth is
`app/main.py`.

Interactive API docs are available at <http://localhost:8093/docs> (FastAPI
Swagger UI).

## Service

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | Liveness + component list + current autonomy level. |
| `GET` | `/` | HTML dashboard (auto-refreshing). |
| `GET` | `/api/security/dashboard` | Aggregated dashboard JSON (active sessions, recent threats, quarantine, guardian actions, autonomy, refresh interval). |
| `WS` | `/api/security/ws` | Push channel; the dashboard reconnects and refreshes on each message. |

## Identity lifecycle

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/security/sessions` | Provision a session. Body: `agent_id`, `agent_class`, `scope`, `ttl_hours`. Returns `session_id`, `token` (returned once), `expires_at`, `scope`. Requires `RUNTIME_SECURITY_JWT_SECRET` (else 503). |
| `GET` | `/api/security/sessions` | List active (non-revoked) sessions. |
| `POST` | `/api/security/sessions/{session_id}/rotate` | Issue a new credential with the same scope and revoke the old one (rotation). |
| `POST` | `/api/security/sessions/{session_id}/revoke` | Revoke a session (`reason` query param). |
| `POST` | `/api/security/scope/check` | Enforce scope for a tool/data-class. Body: `session_id`, `required_tool`, `required_data_class`. A violation escalates to the guardian as **critical** (privilege escalation). |

### Example: provision, then scope-check

```bash
# Provision
curl -s -X POST http://localhost:8093/api/security/sessions \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"agent-42","agent_class":"research","scope":{"tools":["search"],"data_classification":"internal"},"ttl_hours":8}'

# Scope check (out-of-scope tool -> allowed:false + critical escalation)
curl -s -X POST http://localhost:8093/api/security/scope/check \
  -H 'Content-Type: application/json' \
  -d '{"session_id":"<from above>","required_tool":"delete_prod_db","required_data_class":"restricted"}'
```

## Behavioral monitor

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/security/behavioral/sample` | Record a metric sample and evaluate it. Body: `agent_id`, `metric`, `value`, `agent_class`, `session_id`. A z-score anomaly escalates to the guardian (`high`). Until `BASELINE_MIN_SESSIONS` samples exist, returns `active:false` with `samples_needed`. |
| `POST` | `/api/security/behavioral/threshold` | Set a per-class, per-metric z-score threshold. |
| `GET` | `/api/security/behavioral/baselines` | List baselines (optionally `?agent_id=`). |
| `POST` | `/api/security/behavioral/outbound` | Record an outbound observation. Body: `session_id`, `agent_id`, `bytes_out`, `destination_host`, `data_type`. New host outside the allowlist → **critical**; volume spike beyond `DATA_EXFIL_VOLUME_SIGMA` → **high**; both escalate to the guardian as data exfiltration. |

Default tracked metrics include `file_access_per_min`, `tool_calls_per_min`,
`tokens_per_min`, `api_calls_per_min`.

## Memory integrity

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/security/memory/check` | Evaluate a memory write through the 4-stage pipeline. Body: `content`, `agent_id`, `session_id`, `namespace`, `source_tool`, `fact_anchors`, `centroid_distance`. Returns a `decision` of `commit`, `quarantine`, or `reject`. Non-commit decisions raise a memory-poisoning threat and escalate to the guardian. |
| `GET` | `/api/security/quarantine` | List quarantined writes (`?limit=`, max 500) + count. |
| `POST` | `/api/security/quarantine/{write_id}/review` | Operator decision. Body: `action` = `promote` or `reject`, `operator`. |

## Coordination scorer

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/security/coordination/css` | Record a Component Synergy Score for a pair. Body: `agent_a`, `agent_b`, `score`. Below `CSS_ISOLATION_THRESHOLD` → isolate (critical); below `CSS_REVIEW_THRESHOLD` → review (warning). |
| `POST` | `/api/security/coordination/tue` | Record a Tool Utilization Efficacy score. Body: `agent_id`, `score`, `window_size`. Flagged when below `TUE_DEGRADED_THRESHOLD` for `TUE_DEGRADED_WINDOWS` consecutive windows. |
| `GET` | `/api/security/scores/{agent_id}` | Recent CSS + TUE trends and baselines for an agent. |

## Threat detection

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/security/threats/check` | Prompt-injection check. Body: `text`, `agent_id`, `session_id`. Signature match → `block:true` + threat id; escalates to the guardian (`high`, or `critical` on multiple signatures). |
| `GET` | `/api/security/threats` | Recent threats (`?limit=` max 500, `?hours=` max 720). |

## Guardian

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/security/guardian/actions` | Guardian action history (`?agent_id=`, `?limit=` max 500). |

Guardian actions are driven by a decision matrix keyed on `(severity,
threat_type)` and gated by the configured autonomy level (see
[OVERVIEW](OVERVIEW.md#guardian-autonomy-levels)).

## Forensic & compliance

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/security/forensic/session/{session_id}` | Replay a session's event timeline (`?since=`). |
| `GET` | `/api/security/forensic/agent/{agent_id}` | Replay an agent's events (`?since=`, `?limit=` max 5000). |
| `POST` | `/api/security/compliance/soc2` | Generate a SOC 2 Type II evidence report. Query: `period_start`, `period_end`, `fmt` (`json`\|`txt`), `operator_id`. |
| `GET` | `/api/security/compliance/reports` | List generated compliance reports. |

The SOC 2 report summarizes forensic events, guardian actions, and threats for
the period and maps to controls `CC6.1, CC6.3, CC6.7, CC7.1, CC7.2, CC7.3,
CC9.1`.

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
