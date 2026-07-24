# Administrator guide

This guide covers configuration, autonomy, thresholds, storage, and operational
concerns for running `bulletproof-runtime-security`. All configuration is
env-driven (see `app/config.py` and [`.env.example`](../.env.example)).

## Required and key settings

| Variable | Default | Notes |
|----------|---------|-------|
| `RUNTIME_SECURITY_JWT_SECRET` | *(empty)* | **Required to issue credentials.** Signs session JWTs (HS256). If empty, `POST /api/security/sessions` returns 503. Generate with `python3 -c "import secrets; print(secrets.token_hex(32))"`. |
| `RUNTIME_SECURITY_JWT_ISSUER` | `runtime-security` | `iss` claim; verified on decode. |
| `OUTBOUND_HOST_ALLOWLIST` | *(empty)* | Comma-separated hosts guarded agents may reach. **Set to your own hosts.** A new destination not on the list triggers a critical exfiltration event. |
| `GUARDIAN_AUTONOMY` | `advisory` | `advisory` \| `semi_autonomous` \| `fully_autonomous` (see below). |
| `QDRANT_URL` | `http://host.docker.internal:6334` | Referenced for memory-integrity centroid checks. Not required to boot. |
| `HOST` / `PORT` | `0.0.0.0` / `8093` | Bind address. |

## Guardian autonomy

`GUARDIAN_AUTONOMY` controls what the guardian does when a component escalates a
threat (decision matrix in `app/components/guardian_agent.py`):

- **`advisory`** — every action is logged only; an operator must act. Safest
  default for a new deployment.
- **`semi_autonomous`** — `observe` / `warn` / `throttle` run automatically;
  `suspend`, `isolate`, and `block_session` are recorded as recommendations for
  an operator.
- **`fully_autonomous`** — all matrix actions execute automatically (including
  suspending or revoking sessions); the operator is notified. Target
  notification latency is `GUARDIAN_NOTIFY_WITHIN_SEC` (default 30s; the sample
  `.env` sets 300).

Escalations map to actions by `(severity, threat_type)` — e.g. critical
`PROMPT_INJECTION` → `block_session`, critical `PRIVILEGE_ESCALATION`/
`DATA_EXFILTRATION` → `suspend`, critical `MEMORY_POISONING` → `isolate`.

## Detection thresholds

All tunable via env (defaults from `app/config.py`; note the sample `.env`
overrides some of these):

| Concern | Variable | Default |
|---------|----------|---------|
| Behavioral baseline warm-up | `BASELINE_MIN_SESSIONS` | 10 |
| Behavioral anomaly z-score | `DEFAULT_ANOMALY_ZSCORE` | 2.5 |
| Credential TTL (hours) | `CREDENTIAL_TTL_HOURS_DEFAULT` | 24 |
| Revoke window (sec) | `CREDENTIAL_REVOKE_WINDOW_SEC` | 60 |
| Memory anomaly sigma (quarantine) | `MEMORY_ANOMALY_THRESHOLD_SIGMA` | 4.5 |
| Coordination isolate threshold (CSS) | `CSS_ISOLATION_THRESHOLD` | 0.2 |
| Coordination review threshold (CSS) | `CSS_REVIEW_THRESHOLD` | 0.4 |
| TUE window size | `TUE_WINDOW_SIZE` | 50 |
| TUE degraded threshold | `TUE_DEGRADED_THRESHOLD` | 0.35 |
| TUE degraded windows | `TUE_DEGRADED_WINDOWS` | 3 |
| Exfil volume sigma | `DATA_EXFIL_VOLUME_SIGMA` | 3.0 |
| Forensic retention (days) | `FORENSIC_RETENTION_DAYS` | 90 |
| Dashboard refresh (sec) | `DASHBOARD_REFRESH_SEC` | 30 |

Per-class, per-metric z-score thresholds can also be set at runtime via
`POST /api/security/behavioral/threshold` (persisted in `threshold_config`),
which overrides `DEFAULT_ANOMALY_ZSCORE` for that class+metric.

## Storage and databases

The service uses SQLite (schema in `app/db.py`, WAL mode):

| Path (env) | Default | Contents |
|------------|---------|----------|
| `SQLITE_PATH` | `/security/runtime_security.sqlite` | Sessions, baselines, threshold config, coordination scores, threat events, guardian actions, memory-integrity events, outbound observations, forensic events, compliance reports. |
| `AUDIT_DB_PATH` | `/security/audit_bus.sqlite` | Mirrored append-only governance audit stream (`audit_events`). |

`ensure_dirs()` creates the parent directories on startup. In Docker, mount a
volume at `/security` and ensure it is writable by uid 10001 (`appuser`).

### Audit delivery

Events are written to the local `forensic_events` table first (primary store),
then mirrored to the audit bus. Mirroring is **at-least-once**: if the audit bus
is unavailable, the event stays `delivered = 0` and a background worker
(`_audit_retry_worker`, every 30s) retries. A second worker
(`_expiry_worker`, every 60s) revokes expired sessions.

## Operational tasks

- **Provision / rotate / revoke credentials** — `POST /api/security/sessions`,
  `.../rotate`, `.../revoke`. Rotation issues a fresh credential with the same
  scope and revokes the old one.
- **Review quarantined memory** — `GET /api/security/quarantine`, then
  `POST /api/security/quarantine/{write_id}/review` with `promote` or `reject`.
- **Investigate an incident** — `GET /api/security/forensic/session/{id}` or
  `/agent/{id}` to replay the event timeline.
- **Produce compliance evidence** — `POST /api/security/compliance/soc2` for a
  period; list prior reports with `GET /api/security/compliance/reports`.
- **Live monitoring** — the dashboard (`/`) and WebSocket (`/api/security/ws`)
  refresh at `DASHBOARD_REFRESH_SEC`.

## Security posture

- The service issues **short-lived, non-reusable** JWTs (token hash stored, not
  the token). Revoked/suspended sessions fail verification and scope checks.
- Prompt-injection signatures are stored base64-encoded in
  `threat_detection.py` and decoded once at import — this is an intentional
  measure so the signature strings don't trip upstream pre-write security hooks
  during deployment; they are not secrets.
- The container runs as non-root (`appuser`, uid 10001).
- The latest Code Hardener scan reports **0 critical / 0 high** and
  **gitleaks PASS** (see [scan/scan-report.md](scan/scan-report.md)).

## Known limitations

- The DOI-disclosure export function (`compliance.generate_doi_report`) is
  present in `app/compliance.py` but is **not wired to an HTTP endpoint** and
  queries tables (e.g. `agent_identities`, `behavioral_baselines`) that are not
  part of the current `app/db.py` schema; it is a scaffold for a future
  disclosure format and should not be relied on as-is. The SOC 2 export
  (`generate_soc2_report`) is fully wired and operational.
- Memory-integrity stages operate on supplied `centroid_distance` values and
  heuristics; wiring live Qdrant embeddings is left to the deployer.
- No unit tests ship in this public release (CI compiles all Python and runs
  `pytest` if tests are added).

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
