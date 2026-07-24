# bulletproof-runtime-security

**Runtime security and SOC2-style evidence for AI agents: identity, behavior, threats, and memory integrity.**

`bulletproof-runtime-security` watches AI agents at runtime and produces the
forensic evidence a security program needs. It provisions short-lived agent
identities, baselines and monitors behavior, detects threats and data exfiltration,
verifies memory integrity, and keeps an append-only audit trail — with a guardian
agent that can observe, notify, or act.

## Components

| Component | Role |
|-----------|------|
| **Identity lifecycle** | Issues + revokes short-lived agent credentials (TTL, revoke window) |
| **Behavioral monitor** | Baselines agent behavior and flags anomalies (z-score) |
| **Threat detection** | Detects risky commands / patterns in agent actions |
| **Memory integrity** | Verifies memory writes; quarantines/rejects anomalous ones |
| **Guardian agent** | Observes → notifies → acts, per configured autonomy |
| **Coordination scorer** | Scores multi-agent coordination for isolation/review thresholds |
| **Audit** | Append-only forensic audit trail with configurable retention |

## Run it

```bash
pip install -r requirements.txt
cp .env.example .env       # set RUNTIME_SECURITY_JWT_SECRET + OUTBOUND_HOST_ALLOWLIST
uvicorn app.main:app --host 0.0.0.0 --port 8093
```

Or via Docker (`Dockerfile` included). A dashboard is served at `/`.

## Configuration

Everything is env-driven — see [`.env.example`](.env.example). Key settings:

- **`RUNTIME_SECURITY_JWT_SECRET`** — required; signs the API's JWTs.
- **`OUTBOUND_HOST_ALLOWLIST`** — comma-separated hosts guarded agents may reach.
  **Set this to your own allowed hosts.**
- **`GUARDIAN_AUTONOMY`** — `observe` | `notify` | `act`.
- **`QDRANT_URL`** — for the memory-integrity checks.
- Detection thresholds (z-scores, sigmas, TTLs) are all tunable via env.

## Development

```bash
pip install -r requirements.txt
python -m pytest
```

## License

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
