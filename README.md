# bulletproof-runtime-security

**Runtime security and SOC2-style evidence for AI agents: identity, behavior, threats, and memory integrity.**

![bulletproof-runtime-security — overview](docs/media/infographic.png)

`bulletproof-runtime-security` watches AI agents at runtime and produces the
forensic evidence a security program needs. It provisions short-lived agent
identities, baselines and monitors behavior, detects threats and data exfiltration,
verifies memory integrity, and keeps an append-only audit trail — with a guardian
agent that can act at an advisory, semi-autonomous, or fully-autonomous level.

## Components

| Component | Role |
|-----------|------|
| **Identity lifecycle** | Issues + revokes short-lived agent credentials (TTL, revoke window) |
| **Behavioral monitor** | Baselines agent behavior and flags anomalies (z-score) |
| **Threat detection** | Detects risky commands / patterns in agent actions |
| **Memory integrity** | Verifies memory writes; quarantines/rejects anomalous ones |
| **Guardian agent** | Acts per configured autonomy: advisory, semi-autonomous, or fully-autonomous |
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
- **`GUARDIAN_AUTONOMY`** — `advisory` (log only; operator review required — the
  default) | `semi_autonomous` (auto throttle/warn, but suspend/terminate need an
  operator) | `fully_autonomous` (all actions automated; operator notified).
- **`QDRANT_URL`** — for the memory-integrity checks.
- Detection thresholds (z-scores, sigmas, TTLs) are all tunable via env.

## Development

```bash
pip install -r requirements.txt
python -m pytest
```

## Documentation

- [Overview](docs/OVERVIEW.md) — components, data flow, autonomy levels
- [Install](docs/INSTALL.md) — run from source or Docker
- [How to use](docs/HOW-TO-USE.md) — full API reference
- [Administrator guide](docs/ADMINISTRATOR.md) — configuration, thresholds, operations
- [SBOM](docs/SBOM.md) — software bill of materials ([CycloneDX](docs/bulletproof-runtime-security.cyclonedx.json))
- [Security scan report](docs/scan/scan-report.md) — Code Hardener scan (score 933, 0 critical / 0 high)

## Media

A NotebookLM-generated overview lives in [`media/`](media/): a narrated
[explainer video](media/system-overview.mp4) and a
[briefing document](media/system-overview.md). The overview infographic is
[`docs/media/infographic.png`](docs/media/infographic.png) (shown above).

## License

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
