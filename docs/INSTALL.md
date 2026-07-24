# Installation

`bulletproof-runtime-security` is a single FastAPI service (Python 3.12). It has
no required external services to boot — it persists to local SQLite and will run
with just a JWT secret set.

## Requirements

- Python 3.12 (matches the Docker base image), or Docker.
- The Python dependencies pinned in [`requirements.txt`](../requirements.txt):
  `fastapi`, `uvicorn[standard]`, `httpx`, `pyyaml`, `jinja2`, `pydantic`,
  `qdrant-client`, `numpy`, `PyJWT`, `cryptography`.

## Run from source

```bash
pip install -r requirements.txt
cp .env.example .env       # then edit .env (see below)
uvicorn app.main:app --host 0.0.0.0 --port 8093
```

Open the dashboard at <http://localhost:8093/> and the health probe at
<http://localhost:8093/health>.

### Minimum configuration

Only one variable is strictly required to issue credentials:

```bash
# .env
RUNTIME_SECURITY_JWT_SECRET=<random 64-hex>   # python3 -c "import secrets; print(secrets.token_hex(32))"
```

If `RUNTIME_SECURITY_JWT_SECRET` is unset, the service still starts and serves
the dashboard/health, but `POST /api/security/sessions` returns **503** because
it refuses to mint unsigned credentials.

You should also set `OUTBOUND_HOST_ALLOWLIST` to **your own** allowed hosts so
the exfiltration detector knows which destinations are expected.

See [`.env.example`](../.env.example) and the [ADMINISTRATOR guide](ADMINISTRATOR.md)
for the full list of tunables.

## Run with Docker

A [`Dockerfile`](../Dockerfile) is included (base `python:3.12-slim`, runs as a
non-root `appuser`, healthcheck on `/health`).

```bash
docker build -t bulletproof-runtime-security .

docker run --rm -p 8093:8093 \
  -e RUNTIME_SECURITY_JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
  -e OUTBOUND_HOST_ALLOWLIST="api.anthropic.com,api.openai.com" \
  -v "$(pwd)/data:/security" \
  bulletproof-runtime-security
```

The container writes its SQLite databases under `/security` (set by
`SQLITE_PATH` / `AUDIT_DB_PATH`). Mount a volume there to persist data across
restarts. The image runs as UID 10001 (`appuser`), so the mounted directory must
be writable by that user.

## Verify the install

```bash
curl -s http://localhost:8093/health
# {"status":"ok","service":"runtime-security","components":[...],"autonomy":"advisory"}
```

## Development

```bash
pip install -r requirements.txt
python -m pytest        # see note below
```

> **Note:** the repository ships the service and a CI workflow
> (`.github/workflows/ci.yml`) that compiles all Python and runs `pytest` if a
> test suite is present. No unit tests are bundled in this public release, so
> `pytest` currently reports "no tests ran". Contributions of tests are welcome.

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
