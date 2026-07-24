# Software Bill of Materials (SBOM)

A machine-readable CycloneDX SBOM is committed alongside this file:
[`bulletproof-runtime-security.cyclonedx.json`](bulletproof-runtime-security.cyclonedx.json).
It was generated from a clean Python 3.12 virtual environment installed from the
repository's pinned [`requirements.txt`](../requirements.txt) and reflects the
**37** resolved runtime components (direct + transitive).

## Direct dependencies

These are the 10 packages pinned in `requirements.txt` (all versions are exact
pins; the `cryptography`, `PyJWT`, and `jinja2` pins were raised during security
remediation — see [scan/scan-report.md](scan/scan-report.md)).

| Package | Version | License |
|---------|---------|---------|
| fastapi | 0.115.6 | MIT |
| uvicorn[standard] | 0.34.0 | BSD-3-Clause |
| httpx | 0.28.1 | BSD-3-Clause |
| pyyaml | 6.0.2 | MIT |
| jinja2 | 3.1.6 | BSD-3-Clause |
| pydantic | 2.10.4 | MIT |
| qdrant-client | 1.12.1 | Apache-2.0 |
| numpy | 2.2.1 | BSD-3-Clause |
| PyJWT | 2.13.0 | MIT |
| cryptography | 48.0.1 | Apache-2.0 OR BSD-3-Clause |

## Transitive dependency summary

The full resolved graph is **37 components**. License distribution (permissive
throughout — MIT / BSD / Apache-2.0 dominant):

| License family | Approx. count |
|----------------|---------------|
| MIT / MIT-0 | ~15 |
| BSD (2-/3-Clause) | ~14 |
| Apache-2.0 (incl. dual Apache/BSD, Apache/MIT) | ~5 |
| PSF-2.0 (`typing_extensions`) | 1 |
| MPL-2.0 (`certifi`, dual-licensed) | 1 |

No copyleft-only (GPL/AGPL/LGPL) dependencies are present. `certifi` is
MPL-2.0 but distributed as a data bundle, which does not impose copyleft
obligations on this project's source.

Notable transitive packages include `starlette` and `anyio` (via FastAPI),
`grpcio` / `protobuf` / `portalocker` (via `qdrant-client`), `cffi` / `pycparser`
(via `cryptography`), `h11` / `h2` / `httpcore` (via `httpx`/`uvicorn`), and
`uvloop` / `watchfiles` / `websockets` (via `uvicorn[standard]`).

## Base image

The container is built `FROM python:3.12-slim` (Debian-based). See the
[`Dockerfile`](../Dockerfile) — it installs only the pinned Python requirements
and runs as a non-root `appuser` (uid 10001). Base-OS package inventory is
tracked by the container scanners (trivy/grype) in the
[scan report](scan/scan-report.md); no OS-level critical/high vulnerabilities
were reported.

## Regenerating

```bash
python3.12 -m venv .sbomenv && . .sbomenv/bin/activate
pip install -r requirements.txt
pip install cyclonedx-bom
cyclonedx-py environment .sbomenv --output-format json \
  > docs/bulletproof-runtime-security.cyclonedx.json
```

> Note: the SARIF scan report includes `SBOM-LICENSE-UNKNOWN` low-severity
> notes for a few packages — those reflect metadata the scanner could not
> classify automatically, not missing licenses. The authoritative license data
> is the table above and the committed CycloneDX file.

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
