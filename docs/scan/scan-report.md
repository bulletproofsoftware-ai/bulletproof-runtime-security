# Security Scan Report

`bulletproof-runtime-security` is scanned with **Code Hardener** (`standard`
profile — 12 code-appropriate scanners: trivy, gitleaks, opengrep, checkov,
grype, syft, ruff, actionlint, jscpd, typos, package-validator, plus oxlint
which auto-skips on non-JS/TS repos).

## Result

| Metric | Value |
|--------|-------|
| **Score** | **933 / 1000** |
| **Critical** | **0** |
| **High** | **0** |
| Medium | 8 (cosmetic — unused imports, one placeholder-free f-string) |
| Low | 16 (informational — license/SBOM metadata) |
| Secrets (gitleaks) | **PASS — 0** |
| Scan ID | `749c0ae0-4755-46cf-b633-7afb97dc4ec6` |
| Branch | `main` |

Signed artifacts from this scan:

- **[Attestation PDF](bulletproof-runtime-security-scan-report.pdf)** — 11-page
  Code Hardener report; page 1 is the cryptographically-signed (Ed25519)
  attestation certificate with the score.
- **[attestation.json](attestation.json)** — in-toto attestation.
- **[scan-report.sarif.json](scan-report.sarif.json)** — SARIF for CI/code-scanning ingestion.
- **[scan-report-full.md](scan-report-full.md)** — full machine-generated findings.

## Fixes applied (every CRITICAL + HIGH driven to zero)

The initial `standard` scan reported **0 critical / 11 high**. All 11 were
remediated and a clean re-scan confirmed **0 / 0**. Each fix:

| # | Finding (scanner) | Fix |
|---|-------------------|-----|
| 1 | `cryptography@44.0.0` — GHSA-537c-gmf6-5ccf, vulnerable OpenSSL in wheels (grype + trivy) | Bump `cryptography` → **48.0.1** (advisory firstPatchedVersion) |
| 2 | `cryptography@44.0.0` — CVE-2026-26007, SECT-curve subgroup attack (grype + trivy) | Same bump → **48.0.1** (≥ 46.0.5 patched) |
| 3 | `pyjwt@2.10.1` — CVE-2026-48526, auth bypass via forged JWT (grype + trivy) | Bump `PyJWT` → **2.13.0** |
| 4 | `pyjwt@2.10.1` — CVE-2026-32597, unknown `crit` header extensions (grype + trivy) | Same bump → **2.13.0** (supersedes 2.12.0 patch) |
| 5 | `Dockerfile` — image runs as `root` (trivy DS-0002, opengrep `missing-user`, dockle CIS DI-0001) | Create non-root `appuser` (uid 10001), pre-create `/security`, `chown`, `USER appuser` before `CMD`. Verified: `docker run … id -un` → `appuser`. |
| 6 | `dashboard.html:153` — insecure WebSocket literal `ws://` (opengrep `detect-insecure-websocket`) | Derive the WS scheme from `location.protocol` (`http`→`ws`, `https`→`wss`) with no literal `ws://`. Behavior unchanged — HTTPS pages still use `wss://`. |

Two additional, low-risk hygiene fixes were folded in during remediation
(both were medium-severity but cheap and safe):

- Bumped `jinja2` 3.1.5 → **3.1.6** (CVE-2025-27516).
- Pinned `actions/checkout` and `actions/setup-python` in
  `.github/workflows/ci.yml` to commit SHAs (opengrep
  `github-actions-mutable-action-tag`).

Post-fix verification: the Docker image rebuilds and runs as `appuser`,
`/health` returns `ok`, the dashboard returns HTTP 200, and the bumped
dependency versions are present in the image.

## What remains (low-risk, not fixed)

These residual findings are cosmetic/informational and are **not** security
defects. Per policy we do not auto-strip them (removing "unused" imports blind
can delete defensive references, and license-metadata findings are advisory):

- **8 medium** — `ruff` `F401` unused imports (7) in `app/main.py`,
  `app/components/memory_integrity.py`, and one `F541` f-string without a
  placeholder in `app/compliance.py`. No runtime impact.
- **16 low** — `syft`/`trivy` license-metadata notes for pinned dependencies and
  the two pinned GitHub Actions (license "unknown"/"compliance" — the real
  licenses are documented in [../SBOM.md](../SBOM.md)).

`oxlint` was skipped (no JavaScript/TypeScript in this Python repo) — expected,
not a failure.

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [../../LICENSE](../../LICENSE) and [../../NOTICE](../../NOTICE).
