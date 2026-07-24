# Security Scan Report: bulletproof-runtime-security

**Scan ID:** `749c0ae0-4755-46cf-b633-7afb97dc4ec6`
**Date:** 2026-07-24T20:23:56.454Z
**Score:** 1000/1000 (excellent)
**Branch:** main | **Commit:** `N/A`
**Profile:** standard

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 8 |
| Low | 16 |
| Info | 0 |
| **Total (open)** | **24** |

> **Note:** The counts above reflect _open_ findings only.
> 1 scanner(s) were skipped — see "Skipped Scanners" below.

## Scanners Executed

| Scanner | Status | Findings | Duration | Notes |
|---------|--------|----------|----------|-------|
| trivy | pass | 4 | 2.4s |  |
| gitleaks | pass | 0 | 0.5s |  |
| opengrep | pass | 0 | 6.0s |  |
| checkov | pass | 0 | 3.4s |  |
| grype | pass | 0 | 3.2s |  |
| syft | pass | 12 | 1.5s |  |
| package-validator | pass | 0 | 0.1s |  |
| oxlint | skipped | 0 | 0.0s | _skipped: no_matching_files_ |
| ruff | pass | 8 | 0.0s |  |
| actionlint | pass | 0 | 0.0s |  |
| jscpd | pass | 0 | 0.0s |  |
| typos | pass | 0 | 0.0s |  |
| _file_inventory | pass | 0 | 0.0s |  |

## Medium Findings (8)

### [MEDIUM] \`fastapi.responses.PlainTextResponse\` imported but unused

- **File:** `app/main.py:18`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `fastapi.responses.PlainTextResponse` imported but unused

**How to fix:** Auto-fix available: Remove unused import (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`fastapi.responses.JSONResponse\` imported but unused

- **File:** `app/main.py:18`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `fastapi.responses.JSONResponse` imported but unused

**How to fix:** Auto-fix available: Remove unused import (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`datetime.timezone\` imported but unused

- **File:** `app/main.py:13`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `datetime.timezone` imported but unused

**How to fix:** Auto-fix available: Remove unused import (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`datetime.datetime\` imported but unused

- **File:** `app/main.py:13`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `datetime.datetime` imported but unused

**How to fix:** Auto-fix available: Remove unused import (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`time\` imported but unused

- **File:** `app/main.py:11`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `time` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `time` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`statistics\` imported but unused

- **File:** `app/components/memory_integrity.py:10`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `statistics` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `statistics` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] \`math\` imported but unused

- **File:** `app/components/memory_integrity.py:9`
- **Scanner:** ruff
- **Rule:** `RUFF-F401`

**What's wrong:** `math` imported but unused

**How to fix:** Auto-fix available: Remove unused import: `math` (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

### [MEDIUM] f-string without any placeholders

- **File:** `app/compliance.py:99`
- **Scanner:** ruff
- **Rule:** `RUFF-F541`

**What's wrong:** f-string without any placeholders

**How to fix:** Auto-fix available: Remove extraneous `f` prefix (applicability: safe)

**Action:** Plan to fix this issue in your next sprint or release.

---

## Low Findings (16)

- **SBOM-LICENSE-UNKNOWN**: Unknown License: uvicorn@0.34.0 (`/requirements.txt`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: qdrant-client@1.12.1 (`/requirements.txt`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: pyyaml@6.0.2 (`/requirements.txt`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: pyjwt@2.13.0 (`/requirements.txt`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: pydantic@2.10.4 (`/requirements.txt`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: numpy@2.2.1 (`/requirements.txt`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: jinja2@3.1.6 (`/requirements.txt`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: httpx@0.28.1 (`/requirements.txt`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: fastapi@0.115.6 (`/requirements.txt`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: cryptography@48.0.1 (`/requirements.txt`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 (`/.github/workflows/ci.yml`)
- **SBOM-LICENSE-UNKNOWN**: Unknown License: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 (`/.github/workflows/ci.yml`)
- **LICENSE-Apache-2.0**: License Compliance: Apache-2.0 in  (`LICENSE`)
- **LICENSE-BSD-3-Clause**: License Compliance: BSD-3-Clause in jinja2 (`requirements.txt`)
- **LICENSE-BSD-3-Clause**: License Compliance: BSD-3-Clause in httpx (`requirements.txt`)
- **LICENSE-MIT**: License Compliance: MIT in PyJWT (`requirements.txt`)

## Skipped Scanners (1)

Scanners that did not run on this scan, with the reason why and how to enable them.

| Scanner | Reason | How to enable |
|---------|--------|---------------|
| `oxlint` | no_matching_files | No .js/.ts files found — Oxlint requires a JavaScript/TypeScript project |

## Recommendations

1. Update 4 vulnerable dependency/dependencies -- run `npm audit fix` or equivalent

---
*Generated by Code Hardener v0.1.0 | 2026-07-24T20:25:18.110Z*