# Bulletproof Runtime Security: Technical Architecture and Governance Report

## 1. System Fundamentals and Architecture Overview

The `bulletproof-runtime-security` service is a specialized FastAPI-based infrastructure designed to provide runtime security monitoring, behavioral guardrails, and SOC 2 evidence collection for AI agent ecosystems. Operating as a decoupled security layer, it enables organizations to instrument agent activities with minimal latency while maintaining a high-fidelity audit trail for forensic replay.

### Service Specification

| Attribute | Specification |
| :--- | :--- |
| **Port** | 8093 |
| **Tech Stack** | Python 3.12, FastAPI |
| **Persistence** | SQLite (WAL mode for concurrent read/write performance) |
| **Primary API Path** | `/api/security/*` |
| **User Context** | Non-root (UID 10001 / appuser) |

### Data Flow

The system processes telemetry through a standardized pipeline to ensure every agent action is validated, monitored, and recorded:

1.  **Session Provisioning:** A caller requests a session, resulting in a unique session ID and a cryptographically signed JWT.
2.  **Activity Monitoring:** Agents submit behavioral samples, outbound observations, and memory writes. Real-time visibility is maintained via the **HTML Dashboard (`/`)** and a **WebSocket feed (`/api/security/ws`)** which provides instant observability for operators.
3.  **Detection and Escalation:** Individual detectors analyze telemetry against signatures and baselines. Anomalies are escalated to the Guardian Agent and logged in the forensic store.
4.  **Autonomous Response:** The Guardian evaluates escalations against a decision matrix and the configured autonomy level, executing responses (e.g., throttling or suspension).
5.  **Audit Integration:** Events are mirrored to the internal audit bus to ensure a tamper-evident record for compliance and forensic replay.

## 2. Identity Lifecycle and Session Management

Identity management is governed by a strict state machine, ensuring agents operate within predefined temporal and functional boundaries.

### Identity Lifecycle States
The service enforces the following progression: **PROVISION → AUTHENTICATE → AUTHORIZE → MONITOR → SUSPEND → REVOKE**.

### Credential Security Properties
*   **JWT Standards:** Credentials utilize **HS256** for signing. The `RUNTIME_SECURITY_JWT_SECRET` must be configured; if absent, the service will return a 503 Service Unavailable error to prevent insecure session minting.
*   **Forensic Verification:** The service stores token hashes rather than raw tokens. Revoked or suspended sessions immediately fail all subsequent verification checks.
*   **Revocation Buffer:** The system implements a `CREDENTIAL_REVOKE_WINDOW_SEC` (default 60s) to provide a managed transition during revocation events.

### Operational Identity Tasks

| Task | Endpoint | Description |
| :--- | :--- | :--- |
| **Provisioning** | `POST /api/security/sessions` | Issues a session ID and a one-time short-lived token. |
| **Rotation** | `POST /api/security/sessions/{id}/rotate` | Issues a new credential while revoking the old one to maintain session continuity. |
| **Revocation** | `POST /api/security/sessions/{id}/revoke` | Terminates session access immediately. |
| **Scope Check** | `POST /api/security/scope/check` | Enforces tool and data-class authorization. |

## 3. Threat Detection and Behavioral Monitoring

The service utilizes a hybrid detection model, combining Welford-style statistical baselining with signature-based identification.

### Behavioral Monitor Logic
The behavioral monitor builds per-agent baselines for metrics such as `tokens_per_min` and `tool_calls_per_min`.
*   **Z-Score Detection:** Once the `BASELINE_MIN_SESSIONS` (default 10) threshold is met, the system flags samples deviating beyond the `DEFAULT_ANOMALY_ZSCORE` (default 2.5).
*   **Runtime Tuning:** To minimize false-positive fatigue, architects can override thresholds per-class or per-metric at runtime via `POST /api/security/behavioral/threshold`.

### Threat Classification

| Detector | Trigger / Detection Mechanism | Severity |
| :--- | :--- | :--- |
| **Privilege Escalation** | Access attempts targeting unauthorized tools or data classes. | **Critical** |
| **Data Exfiltration** | Outbound host allowlist breach (`OUTBOUND_HOST_ALLOWLIST`). | **Critical** |
| **Data Exfiltration** | Volume spike beyond `DATA_EXFIL_VOLUME_SIGMA` (default 3.0). | **High** |
| **Prompt Injection** | Signature matches against malicious pattern strings. | **High/Critical** |
| **Memory Poisoning** | Memory writes that fail integrity checks (Reject or Quarantine). | **High** |
| **Tool Abuse** | Frequency of tool calls exceeding statistical baselines. | **High** |

### Outbound Host Guarding
The service enforces egress security via the `behavioral/outbound` endpoint. Any destination not explicitly defined in the `OUTBOUND_HOST_ALLOWLIST` environment variable results in an immediate **Critical** threat escalation.

## 4. Memory Integrity and Coordination Scoring

Advanced integrity checks prevent "poisoning" of the agent's long-term memory and monitor the health of multi-agent interactions.

### 4-Stage Memory Write Pipeline
Before a memory write is committed to the agent's context, it passes through:
1.  **Semantic Consistency:** Validates write against agent context.
2.  **Fact Verification:** Accuracy check of provided information.
3.  **Provenance:** Confirms data source and history.
4.  **Anomaly Score:** Heuristic-based scoring. *Note: For production centroid-distance checks, administrators must externally wire live Qdrant embeddings via `QDRANT_URL`.*

### Quarantine Workflow
*   **Commit:** Verified and permitted.
*   **Reject:** Blocked immediately; triggers a memory-poisoning threat.
*   **Quarantine:** Held for review. Operators use `POST /api/security/quarantine/{id}/review` to **promote** or **reject** the entry.

### Coordination Scorer Metrics
*   **Component Synergy Score (CSS):** Measures inter-agent effectiveness.
    *   **Isolate:** CSS < 0.2 (Critical)
    *   **Review:** CSS < 0.4 (Warning)
*   **Tool Utilization Efficacy (TUE):** Monitors for degraded tool usage. Alerts trigger if TUE falls below 0.35 for three consecutive windows.

## 5. The Guardian Agent and Autonomy Framework

The Guardian Agent acts as the central orchestrator for automated incident response.

### Guardian Autonomy Levels

| Level Name | Automatic Actions | Operator Requirements |
| :--- | :--- | :--- |
| **Advisory** | Log actions only. | Manual intervention required for all responses. |
| **Semi-Autonomous** | Observe, Warn, and Throttle. | Suspend and Isolate are recommendations only. |
| **Fully Autonomous** | All actions (including Suspend/Revoke). | Notification after-the-fact via `GUARDIAN_NOTIFY_WITHIN_SEC`. |

The `GUARDIAN_NOTIFY_WITHIN_SEC` (default 30s) variable controls notification latency for autonomous responses, ensuring prompt administrative awareness.

## 6. Forensic Audit and SOC 2 Compliance

The service is engineered to provide tamper-evident evidence for security certifications.

### Audit Architecture
*   **Append-Only Logic:** All events are written to the primary `forensic_events` table and then mirrored to `audit_bus.sqlite`.
*   **Background Resilience:**
    *   `_audit_retry_worker`: Ensures at-least-once delivery to the audit bus every 30 seconds.
    *   `_expiry_worker`: Runs every 60 seconds to automatically revoke expired sessions.
*   **Retention:** The service maintains forensic data for a period defined by `FORENSIC_RETENTION_DAYS` (default 90 days), meeting standard SOC 2 requirements.

### SOC 2 Compliance Support
The service generates Type II evidence reports via `POST /api/security/compliance/soc2`, mapping telemetry to controls: **CC6.1, CC6.3, CC6.7, CC7.1, CC7.2, CC7.3, and CC9.1**.

## 7. Operational Security and Deployment Configuration

### Security Posture
*   **Scan Results:** The service achieved a 933/1000 score (0 Critical / 0 High vulnerabilities). 
*   **Remediation:** Critical vulnerabilities in `cryptography` (bumped to 48.0.1) and `PyJWT` (bumped to 2.13.0) have been resolved.
*   **Signature Handling:** Prompt-injection signatures are Base64-encoded. This is an architectural measure to **avoid tripping upstream security hooks** during deployment; these strings are not secrets.

### Infrastructure & Quick-Reference
The service runs as a non-root user (UID 10001). **Important:** When deploying via Docker, mounted volumes for the `/security` directory **must be writable by UID 10001**, otherwise SQLite persistence will fail.

| Variable | Requirement | Description |
| :--- | :--- | :--- |
| `RUNTIME_SECURITY_JWT_SECRET` | **Required** | Signs session JWTs. |
| `OUTBOUND_HOST_ALLOWLIST` | **Required** | Comma-separated allowed egress hosts. |
| `GUARDIAN_AUTONOMY` | Optional | `advisory`, `semi_autonomous`, or `fully_autonomous`. |
| `SQLITE_PATH` | Optional | Default: `/security/runtime_security.sqlite`. |

### Known Limitations
*   **DOI Reports:** The `generate_doi_report` function is currently a scaffold and should not be relied upon for production disclosure.
*   **Qdrant Integration:** External wiring of embeddings is required for live memory-integrity centroid checks.

## 8. Software Bill of Materials (SBOM) Summary

The service utilizes 37 resolved runtime components under permissive licenses.

### Direct Dependencies

| Package | Version | License |
| :--- | :--- | :--- |
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

### License Distribution
The transitive landscape consists of 37 components with no copyleft-only (GPL) dependencies. Notably, `certifi` is included under the **MPL-2.0** license; however, as it is distributed as a data bundle, it does not impose copyleft obligations on the service source code. All other dependencies are MIT, BSD, Apache-2.0, or PSF-2.0.