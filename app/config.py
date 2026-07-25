"""Runtime Security configuration — env-driven with sensible defaults per PRD 11."""

from __future__ import annotations

import os
from pathlib import Path


class Config:
    # Storage
    QDRANT_URL = os.environ.get("QDRANT_URL", "http://host.docker.internal:6334")
    QDRANT_API_KEY = os.environ.get("QDRANT_API_KEY", "")
    SQLITE_PATH = Path(os.environ.get("SQLITE_PATH", "./data/runtime_security.sqlite"))
    AUDIT_DB_PATH = Path(os.environ.get("AUDIT_DB_PATH", "./data/audit_bus.sqlite"))

    # Behavioral baselines (REQ-SEC-001/002)
    BASELINE_MIN_SESSIONS = int(os.environ.get("BASELINE_MIN_SESSIONS", "10"))
    DEFAULT_ANOMALY_ZSCORE = float(os.environ.get("DEFAULT_ANOMALY_ZSCORE", "2.5"))

    # Identity lifecycle (REQ-SEC-003/004/014)
    CREDENTIAL_TTL_HOURS_DEFAULT = int(os.environ.get("CREDENTIAL_TTL_HOURS_DEFAULT", "24"))
    CREDENTIAL_REVOKE_WINDOW_SEC = int(os.environ.get("CREDENTIAL_REVOKE_WINDOW_SEC", "60"))
    JWT_SECRET = os.environ.get("RUNTIME_SECURITY_JWT_SECRET", "")
    JWT_ISSUER = os.environ.get("RUNTIME_SECURITY_JWT_ISSUER", "runtime-security")

    # Memory integrity (REQ-SEC-005/006/007)
    MEMORY_ANOMALY_THRESHOLD_SIGMA = float(os.environ.get("MEMORY_ANOMALY_THRESHOLD_SIGMA", "4.5"))
    MEMORY_QUARANTINE_COLLECTION = os.environ.get("MEMORY_QUARANTINE_COLLECTION", "memory_quarantine")
    MEMORY_REJECTED_COLLECTION = os.environ.get("MEMORY_REJECTED_COLLECTION", "memory_rejected")

    # Coordination (REQ-SEC-008/009)
    CSS_ISOLATION_THRESHOLD = float(os.environ.get("CSS_ISOLATION_THRESHOLD", "0.2"))
    CSS_REVIEW_THRESHOLD = float(os.environ.get("CSS_REVIEW_THRESHOLD", "0.4"))
    TUE_WINDOW_SIZE = int(os.environ.get("TUE_WINDOW_SIZE", "50"))
    TUE_DEGRADED_THRESHOLD = float(os.environ.get("TUE_DEGRADED_THRESHOLD", "0.35"))
    TUE_DEGRADED_WINDOWS = int(os.environ.get("TUE_DEGRADED_WINDOWS", "3"))

    # Guardian (REQ-SEC-010)
    GUARDIAN_AUTONOMY = os.environ.get("GUARDIAN_AUTONOMY", "advisory")  # advisory | semi_autonomous | fully_autonomous
    GUARDIAN_NOTIFY_WITHIN_SEC = int(os.environ.get("GUARDIAN_NOTIFY_WITHIN_SEC", "30"))

    # Threat detection (REQ-SEC-011/013)
    DATA_EXFIL_VOLUME_SIGMA = float(os.environ.get("DATA_EXFIL_VOLUME_SIGMA", "3.0"))
    OUTBOUND_HOST_ALLOWLIST = [
        h.strip() for h in os.environ.get("OUTBOUND_HOST_ALLOWLIST", "").split(",") if h.strip()
    ]

    # Forensic (REQ-SEC-017)
    FORENSIC_RETENTION_DAYS = int(os.environ.get("FORENSIC_RETENTION_DAYS", "90"))

    # Dashboard (REQ-SEC-015)
    DASHBOARD_REFRESH_SEC = int(os.environ.get("DASHBOARD_REFRESH_SEC", "30"))

    # Server
    HOST = os.environ.get("HOST", "0.0.0.0")
    PORT = int(os.environ.get("PORT", "8093"))


def ensure_dirs() -> None:
    Config.SQLITE_PATH.parent.mkdir(parents=True, exist_ok=True)
    Config.AUDIT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
