"""SQLite persistence layer for runtime security: audit, forensic, baselines, sessions."""

from __future__ import annotations

import sqlite3
from contextlib import closing, contextmanager
from typing import Iterator

from .config import Config

SCHEMA = """
-- Per-agent behavioral baselines (REQ-SEC-001)
CREATE TABLE IF NOT EXISTS baselines (
    agent_id TEXT NOT NULL,
    metric TEXT NOT NULL,
    mean REAL NOT NULL,
    stddev REAL NOT NULL,
    p95 REAL NOT NULL,
    sample_count INTEGER NOT NULL,
    last_updated TEXT NOT NULL,
    PRIMARY KEY (agent_id, metric)
);

-- Per-class threshold overrides (REQ-SEC-002)
CREATE TABLE IF NOT EXISTS threshold_config (
    agent_class TEXT NOT NULL,
    metric TEXT NOT NULL,
    zscore_threshold REAL NOT NULL,
    PRIMARY KEY (agent_class, metric)
);

-- Identity sessions (REQ-SEC-003/004/014)
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    agent_class TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    state TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    rotation_schedule TEXT,
    last_activity TEXT,
    risk_score REAL NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sessions_agent ON sessions(agent_id);
CREATE INDEX IF NOT EXISTS idx_sessions_state ON sessions(state);

-- Coordination scores (REQ-SEC-008/009)
CREATE TABLE IF NOT EXISTS coordination_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_pair TEXT,
    agent_id TEXT,
    metric TEXT NOT NULL,
    score REAL NOT NULL,
    window_size INTEGER,
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_coord_agent ON coordination_scores(agent_id);
CREATE INDEX IF NOT EXISTS idx_coord_pair ON coordination_scores(agent_pair);
CREATE INDEX IF NOT EXISTS idx_coord_ts ON coordination_scores(timestamp);

-- Threat events (REQ-SEC-011/012/013)
CREATE TABLE IF NOT EXISTS threat_events (
    threat_id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    agent_id TEXT,
    session_id TEXT,
    timestamp TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    recommended_action TEXT,
    handled INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_threat_severity ON threat_events(severity);
CREATE INDEX IF NOT EXISTS idx_threat_agent ON threat_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_threat_ts ON threat_events(timestamp);

-- Guardian actions (REQ-SEC-010)
CREATE TABLE IF NOT EXISTS guardian_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    session_id TEXT,
    action TEXT NOT NULL,
    autonomy_level TEXT NOT NULL,
    reason TEXT NOT NULL,
    threat_id TEXT,
    operator_notified INTEGER NOT NULL DEFAULT 0,
    notify_latency_sec REAL,
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_guardian_agent ON guardian_actions(agent_id);
CREATE INDEX IF NOT EXISTS idx_guardian_ts ON guardian_actions(timestamp);

-- Memory integrity events (REQ-SEC-005/006/007/012)
CREATE TABLE IF NOT EXISTS memory_integrity_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    write_id TEXT NOT NULL,
    agent_id TEXT,
    session_id TEXT,
    semantic_score REAL,
    fact_score REAL,
    provenance_score REAL,
    anomaly_score REAL,
    decision TEXT NOT NULL,
    namespace TEXT,
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_mi_write ON memory_integrity_events(write_id);
CREATE INDEX IF NOT EXISTS idx_mi_decision ON memory_integrity_events(decision);

-- Forensic event log (REQ-SEC-016/017)
CREATE TABLE IF NOT EXISTS forensic_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    agent_id TEXT,
    session_id TEXT,
    severity TEXT,
    payload_json TEXT NOT NULL,
    delivered INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_forensic_session ON forensic_events(session_id);
CREATE INDEX IF NOT EXISTS idx_forensic_agent ON forensic_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_forensic_ts ON forensic_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_forensic_type ON forensic_events(event_type);

-- Outbound traffic baseline (REQ-SEC-013)
CREATE TABLE IF NOT EXISTS outbound_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    destination_host TEXT NOT NULL,
    bytes_out INTEGER NOT NULL,
    data_type TEXT,
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_outbound_session ON outbound_observations(session_id);
CREATE INDEX IF NOT EXISTS idx_outbound_host ON outbound_observations(destination_host);

-- Compliance reports (REQ-SEC-018)
CREATE TABLE IF NOT EXISTS compliance_reports (
    report_id TEXT PRIMARY KEY,
    framework TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    period_start TEXT NOT NULL,
    period_end TEXT NOT NULL,
    format TEXT NOT NULL,
    signed INTEGER NOT NULL DEFAULT 0,
    artifact_path TEXT,
    operator_id TEXT
);
"""


def connect(path: str | None = None) -> sqlite3.Connection:
    p = path or str(Config.SQLITE_PATH)
    conn = sqlite3.connect(p)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init() -> None:
    with closing(connect()) as conn:
        conn.executescript(SCHEMA)
        conn.commit()


@contextmanager
def transaction(path: str | None = None) -> Iterator[sqlite3.Connection]:
    conn = connect(path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
