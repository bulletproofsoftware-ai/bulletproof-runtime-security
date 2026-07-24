"""Audit bus emission (REQ-SEC-016) — at-least-once delivery to governance audit log.

Writes events to local forensic_events table AND mirrors them into the governance
audit bus SQLite database. CloudEvents-compatible schema.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from typing import Any

from .config import Config
from .db import connect, transaction


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(
    event_type: str,
    severity: str = "info",
    agent_id: str | None = None,
    session_id: str | None = None,
    payload: dict[str, Any] | None = None,
) -> str:
    """Append immutable event to forensic log AND mirror to governance audit bus.

    Returns the event_id (UUID v4) for cross-reference and forensic replay.
    """
    event_id = str(uuid.uuid4())
    timestamp = _now_iso()
    payload_json = json.dumps(payload or {}, default=str)

    # Local forensic log — primary store (REQ-SEC-017)
    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO forensic_events
                (event_id, event_type, timestamp, agent_id, session_id, severity, payload_json, delivered)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (event_id, event_type, timestamp, agent_id, session_id, severity, payload_json),
        )

    # Mirror to governance audit bus (best-effort — at-least-once via retry)
    try:
        Config.AUDIT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(str(Config.AUDIT_DB_PATH))) as gov_conn:
            gov_conn.execute("PRAGMA journal_mode=WAL")
            gov_conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    agent_id TEXT,
                    session_id TEXT,
                    severity TEXT,
                    payload_json TEXT NOT NULL,
                    source_service TEXT NOT NULL DEFAULT 'runtime-security'
                )
                """
            )
            gov_conn.execute(
                """
                INSERT OR IGNORE INTO audit_events
                    (event_id, event_type, timestamp, agent_id, session_id, severity, payload_json, source_service)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'runtime-security')
                """,
                (event_id, event_type, timestamp, agent_id, session_id, severity, payload_json),
            )
            gov_conn.commit()
        with transaction() as conn:
            conn.execute("UPDATE forensic_events SET delivered = 1 WHERE event_id = ?", (event_id,))
    except Exception:
        # Audit bus down — leave delivered=0 for retry pickup
        pass

    return event_id


def replay_session(session_id: str, since: str | None = None) -> list[dict[str, Any]]:
    """Reconstruct timeline for a session from forensic store (REQ-SEC-017)."""
    sql = "SELECT * FROM forensic_events WHERE session_id = ?"
    params: list[Any] = [session_id]
    if since:
        sql += " AND timestamp >= ?"
        params.append(since)
    sql += " ORDER BY timestamp ASC, event_id ASC"
    with closing(connect()) as conn:
        rows = conn.execute(sql, params).fetchall()
        return [_row_to_event(r) for r in rows]


def replay_agent(agent_id: str, since: str | None = None, limit: int = 1000) -> list[dict[str, Any]]:
    sql = "SELECT * FROM forensic_events WHERE agent_id = ?"
    params: list[Any] = [agent_id]
    if since:
        sql += " AND timestamp >= ?"
        params.append(since)
    sql += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    with closing(connect()) as conn:
        rows = conn.execute(sql, params).fetchall()
        return [_row_to_event(r) for r in rows]


def _row_to_event(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    try:
        d["payload"] = json.loads(d.pop("payload_json"))
    except (json.JSONDecodeError, KeyError):
        d["payload"] = {}
    return d


def retry_undelivered(batch_size: int = 100) -> int:
    """At-least-once delivery: pick up undelivered events and retry mirroring."""
    delivered = 0
    with closing(connect()) as conn:
        rows = conn.execute(
            "SELECT * FROM forensic_events WHERE delivered = 0 ORDER BY timestamp ASC LIMIT ?",
            (batch_size,),
        ).fetchall()
    for row in rows:
        try:
            with closing(sqlite3.connect(str(Config.AUDIT_DB_PATH))) as gov_conn:
                gov_conn.execute(
                    """
                    INSERT OR IGNORE INTO audit_events
                        (event_id, event_type, timestamp, agent_id, session_id, severity, payload_json, source_service)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'runtime-security')
                    """,
                    (
                        row["event_id"],
                        row["event_type"],
                        row["timestamp"],
                        row["agent_id"],
                        row["session_id"],
                        row["severity"],
                        row["payload_json"],
                    ),
                )
                gov_conn.commit()
            with transaction() as conn2:
                conn2.execute("UPDATE forensic_events SET delivered = 1 WHERE event_id = ?", (row["event_id"],))
            delivered += 1
        except Exception:
            continue
    return delivered
