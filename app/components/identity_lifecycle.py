"""Identity Lifecycle Manager — REQ-SEC-003/004/014.

PROVISION → AUTHENTICATE → AUTHORIZE → MONITOR → SUSPEND → REVOKE state machine.
Issues time-scoped non-reusable JWTs, supports rotation without interruption,
enforces scope on every access check.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from ..audit import emit
from ..config import Config
from ..db import connect, transaction

VALID_STATES = {"PROVISION", "AUTHENTICATE", "AUTHORIZE", "MONITOR", "SUSPEND", "REVOKE"}


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def provision_session(
    agent_id: str,
    agent_class: str = "default",
    scope: dict[str, Any] | None = None,
    ttl_hours: int | None = None,
    rotation_schedule: str | None = None,
) -> dict[str, Any]:
    """Issue a new session credential. Returns dict with session_id and token (only time)."""
    if not Config.JWT_SECRET:
        raise RuntimeError("RUNTIME_SECURITY_JWT_SECRET unset — cannot issue credentials")

    session_id = str(uuid.uuid4())
    nonce = secrets.token_urlsafe(16)
    ttl = ttl_hours or Config.CREDENTIAL_TTL_HOURS_DEFAULT
    issued = _now()
    expires = issued + timedelta(hours=ttl)
    scope = scope or {"tools": ["*"], "data_classification": "internal"}

    payload = {
        "iss": Config.JWT_ISSUER,
        "sub": agent_id,
        "sid": session_id,
        "scope": scope,
        "nonce": nonce,
        "iat": int(issued.timestamp()),
        "exp": int(expires.timestamp()),
    }
    token = jwt.encode(payload, Config.JWT_SECRET, algorithm="HS256")

    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO sessions
                (session_id, agent_id, agent_class, token_hash, scope_json, state,
                 issued_at, expires_at, rotation_schedule, last_activity)
            VALUES (?, ?, ?, ?, ?, 'AUTHORIZE', ?, ?, ?, ?)
            """,
            (
                session_id,
                agent_id,
                agent_class,
                _hash_token(token),
                json.dumps(scope),
                issued.isoformat(),
                expires.isoformat(),
                rotation_schedule,
                issued.isoformat(),
            ),
        )

    emit(
        "identity.state.transitioned",
        severity="info",
        agent_id=agent_id,
        session_id=session_id,
        payload={
            "from": "PROVISION",
            "to": "AUTHORIZE",
            "ttl_hours": ttl,
            "rotation_schedule": rotation_schedule,
        },
    )
    return {"session_id": session_id, "token": token, "expires_at": expires.isoformat(), "scope": scope}


def transition_state(session_id: str, new_state: str, reason: str = "") -> bool:
    if new_state not in VALID_STATES:
        return False
    with transaction() as conn:
        row = conn.execute("SELECT agent_id, state FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
        if not row:
            return False
        prev = row["state"]
        conn.execute(
            "UPDATE sessions SET state = ?, last_activity = ? WHERE session_id = ?",
            (new_state, _now().isoformat(), session_id),
        )
    emit(
        "identity.state.transitioned",
        severity="info",
        agent_id=row["agent_id"],
        session_id=session_id,
        payload={"from": prev, "to": new_state, "reason": reason},
    )
    return True


def revoke(session_id: str, reason: str = "") -> bool:
    """Revoke session credential — REQ-SEC-004 (60-sec window)."""
    return transition_state(session_id, "REVOKE", reason=reason)


def rotate(session_id: str, ttl_hours: int | None = None) -> dict[str, Any] | None:
    """Issue new credential with same scope, revoke old within 60s — REQ-SEC-004."""
    with closing(connect()) as conn:
        row = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
    if not row:
        return None
    new_session = provision_session(
        agent_id=row["agent_id"],
        agent_class=row["agent_class"],
        scope=json.loads(row["scope_json"]),
        ttl_hours=ttl_hours,
        rotation_schedule=row["rotation_schedule"],
    )
    revoke(session_id, reason="rotation")
    emit(
        "identity.state.transitioned",
        severity="info",
        agent_id=row["agent_id"],
        session_id=session_id,
        payload={"event": "rotation", "old": session_id, "new": new_session["session_id"]},
    )
    return new_session


def verify_token(token: str) -> dict[str, Any] | None:
    if not Config.JWT_SECRET:
        return None
    try:
        payload = jwt.decode(token, Config.JWT_SECRET, algorithms=["HS256"], issuer=Config.JWT_ISSUER)
    except jwt.PyJWTError:
        return None
    with closing(connect()) as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE session_id = ? AND token_hash = ?",
            (payload.get("sid"), _hash_token(token)),
        ).fetchone()
        if not row:
            return None
        if row["state"] in ("REVOKE", "SUSPEND"):
            return None
    return payload


def check_scope(session_id: str, required_tool: str, required_data_class: str = "internal") -> tuple[bool, str]:
    """REQ-SEC-014: enforce scope on every tool call. Out-of-scope = block + Critical event."""
    with closing(connect()) as conn:
        row = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
    if not row:
        return False, "session not found"
    if row["state"] in ("REVOKE", "SUSPEND"):
        return False, f"session state {row['state']}"
    scope = json.loads(row["scope_json"])
    allowed_tools = set(scope.get("tools", []))
    if "*" not in allowed_tools and required_tool not in allowed_tools:
        emit(
            "identity.scope.violation",
            severity="critical",
            agent_id=row["agent_id"],
            session_id=session_id,
            payload={"required_tool": required_tool, "scope": list(allowed_tools)},
        )
        return False, f"tool {required_tool} not in scope"
    classifications = ("public", "internal", "confidential", "restricted")
    granted = scope.get("data_classification", "internal")
    if classifications.index(required_data_class) > classifications.index(granted):
        emit(
            "identity.scope.violation",
            severity="critical",
            agent_id=row["agent_id"],
            session_id=session_id,
            payload={"required_class": required_data_class, "granted_class": granted},
        )
        return False, f"data class {required_data_class} exceeds granted {granted}"
    return True, "ok"


def list_active_sessions() -> list[dict[str, Any]]:
    with closing(connect()) as conn:
        rows = conn.execute(
            "SELECT * FROM sessions WHERE state NOT IN ('REVOKE') ORDER BY issued_at DESC"
        ).fetchall()
        return [_row_summary(dict(r)) for r in rows]


def _row_summary(d: dict[str, Any]) -> dict[str, Any]:
    d["scope"] = json.loads(d.pop("scope_json", "{}"))
    d.pop("token_hash", None)
    return d


def expire_old_credentials() -> int:
    """Background job: mark expired sessions as REVOKE."""
    expired = 0
    with transaction() as conn:
        rows = conn.execute(
            "SELECT session_id, agent_id FROM sessions WHERE state NOT IN ('REVOKE') AND expires_at < ?",
            (_now().isoformat(),),
        ).fetchall()
        for r in rows:
            conn.execute(
                "UPDATE sessions SET state = 'REVOKE', last_activity = ? WHERE session_id = ?",
                (_now().isoformat(), r["session_id"]),
            )
            expired += 1
    for r in rows:
        emit(
            "identity.state.transitioned",
            severity="info",
            agent_id=r["agent_id"],
            session_id=r["session_id"],
            payload={"to": "REVOKE", "reason": "expired"},
        )
    return expired
