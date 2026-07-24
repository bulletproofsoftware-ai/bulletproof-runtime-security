"""Guardian Agent — REQ-SEC-010.

Decision matrix consuming signals from all other components.
3 autonomy levels: advisory | semi_autonomous | fully_autonomous.

advisory          → log only, operator review required for any action
semi_autonomous   → log + recommend; throttle/warn auto, suspend/terminate require operator
fully_autonomous  → all actions automated; operator notified within 30 sec
"""

from __future__ import annotations

import time
from contextlib import closing
from datetime import datetime, timezone
from typing import Any

from ..audit import emit
from ..config import Config
from ..db import connect, transaction
from . import identity_lifecycle


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Decision matrix — { (severity, threat_type) : suggested_action }
DECISION_MATRIX: dict[tuple[str, str], str] = {
    ("info", "*"): "observe",
    ("warning", "*"): "warn",
    ("high", "TOOL_ABUSE"): "throttle",
    ("high", "MEMORY_POISONING"): "review",
    ("high", "DATA_EXFILTRATION"): "warn",
    ("critical", "PRIVILEGE_ESCALATION"): "suspend",
    ("critical", "PROMPT_INJECTION"): "block_session",
    ("critical", "DATA_EXFILTRATION"): "suspend",
    ("critical", "MEMORY_POISONING"): "isolate",
    ("critical", "*"): "suspend",
}


def evaluate(
    agent_id: str,
    session_id: str | None,
    threat_type: str,
    severity: str,
    threat_id: str | None = None,
    autonomy: str | None = None,
) -> dict[str, Any]:
    """Decide and (depending on autonomy) execute action."""
    autonomy = autonomy or Config.GUARDIAN_AUTONOMY
    suggested = DECISION_MATRIX.get((severity, threat_type)) or DECISION_MATRIX.get((severity, "*")) or "observe"

    executed = False
    started = time.perf_counter()

    if autonomy == "advisory":
        executed_action = "logged"
    elif autonomy == "semi_autonomous":
        if suggested in ("observe", "warn", "throttle"):
            executed_action = suggested
            executed = True
            _execute_action(agent_id, session_id, suggested)
        else:
            executed_action = f"recommend:{suggested}"
    else:  # fully_autonomous
        executed_action = suggested
        executed = True
        _execute_action(agent_id, session_id, suggested)

    notify_latency_sec = round(time.perf_counter() - started, 3)

    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO guardian_actions
                (agent_id, session_id, action, autonomy_level, reason, threat_id,
                 operator_notified, notify_latency_sec, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                agent_id,
                session_id,
                executed_action,
                autonomy,
                f"{severity} {threat_type}",
                threat_id,
                notify_latency_sec,
                _now_iso(),
            ),
        )

    emit(
        "guardian.action.taken",
        severity=severity,
        agent_id=agent_id,
        session_id=session_id,
        payload={
            "autonomy": autonomy,
            "action_suggested": suggested,
            "action_executed": executed_action,
            "executed": executed,
            "threat_id": threat_id,
            "notify_latency_sec": notify_latency_sec,
        },
    )

    return {
        "agent_id": agent_id,
        "session_id": session_id,
        "suggested_action": suggested,
        "executed_action": executed_action,
        "executed": executed,
        "autonomy": autonomy,
        "notify_latency_sec": notify_latency_sec,
    }


def _execute_action(agent_id: str, session_id: str | None, action: str) -> None:
    if not session_id:
        return
    if action in ("suspend", "isolate"):
        identity_lifecycle.transition_state(session_id, "SUSPEND", reason=f"guardian:{action}")
    elif action == "block_session":
        identity_lifecycle.revoke(session_id, reason="guardian:block_session")
    elif action == "throttle":
        # Marker only — actual throttling enforced by API gateway
        pass


def history(agent_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    with closing(connect()) as conn:
        if agent_id:
            rows = conn.execute(
                "SELECT * FROM guardian_actions WHERE agent_id = ? ORDER BY timestamp DESC LIMIT ?",
                (agent_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM guardian_actions ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]
