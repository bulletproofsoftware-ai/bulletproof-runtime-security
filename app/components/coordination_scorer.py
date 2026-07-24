"""Inter-Agent Coordination Scorer — REQ-SEC-008/009.

Component Synergy Score (CSS) for multi-agent pairs; Tool Utilization Efficacy (TUE) per agent.
"""

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
from typing import Any

from ..audit import emit
from ..config import Config
from ..db import connect, transaction


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def record_css(agent_a: str, agent_b: str, score: float) -> dict[str, Any]:
    """REQ-SEC-008: log CSS observation; trigger review/isolation per thresholds."""
    pair_key = "::".join(sorted([agent_a, agent_b]))
    with transaction() as conn:
        conn.execute(
            "INSERT INTO coordination_scores (agent_pair, metric, score, timestamp) VALUES (?, 'css', ?, ?)",
            (pair_key, score, _now_iso()),
        )
    severity_action = None
    if score < Config.CSS_ISOLATION_THRESHOLD:
        emit(
            "coordination.css.critical.breach",
            severity="critical",
            agent_id=agent_a,
            payload={"agent_b": agent_b, "css": score, "threshold": Config.CSS_ISOLATION_THRESHOLD},
        )
        severity_action = "isolate"
    elif score < Config.CSS_REVIEW_THRESHOLD:
        emit(
            "coordination.css.threshold.breach",
            severity="warning",
            agent_id=agent_a,
            payload={"agent_b": agent_b, "css": score, "threshold": Config.CSS_REVIEW_THRESHOLD},
        )
        severity_action = "review"
    return {"agent_a": agent_a, "agent_b": agent_b, "css": score, "action": severity_action}


def record_tue(agent_id: str, score: float, window_size: int | None = None) -> dict[str, Any]:
    """REQ-SEC-009: rolling 50-call TUE windows; degraded if < 0.35 for 3+ consecutive windows."""
    window_size = window_size or Config.TUE_WINDOW_SIZE
    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO coordination_scores (agent_id, metric, score, window_size, timestamp)
            VALUES (?, 'tue', ?, ?, ?)
            """,
            (agent_id, score, window_size, _now_iso()),
        )
        rows = conn.execute(
            """
            SELECT score FROM coordination_scores
            WHERE agent_id = ? AND metric = 'tue'
            ORDER BY timestamp DESC LIMIT ?
            """,
            (agent_id, Config.TUE_DEGRADED_WINDOWS),
        ).fetchall()
    consecutive_below = sum(1 for r in rows if r["score"] < Config.TUE_DEGRADED_THRESHOLD)
    flagged = consecutive_below >= Config.TUE_DEGRADED_WINDOWS
    if flagged:
        emit(
            "coordination.tue.degraded",
            severity="warning",
            agent_id=agent_id,
            payload={
                "tue": score,
                "consecutive_windows": consecutive_below,
                "threshold": Config.TUE_DEGRADED_THRESHOLD,
                "window_size": window_size,
            },
        )
    return {
        "agent_id": agent_id,
        "tue": score,
        "consecutive_below": consecutive_below,
        "flagged": flagged,
    }


def trends(agent_id: str, metric: str = "tue", limit: int = 50) -> list[dict[str, Any]]:
    with closing(connect()) as conn:
        rows = conn.execute(
            """
            SELECT timestamp, score, window_size FROM coordination_scores
            WHERE agent_id = ? AND metric = ?
            ORDER BY timestamp DESC LIMIT ?
            """,
            (agent_id, metric, limit),
        ).fetchall()
        return [dict(r) for r in rows]
