"""Memory Integrity Verifier — REQ-SEC-005/006/007/012.

4-stage write pipeline: semantic_consistency → fact_verification → provenance_validation → anomaly_score.
Failed writes → quarantine collection (not silently dropped). Operators promote/reject via API.
"""

from __future__ import annotations

import math
import statistics
import uuid
from contextlib import closing
from datetime import datetime, timezone
from typing import Any

from ..audit import emit
from ..config import Config
from ..db import connect, transaction

# Stage weights — tunable per namespace via env in future
STAGE_WEIGHTS = {"semantic": 0.30, "fact": 0.25, "provenance": 0.25, "anomaly": 0.20}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def stage_semantic_consistency(content: str, namespace: str) -> float:
    """Score 0..1 — heuristic: penalize very short/repetitive content."""
    if not content or len(content) < 5:
        return 0.0
    words = content.split()
    if not words:
        return 0.0
    unique_ratio = len(set(words)) / max(1, len(words))
    length_factor = min(1.0, len(content) / 200)
    return round(0.5 + 0.4 * unique_ratio + 0.1 * length_factor, 4)


def stage_fact_verification(content: str, fact_anchors: list[str] | None = None) -> float:
    """Score 0..1 — placeholder: cross-reference fact anchors. Higher = more verifiable.
    In production, queries knowledge_anchors collection.
    """
    if not fact_anchors:
        return 0.7  # neutral when no anchors provided
    matched = sum(1 for a in fact_anchors if a.lower() in content.lower())
    return round(min(1.0, 0.4 + 0.6 * (matched / len(fact_anchors))), 4)


def stage_provenance_validation(agent_id: str | None, source_tool: str | None) -> float:
    if not agent_id:
        return 0.0
    if not source_tool:
        return 0.5
    return 1.0


def stage_anomaly_score(
    content: str,
    namespace: str,
    centroid_distance: float | None = None,
    threshold_sigma: float | None = None,
) -> tuple[float, float]:
    """Returns (score_0_to_1, sigma_distance). Lower distance = more aligned with cluster."""
    threshold = threshold_sigma or Config.MEMORY_ANOMALY_THRESHOLD_SIGMA
    distance = centroid_distance if centroid_distance is not None else 1.0
    sigma = abs(distance) * 1.2  # heuristic when real embeddings absent
    if sigma >= threshold:
        return 0.0, sigma
    score = round(1.0 - (sigma / threshold), 4)
    return score, sigma


def evaluate_write(
    content: str,
    agent_id: str | None,
    session_id: str | None,
    namespace: str = "default",
    source_tool: str | None = None,
    fact_anchors: list[str] | None = None,
    centroid_distance: float | None = None,
) -> dict[str, Any]:
    """Run full 4-stage pipeline. Returns decision (commit | quarantine | reject)."""
    write_id = str(uuid.uuid4())
    sem = stage_semantic_consistency(content, namespace)
    fact = stage_fact_verification(content, fact_anchors)
    prov = stage_provenance_validation(agent_id, source_tool)
    anom_score, sigma = stage_anomaly_score(content, namespace, centroid_distance)

    aggregate = (
        STAGE_WEIGHTS["semantic"] * sem
        + STAGE_WEIGHTS["fact"] * fact
        + STAGE_WEIGHTS["provenance"] * prov
        + STAGE_WEIGHTS["anomaly"] * anom_score
    )

    if sigma >= Config.MEMORY_ANOMALY_THRESHOLD_SIGMA:
        decision = "quarantine"
    elif aggregate < 0.4:
        decision = "reject"
    elif aggregate < 0.7:
        decision = "quarantine"
    else:
        decision = "commit"

    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO memory_integrity_events
                (write_id, agent_id, session_id, semantic_score, fact_score,
                 provenance_score, anomaly_score, decision, namespace, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (write_id, agent_id, session_id, sem, fact, prov, anom_score, decision, namespace, _now_iso()),
        )

    if decision == "quarantine":
        emit(
            "memory.integrity.quarantined",
            severity="warning",
            agent_id=agent_id,
            session_id=session_id,
            payload={
                "write_id": write_id,
                "namespace": namespace,
                "scores": {"semantic": sem, "fact": fact, "provenance": prov, "anomaly": anom_score},
                "sigma_distance": sigma,
                "aggregate": round(aggregate, 4),
            },
        )
    elif decision == "reject":
        emit(
            "memory.integrity.rejected",
            severity="warning",
            agent_id=agent_id,
            session_id=session_id,
            payload={
                "write_id": write_id,
                "scores": {"semantic": sem, "fact": fact, "provenance": prov, "anomaly": anom_score},
                "aggregate": round(aggregate, 4),
            },
        )

    return {
        "write_id": write_id,
        "decision": decision,
        "scores": {
            "semantic": sem,
            "fact": fact,
            "provenance": prov,
            "anomaly": anom_score,
            "aggregate": round(aggregate, 4),
        },
        "sigma_distance": round(sigma, 3),
    }


def review_quarantined(write_id: str, action: str, operator: str = "system") -> dict[str, Any]:
    """REQ-SEC-007: operators promote (commit) or reject quarantined memories."""
    if action not in ("promote", "reject"):
        return {"success": False, "reason": "action must be promote|reject"}
    with transaction() as conn:
        row = conn.execute(
            "SELECT * FROM memory_integrity_events WHERE write_id = ?",
            (write_id,),
        ).fetchone()
        if not row:
            return {"success": False, "reason": "write_id not found"}
        if row["decision"] != "quarantine":
            return {"success": False, "reason": f"current decision: {row['decision']}"}
        new_decision = "commit" if action == "promote" else "rejected_by_operator"
        conn.execute(
            "UPDATE memory_integrity_events SET decision = ?, timestamp = ? WHERE write_id = ?",
            (new_decision, _now_iso(), write_id),
        )
    emit(
        "memory.integrity.promoted" if action == "promote" else "memory.integrity.rejected",
        severity="info",
        agent_id=row["agent_id"],
        session_id=row["session_id"],
        payload={"write_id": write_id, "operator": operator, "previous_decision": row["decision"]},
    )
    return {"success": True, "write_id": write_id, "new_decision": new_decision}


def quarantine_count() -> int:
    with closing(connect()) as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM memory_integrity_events WHERE decision = 'quarantine'"
        ).fetchone()
        return int(row["n"]) if row else 0


def list_quarantined(limit: int = 100) -> list[dict[str, Any]]:
    with closing(connect()) as conn:
        rows = conn.execute(
            """
            SELECT * FROM memory_integrity_events
            WHERE decision = 'quarantine'
            ORDER BY timestamp DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
