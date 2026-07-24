"""Compliance reports — REQ-SEC-018. SOC 2 Type II + DOI agent disclosure exports."""

from __future__ import annotations

import json
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Config
from .db import connect, transaction


SOC2_CONTROLS = ("CC6.1", "CC6.3", "CC6.7", "CC7.1", "CC7.2", "CC7.3", "CC9.1")


def generate_soc2_report(
    period_start: str,
    period_end: str,
    fmt: str = "json",
    operator_id: str = "system",
) -> dict[str, Any]:
    report_id = str(uuid.uuid4())
    with closing(connect()) as conn:
        events = conn.execute(
            """
            SELECT event_type, severity, COUNT(*) AS cnt
            FROM forensic_events
            WHERE timestamp BETWEEN ? AND ?
            GROUP BY event_type, severity
            """,
            (period_start, period_end),
        ).fetchall()
        guardian = conn.execute(
            """
            SELECT action, autonomy_level, COUNT(*) AS cnt
            FROM guardian_actions
            WHERE timestamp BETWEEN ? AND ?
            GROUP BY action, autonomy_level
            """,
            (period_start, period_end),
        ).fetchall()
        threats = conn.execute(
            """
            SELECT type, severity, COUNT(*) AS cnt
            FROM threat_events
            WHERE timestamp BETWEEN ? AND ?
            GROUP BY type, severity
            """,
            (period_start, period_end),
        ).fetchall()

    body = {
        "report_id": report_id,
        "framework": "SOC 2 Type II",
        "controls": SOC2_CONTROLS,
        "period": {"start": period_start, "end": period_end},
        "audit_events_summary": [dict(r) for r in events],
        "guardian_actions_summary": [dict(r) for r in guardian],
        "threat_events_summary": [dict(r) for r in threats],
        "operator_id": operator_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    artifact_dir = Path(Config.SQLITE_PATH).parent / "reports"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / f"soc2_{report_id}.{fmt}"
    if fmt == "json":
        artifact_path.write_text(json.dumps(body, indent=2, default=str))
    else:
        artifact_path.write_text(_render_text(body))

    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO compliance_reports
                (report_id, framework, generated_at, period_start, period_end,
                 format, signed, artifact_path, operator_id)
            VALUES (?, 'SOC 2 Type II', ?, ?, ?, ?, 0, ?, ?)
            """,
            (
                report_id,
                body["generated_at"],
                period_start,
                period_end,
                fmt,
                str(artifact_path),
                operator_id,
            ),
        )

    return {**body, "artifact_path": str(artifact_path)}


def _render_text(body: dict[str, Any]) -> str:
    lines = [
        f"SOC 2 Type II — Runtime Security Evidence Report",
        f"Report ID: {body['report_id']}",
        f"Period: {body['period']['start']} → {body['period']['end']}",
        f"Generated: {body['generated_at']}",
        "Controls covered: " + ", ".join(body["controls"]),
        "",
        "AUDIT EVENT SUMMARY",
    ]
    for r in body["audit_events_summary"]:
        lines.append(f"  - {r['event_type']:42} {r['severity']:10} count={r['cnt']}")
    lines.append("\nGUARDIAN ACTIONS")
    for r in body["guardian_actions_summary"]:
        lines.append(f"  - {r['action']:20} ({r['autonomy_level']}) count={r['cnt']}")
    lines.append("\nTHREAT SUMMARY")
    for r in body["threat_events_summary"]:
        lines.append(f"  - {r['type']:30} {r['severity']:10} count={r['cnt']}")
    return "\n".join(lines)


def list_reports() -> list[dict[str, Any]]:
    with closing(connect()) as conn:
        rows = conn.execute(
            "SELECT * FROM compliance_reports ORDER BY generated_at DESC LIMIT 100"
        ).fetchall()
        return [dict(r) for r in rows]


# ─── DOI agent disclosure (REQ-SEC-018) ──────────────────────────────────────

DOI_DISCLOSURE_FIELDS = (
    "agent_inventory",
    "autonomy_levels_in_use",
    "guardian_actions_taken",
    "behavioral_baselines",
    "identity_rotation_events",
    "memory_integrity_checks",
    "threat_detections",
    "coordination_scores",
)


def generate_doi_report(
    period_start: str,
    period_end: str,
    fmt: str = "json",
    operator_id: str = "system",
) -> dict[str, Any]:
    """DOI agent disclosure export — agent inventory + autonomy + actions taken in period.

    Mirrors the NAIC DOI-aligned disclosure requirements: every operating agent,
    its autonomy level, the actions it took with operator-sign-off lineage, and
    the security controls applied (behavioral monitoring + memory integrity).
    """
    report_id = str(uuid.uuid4())
    with closing(connect()) as conn:
        agents = conn.execute(
            """
            SELECT DISTINCT agent_id, autonomy_level
            FROM agent_identities
            ORDER BY agent_id
            """
        ).fetchall()
        guardian_actions = conn.execute(
            """
            SELECT agent_id, action, autonomy_level, operator_approved, COUNT(*) AS cnt
            FROM guardian_actions
            WHERE timestamp BETWEEN ? AND ?
            GROUP BY agent_id, action, autonomy_level, operator_approved
            """,
            (period_start, period_end),
        ).fetchall()
        baselines = conn.execute(
            """
            SELECT agent_id, metric_dimension, sample_count
            FROM behavioral_baselines
            ORDER BY agent_id
            """
        ).fetchall()
        identity_rotations = conn.execute(
            """
            SELECT agent_id, COUNT(*) AS rotation_count
            FROM identity_lifecycle_events
            WHERE event_type = 'rotation' AND timestamp BETWEEN ? AND ?
            GROUP BY agent_id
            """,
            (period_start, period_end),
        ).fetchall()
        memory_integrity = conn.execute(
            """
            SELECT verdict, COUNT(*) AS cnt
            FROM memory_integrity_checks
            WHERE timestamp BETWEEN ? AND ?
            GROUP BY verdict
            """,
            (period_start, period_end),
        ).fetchall()
        threats = conn.execute(
            """
            SELECT type, severity, COUNT(*) AS cnt
            FROM threat_events
            WHERE timestamp BETWEEN ? AND ?
            GROUP BY type, severity
            """,
            (period_start, period_end),
        ).fetchall()
        coordination = conn.execute(
            """
            SELECT score_band, COUNT(*) AS cnt
            FROM coordination_scores
            WHERE timestamp BETWEEN ? AND ?
            GROUP BY score_band
            """,
            (period_start, period_end),
        ).fetchall()

    body = {
        "report_id": report_id,
        "framework": "DOI Agent Disclosure",
        "disclosure_fields": list(DOI_DISCLOSURE_FIELDS),
        "period": {"start": period_start, "end": period_end},
        "agent_inventory": [dict(r) for r in agents],
        "autonomy_levels_in_use": sorted({dict(r)["autonomy_level"] for r in agents}),
        "guardian_actions_taken": [dict(r) for r in guardian_actions],
        "behavioral_baselines": [dict(r) for r in baselines],
        "identity_rotation_events": [dict(r) for r in identity_rotations],
        "memory_integrity_checks": [dict(r) for r in memory_integrity],
        "threat_detections": [dict(r) for r in threats],
        "coordination_scores": [dict(r) for r in coordination],
        "operator_id": operator_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    artifact_dir = Path(Config.SQLITE_PATH).parent / "reports"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / f"doi_{report_id}.{fmt}"
    if fmt == "json":
        artifact_path.write_text(json.dumps(body, indent=2, default=str))
    else:
        artifact_path.write_text(_render_doi_text(body))

    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO compliance_reports
                (report_id, framework, generated_at, period_start, period_end,
                 format, signed, artifact_path, operator_id)
            VALUES (?, 'DOI Agent Disclosure', ?, ?, ?, ?, 0, ?, ?)
            """,
            (
                report_id,
                body["generated_at"],
                period_start,
                period_end,
                fmt,
                str(artifact_path),
                operator_id,
            ),
        )

    return {**body, "artifact_path": str(artifact_path)}


def _render_doi_text(body: dict[str, Any]) -> str:
    lines = [
        "DOI Agent Disclosure — Runtime Security Report",
        f"Report ID: {body['report_id']}",
        f"Period: {body['period']['start']} → {body['period']['end']}",
        f"Generated: {body['generated_at']}",
        f"Disclosure fields: {', '.join(body['disclosure_fields'])}",
        "",
        "AGENT INVENTORY",
    ]
    for r in body["agent_inventory"]:
        lines.append(f"  - {r['agent_id']:30} autonomy={r['autonomy_level']}")
    lines.append("\nGUARDIAN ACTIONS")
    for r in body["guardian_actions_taken"]:
        approved = "approved" if r.get("operator_approved") else "auto"
        lines.append(f"  - {r['agent_id']:30} {r['action']:20} ({approved}) count={r['cnt']}")
    lines.append("\nIDENTITY ROTATIONS")
    for r in body["identity_rotation_events"]:
        lines.append(f"  - {r['agent_id']:30} rotations={r['rotation_count']}")
    lines.append("\nMEMORY INTEGRITY")
    for r in body["memory_integrity_checks"]:
        lines.append(f"  - {r['verdict']:20} count={r['cnt']}")
    lines.append("\nTHREAT DETECTIONS")
    for r in body["threat_detections"]:
        lines.append(f"  - {r['type']:30} {r['severity']:10} count={r['cnt']}")
    return "\n".join(lines)
