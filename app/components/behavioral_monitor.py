"""Behavioral Monitor — REQ-SEC-001/002/013.

Establishes per-agent baselines across configurable metrics, computes z-score
anomalies once 10+ samples are collected, and emits structured events.
"""

from __future__ import annotations

import math
from contextlib import closing
from datetime import datetime, timezone
from typing import Any

import numpy as np

from ..audit import emit
from ..config import Config
from ..db import connect, transaction

DEFAULT_METRICS = (
    "file_access_per_min",
    "tool_calls_per_min",
    "tokens_per_min",
    "api_calls_per_min",
)


def record_sample(agent_id: str, metric: str, value: float) -> None:
    """Add a sample and update baseline when threshold reached."""
    with transaction() as conn:
        row = conn.execute(
            "SELECT * FROM baselines WHERE agent_id = ? AND metric = ?",
            (agent_id, metric),
        ).fetchone()
        if row is None:
            conn.execute(
                """
                INSERT INTO baselines (agent_id, metric, mean, stddev, p95, sample_count, last_updated)
                VALUES (?, ?, ?, 0, ?, 1, ?)
                """,
                (agent_id, metric, value, value, datetime.now(timezone.utc).isoformat()),
            )
            return
        # Welford's online algorithm — running mean/variance
        n = row["sample_count"] + 1
        old_mean = row["mean"]
        new_mean = old_mean + (value - old_mean) / n
        # Approximate stddev update — for production use full Welford M2
        old_stddev = row["stddev"]
        new_var = ((n - 1) * old_stddev * old_stddev + (value - old_mean) * (value - new_mean)) / n
        new_stddev = math.sqrt(max(0.0, new_var))
        # p95 update — keep approximate via momentum
        new_p95 = max(row["p95"], value) if n < 100 else row["p95"] * 0.99 + value * 0.01
        conn.execute(
            """
            UPDATE baselines SET mean = ?, stddev = ?, p95 = ?, sample_count = ?, last_updated = ?
            WHERE agent_id = ? AND metric = ?
            """,
            (
                new_mean,
                new_stddev,
                new_p95,
                n,
                datetime.now(timezone.utc).isoformat(),
                agent_id,
                metric,
            ),
        )


def evaluate_sample(
    agent_id: str,
    metric: str,
    value: float,
    agent_class: str = "default",
    session_id: str | None = None,
) -> dict[str, Any]:
    """Compute z-score for a sample. If baseline not yet established (< MIN_SESSIONS),
    return inactive=True. Otherwise compare against per-class threshold (REQ-SEC-002).
    """
    with closing(connect()) as conn:
        row = conn.execute(
            "SELECT * FROM baselines WHERE agent_id = ? AND metric = ?",
            (agent_id, metric),
        ).fetchone()
        if row is None or row["sample_count"] < Config.BASELINE_MIN_SESSIONS:
            samples_needed = Config.BASELINE_MIN_SESSIONS - (row["sample_count"] if row else 0)
            return {
                "active": False,
                "samples_needed": samples_needed,
                "agent_id": agent_id,
                "metric": metric,
            }
        threshold_row = conn.execute(
            "SELECT zscore_threshold FROM threshold_config WHERE agent_class = ? AND metric = ?",
            (agent_class, metric),
        ).fetchone()
        threshold = (
            threshold_row["zscore_threshold"] if threshold_row else Config.DEFAULT_ANOMALY_ZSCORE
        )

    mean = row["mean"]
    stddev = row["stddev"] if row["stddev"] > 1e-9 else 1e-9
    z = (value - mean) / stddev

    anomaly = abs(z) >= threshold
    if anomaly:
        emit(
            "behavioral.anomaly.detected",
            severity="warning" if abs(z) < threshold * 1.5 else "critical",
            agent_id=agent_id,
            session_id=session_id,
            payload={
                "metric": metric,
                "value": value,
                "mean": mean,
                "stddev": stddev,
                "zscore": z,
                "threshold": threshold,
                "agent_class": agent_class,
            },
        )

    return {
        "active": True,
        "agent_id": agent_id,
        "metric": metric,
        "value": value,
        "mean": mean,
        "stddev": stddev,
        "zscore": z,
        "threshold": threshold,
        "anomaly": anomaly,
    }


def detect_volume_spike(
    session_id: str,
    agent_id: str,
    bytes_out: int,
    destination_host: str,
    data_type: str | None = None,
) -> dict[str, Any]:
    """REQ-SEC-013: outbound volume + new-host detection."""
    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO outbound_observations
                (session_id, agent_id, destination_host, bytes_out, data_type, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                agent_id,
                destination_host,
                bytes_out,
                data_type,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        rows = conn.execute(
            """
            SELECT bytes_out FROM outbound_observations
            WHERE agent_id = ? AND timestamp >= datetime('now', '-1 day')
            """,
            (agent_id,),
        ).fetchall()
        host_seen = conn.execute(
            """
            SELECT 1 FROM outbound_observations
            WHERE agent_id = ? AND destination_host = ? AND timestamp < datetime('now', '-1 hour')
            LIMIT 1
            """,
            (agent_id, destination_host),
        ).fetchone()

    new_host = host_seen is None
    in_allowlist = destination_host in Config.OUTBOUND_HOST_ALLOWLIST

    findings: list[str] = []
    severity = "info"
    if new_host and not in_allowlist:
        findings.append("new_host_outside_allowlist")
        severity = "critical"
        emit(
            "threat.exfil.new_host",
            severity="critical",
            agent_id=agent_id,
            session_id=session_id,
            payload={
                "destination_host": destination_host,
                "bytes_out": bytes_out,
                "data_type": data_type,
            },
        )

    if len(rows) >= 5:
        values = np.array([r["bytes_out"] for r in rows], dtype=float)
        mean_v = float(values.mean())
        stddev_v = float(values.std()) if values.std() > 1e-9 else 1.0
        z = (bytes_out - mean_v) / stddev_v
        if z > Config.DATA_EXFIL_VOLUME_SIGMA:
            findings.append(f"volume_spike_{z:.1f}sigma")
            severity = "critical" if severity == "critical" else "high"
            emit(
                "threat.exfil.volume_spike",
                severity="high",
                agent_id=agent_id,
                session_id=session_id,
                payload={
                    "bytes_out": bytes_out,
                    "mean": mean_v,
                    "stddev": stddev_v,
                    "zscore": z,
                    "destination_host": destination_host,
                },
            )

    return {
        "agent_id": agent_id,
        "session_id": session_id,
        "destination_host": destination_host,
        "bytes_out": bytes_out,
        "new_host": new_host,
        "in_allowlist": in_allowlist,
        "findings": findings,
        "severity": severity,
    }


def upsert_threshold(agent_class: str, metric: str, zscore_threshold: float) -> None:
    """REQ-SEC-002: operator-configurable thresholds per class+metric."""
    with transaction() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO threshold_config (agent_class, metric, zscore_threshold)
            VALUES (?, ?, ?)
            """,
            (agent_class, metric, zscore_threshold),
        )


def list_baselines(agent_id: str | None = None) -> list[dict[str, Any]]:
    with closing(connect()) as conn:
        if agent_id:
            rows = conn.execute(
                "SELECT * FROM baselines WHERE agent_id = ? ORDER BY metric",
                (agent_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM baselines ORDER BY agent_id, metric"
            ).fetchall()
        return [dict(r) for r in rows]
