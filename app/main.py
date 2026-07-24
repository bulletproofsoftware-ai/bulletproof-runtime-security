"""Runtime Security & Identity — PRD 11 main FastAPI app.

Orchestrates 6 components: Behavioral Monitor, Identity Lifecycle, Memory Integrity,
Coordination Scorer, Threat Detection, Guardian Agent.
"""

from __future__ import annotations

import asyncio
import json
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from . import audit, compliance, db
from .components import (
    behavioral_monitor,
    coordination_scorer,
    guardian_agent,
    identity_lifecycle,
    memory_integrity,
    threat_detection,
)
from .config import Config, ensure_dirs


# --- Pydantic models ---

class ProvisionSessionRequest(BaseModel):
    agent_id: str
    agent_class: str = "default"
    scope: dict[str, Any] | None = None
    ttl_hours: int | None = None


class BehavioralSampleRequest(BaseModel):
    agent_id: str
    metric: str
    value: float
    agent_class: str = "default"
    session_id: str | None = None


class OutboundObservationRequest(BaseModel):
    session_id: str
    agent_id: str
    bytes_out: int
    destination_host: str
    data_type: str | None = None


class MemoryWriteRequest(BaseModel):
    content: str
    agent_id: str | None = None
    session_id: str | None = None
    namespace: str = "default"
    source_tool: str | None = None
    fact_anchors: list[str] | None = None
    centroid_distance: float | None = None


class CssRequest(BaseModel):
    agent_a: str
    agent_b: str
    score: float


class TueRequest(BaseModel):
    agent_id: str
    score: float
    window_size: int | None = None


class InjectionCheckRequest(BaseModel):
    text: str
    agent_id: str | None = None
    session_id: str | None = None


class ScopeCheckRequest(BaseModel):
    session_id: str
    required_tool: str
    required_data_class: str = "internal"


class ThresholdRequest(BaseModel):
    agent_class: str
    metric: str
    zscore_threshold: float


class ReviewRequest(BaseModel):
    action: str  # "promote" | "reject"
    operator: str = "system"


# --- Background tasks ---

async def _expiry_worker() -> None:
    while True:
        try:
            await asyncio.sleep(60)
            identity_lifecycle.expire_old_credentials()
        except asyncio.CancelledError:
            return
        except Exception as exc:  # noqa: BLE001
            print(f"[expiry-worker] {exc}")


async def _audit_retry_worker() -> None:
    while True:
        try:
            await asyncio.sleep(30)
            audit.retry_undelivered()
        except asyncio.CancelledError:
            return
        except Exception as exc:  # noqa: BLE001
            print(f"[audit-retry] {exc}")


# --- WebSocket clients (REQ-SEC-015 ≤30s refresh) ---
_ws_clients: set[WebSocket] = set()


async def _broadcast(payload: dict[str, Any]) -> None:
    if not _ws_clients:
        return
    msg = json.dumps(payload, default=str)
    dead: set[WebSocket] = set()
    for ws in list(_ws_clients):
        try:
            await ws.send_text(msg)
        except Exception:
            dead.add(ws)
    _ws_clients.difference_update(dead)


@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_dirs()
    db.init()
    expiry = asyncio.create_task(_expiry_worker())
    audit_retry = asyncio.create_task(_audit_retry_worker())
    yield
    expiry.cancel()
    audit_retry.cancel()


app = FastAPI(title="Runtime Security & Identity", version="1.0.0", lifespan=lifespan)

STATIC_DIR = Path(__file__).parent / "static"
TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# --- Health / dashboard ---

@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "runtime-security",
        "components": [
            "behavioral_monitor",
            "identity_lifecycle",
            "memory_integrity",
            "coordination_scorer",
            "threat_detection",
            "guardian_agent",
        ],
        "autonomy": Config.GUARDIAN_AUTONOMY,
    }


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


# --- Identity Lifecycle (REQ-SEC-003/004/014) ---

@app.post("/api/security/sessions")
async def create_session(req: ProvisionSessionRequest):
    try:
        return identity_lifecycle.provision_session(
            agent_id=req.agent_id,
            agent_class=req.agent_class,
            scope=req.scope,
            ttl_hours=req.ttl_hours,
        )
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))


@app.get("/api/security/sessions")
async def list_sessions():
    return {"sessions": identity_lifecycle.list_active_sessions()}


@app.post("/api/security/sessions/{session_id}/rotate")
async def rotate_session(session_id: str, ttl_hours: int | None = None):
    result = identity_lifecycle.rotate(session_id, ttl_hours=ttl_hours)
    if not result:
        raise HTTPException(404, "session not found")
    return result


@app.post("/api/security/sessions/{session_id}/revoke")
async def revoke_session(session_id: str, reason: str = "operator_request"):
    ok = identity_lifecycle.revoke(session_id, reason=reason)
    if not ok:
        raise HTTPException(404, "session not found")
    return {"revoked": True, "session_id": session_id}


@app.post("/api/security/scope/check")
async def scope_check(req: ScopeCheckRequest):
    ok, reason = identity_lifecycle.check_scope(req.session_id, req.required_tool, req.required_data_class)
    if not ok:
        # REQ-SEC-014: scope violations escalate to Guardian as Critical
        sess = next((s for s in identity_lifecycle.list_active_sessions() if s["session_id"] == req.session_id), None)
        if sess:
            threat = threat_detection.detect_privilege_escalation(sess["agent_id"], req.session_id, reason)
            guardian_agent.evaluate(sess["agent_id"], req.session_id, "PRIVILEGE_ESCALATION", "critical", threat["threat_id"])
    return {"allowed": ok, "reason": reason}


# --- Behavioral Monitor (REQ-SEC-001/002/013) ---

@app.post("/api/security/behavioral/sample")
async def behavioral_sample(req: BehavioralSampleRequest):
    behavioral_monitor.record_sample(req.agent_id, req.metric, req.value)
    eval_ = behavioral_monitor.evaluate_sample(
        req.agent_id, req.metric, req.value, req.agent_class, req.session_id
    )
    if eval_.get("anomaly"):
        guardian_agent.evaluate(req.agent_id, req.session_id, "BEHAVIORAL_ANOMALY", "high")
    return eval_


@app.post("/api/security/behavioral/threshold")
async def update_threshold(req: ThresholdRequest):
    behavioral_monitor.upsert_threshold(req.agent_class, req.metric, req.zscore_threshold)
    return {"updated": True, "agent_class": req.agent_class, "metric": req.metric}


@app.get("/api/security/behavioral/baselines")
async def list_baselines(agent_id: str | None = None):
    return {"baselines": behavioral_monitor.list_baselines(agent_id)}


@app.post("/api/security/behavioral/outbound")
async def outbound_observation(req: OutboundObservationRequest):
    result = behavioral_monitor.detect_volume_spike(
        req.session_id, req.agent_id, req.bytes_out, req.destination_host, req.data_type
    )
    if result.get("severity") == "critical":
        guardian_agent.evaluate(req.agent_id, req.session_id, "DATA_EXFILTRATION", "critical")
    elif result.get("severity") == "high":
        guardian_agent.evaluate(req.agent_id, req.session_id, "DATA_EXFILTRATION", "high")
    return result


# --- Memory Integrity (REQ-SEC-005/006/007/012) ---

@app.post("/api/security/memory/check")
async def memory_check(req: MemoryWriteRequest):
    result = memory_integrity.evaluate_write(
        req.content,
        req.agent_id,
        req.session_id,
        req.namespace,
        req.source_tool,
        req.fact_anchors,
        req.centroid_distance,
    )
    poisoning = threat_detection.detect_memory_poisoning(
        result["write_id"], req.agent_id, req.session_id, result
    )
    if poisoning:
        guardian_agent.evaluate(req.agent_id, req.session_id, "MEMORY_POISONING", poisoning["severity"], poisoning["threat_id"])
    return result


@app.get("/api/security/quarantine")
async def list_quarantined(limit: int = Query(default=100, le=500)):
    return {"quarantine_count": memory_integrity.quarantine_count(), "items": memory_integrity.list_quarantined(limit)}


@app.post("/api/security/quarantine/{write_id}/review")
async def review_quarantined(write_id: str, req: ReviewRequest):
    result = memory_integrity.review_quarantined(write_id, req.action, req.operator)
    if not result["success"]:
        raise HTTPException(400, result["reason"])
    return result


# --- Coordination Scorer (REQ-SEC-008/009) ---

@app.post("/api/security/coordination/css")
async def coordination_css(req: CssRequest):
    res = coordination_scorer.record_css(req.agent_a, req.agent_b, req.score)
    if res.get("action") == "isolate":
        guardian_agent.evaluate(req.agent_a, None, "COORDINATION_FAILURE", "critical")
        guardian_agent.evaluate(req.agent_b, None, "COORDINATION_FAILURE", "critical")
    elif res.get("action") == "review":
        guardian_agent.evaluate(req.agent_a, None, "COORDINATION_DEGRADED", "warning")
    return res


@app.post("/api/security/coordination/tue")
async def coordination_tue(req: TueRequest):
    res = coordination_scorer.record_tue(req.agent_id, req.score, req.window_size)
    if res.get("flagged"):
        guardian_agent.evaluate(req.agent_id, None, "TUE_DEGRADED", "warning")
    return res


@app.get("/api/security/scores/{agent_id}")
async def get_scores(agent_id: str):
    return {
        "agent_id": agent_id,
        "css_recent": coordination_scorer.trends(agent_id, "css", 50),
        "tue_recent": coordination_scorer.trends(agent_id, "tue", 50),
        "baselines": behavioral_monitor.list_baselines(agent_id),
    }


# --- Threat Detection (REQ-SEC-011) ---

@app.post("/api/security/threats/check")
async def threats_check(req: InjectionCheckRequest):
    result = threat_detection.detect_prompt_injection(req.text, req.agent_id, req.session_id)
    if result.get("block"):
        guardian_agent.evaluate(
            req.agent_id or "unknown",
            req.session_id,
            "PROMPT_INJECTION",
            result.get("severity", "high"),
            result.get("threat_id"),
        )
    return result


@app.get("/api/security/threats")
async def list_threats(limit: int = Query(default=100, le=500), hours: int = Query(default=24, le=720)):
    return {"threats": threat_detection.list_recent_threats(limit, hours)}


# --- Guardian (REQ-SEC-010) ---

@app.get("/api/security/guardian/actions")
async def guardian_actions(agent_id: str | None = None, limit: int = Query(default=100, le=500)):
    return {"actions": guardian_agent.history(agent_id, limit)}


# --- Forensic & Compliance (REQ-SEC-017/018) ---

@app.get("/api/security/forensic/session/{session_id}")
async def forensic_session(session_id: str, since: str | None = None):
    return {"session_id": session_id, "events": audit.replay_session(session_id, since)}


@app.get("/api/security/forensic/agent/{agent_id}")
async def forensic_agent(agent_id: str, since: str | None = None, limit: int = Query(default=1000, le=5000)):
    return {"agent_id": agent_id, "events": audit.replay_agent(agent_id, since, limit)}


@app.post("/api/security/compliance/soc2")
async def compliance_soc2(period_start: str, period_end: str, fmt: str = "json", operator_id: str = "system"):
    if fmt not in ("json", "txt"):
        raise HTTPException(400, "fmt must be json or txt")
    return compliance.generate_soc2_report(period_start, period_end, fmt, operator_id)


@app.get("/api/security/compliance/reports")
async def compliance_reports():
    return {"reports": compliance.list_reports()}


# --- WebSocket (REQ-SEC-015) ---

@app.websocket("/api/security/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    _ws_clients.add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        _ws_clients.discard(ws)


# --- Aggregate dashboard data ---

@app.get("/api/security/dashboard")
async def dashboard_data():
    sessions = identity_lifecycle.list_active_sessions()
    threats = threat_detection.list_recent_threats(50, 24)
    quarantined = memory_integrity.list_quarantined(20)
    actions = guardian_agent.history(None, 50)
    return {
        "active_sessions": len(sessions),
        "sessions_sample": sessions[:25],
        "recent_threats_24h": threats,
        "quarantine_count": memory_integrity.quarantine_count(),
        "quarantine_sample": quarantined,
        "guardian_actions_recent": actions,
        "autonomy_level": Config.GUARDIAN_AUTONOMY,
        "refresh_interval_sec": Config.DASHBOARD_REFRESH_SEC,
    }
