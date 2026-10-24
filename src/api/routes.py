from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from src.api.state import get_db
from src.models.ioc import IOC, IOCType, Confidence, IocCreate, IocResponse
from src.models.threat import Threat, ThreatCreate, ThreatResponse, ThreatStatus

logger = logging.getLogger(__name__)

router = APIRouter()


# --- Health ---


@router.get("/health")
async def health_check():
    return {
        "status": "ok",
        "iocs_total": get_db().count_iocs(),
        "threats_total": get_db().count_threats(),
    }


# --- IOC endpoints ---


@router.post("/iocs", response_model=IocResponse, status_code=201)
async def create_ioc(payload: IocCreate):
    ioc = IOC(
        type=payload.type,
        value=payload.value,
        description=payload.description,
        source=payload.source,
        confidence=payload.confidence,
        tags=payload.tags,
        severity=payload.severity,
        mitre_id=payload.mitre_id,
        reference_urls=payload.reference_urls,
    )
    stored = get_db().store_ioc(ioc)
    return _ioc_to_response(stored)


@router.get("/iocs/{ioc_id}", response_model=IocResponse)
async def get_ioc(ioc_id: str):
    ioc = get_db().get_ioc(ioc_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    return _ioc_to_response(ioc)


@router.get("/iocs", response_model=list[IocResponse])
async def list_iocs(
    value: Optional[str] = Query(None),
    type: Optional[IOCType] = Query(None, alias="ioc_type"),
    source: Optional[str] = Query(None),
    confidence: Optional[Confidence] = Query(None),
    active_only: bool = Query(True),
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
):
    iocs = get_db().search_iocs(
        value=value,
        ioc_type=type,
        source=source,
        confidence=confidence,
        active_only=active_only,
        limit=limit,
        offset=offset,
    )
    return [_ioc_to_response(i) for i in iocs]


@router.delete("/iocs/{ioc_id}", status_code=204)
async def delete_ioc(ioc_id: str):
    if not get_db().delete_ioc(ioc_id):
        raise HTTPException(status_code=404, detail="IOC not found")


# --- Threat endpoints ---


@router.post("/threats", response_model=ThreatResponse, status_code=201)
async def create_threat(payload: ThreatCreate):
    threat = Threat(
        name=payload.name,
        description=payload.description,
        source=payload.source,
        ioc_ids=payload.ioc_ids,
        mitre_techniques=payload.mitre_techniques,
        mitre_tactic=payload.mitre_tactic,
        affected_systems=payload.affected_systems,
        actor=payload.actor,
        campaign=payload.campaign,
        tags=payload.tags,
    )
    stored = get_db().store_threat(threat)
    return _threat_to_response(stored)


@router.get("/threats/{threat_id}", response_model=ThreatResponse)
async def get_threat(threat_id: str):
    threat = get_db().get_threat(threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return _threat_to_response(threat)


@router.get("/threats", response_model=list[ThreatResponse])
async def list_threats(
    name: Optional[str] = Query(None),
    status: Optional[ThreatStatus] = Query(None),
    source: Optional[str] = Query(None),
    min_score: float = Query(0.0, ge=0.0),
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
):
    threats = get_db().search_threats(
        name=name,
        status=status,
        source=source,
        min_score=min_score,
        limit=limit,
        offset=offset,
    )
    return [_threat_to_response(t) for t in threats]


@router.patch("/threats/{threat_id}/status", response_model=ThreatResponse)
async def update_threat_status(threat_id: str, status: ThreatStatus):
    threat = get_db().get_threat(threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    threat = threat.model_copy(update={"status": status, "updated_at": None})
    from datetime import datetime, timezone

    threat.updated_at = datetime.now(timezone.utc)
    stored = get_db().store_threat(threat)
    return _threat_to_response(stored)


@router.delete("/threats/{threat_id}", status_code=204)
async def delete_threat(threat_id: str):
    if not get_db().delete_threat(threat_id):
        raise HTTPException(status_code=404, detail="Threat not found")


# --- Search / Query ---


@router.get("/search", response_model=dict)
async def search_all(
    q: str = Query(..., min_length=1),
    limit: int = Query(50, le=200),
):
    iocs = get_db().search_iocs(value=q, limit=limit)
    threats = get_db().search_threats(name=q, limit=limit)
    return {
        "query": q,
        "iocs": [_ioc_to_response(i) for i in iocs],
        "threats": [_threat_to_response(t) for t in threats],
    }


# --- Stats ---


@router.get("/stats")
async def stats():
    return {
        "total_iocs": get_db().count_iocs(),
        "total_threats": get_db().count_threats(),
    }


# --- Serialization helpers ---


def _ioc_to_response(ioc: IOC) -> IocResponse:
    return IocResponse(
        id=ioc.id,
        type=ioc.type,
        value=ioc.value,
        description=ioc.description,
        source=ioc.source,
        confidence=ioc.confidence,
        tags=ioc.tags,
        first_seen=ioc.first_seen.isoformat()
        if hasattr(ioc.first_seen, "isoformat")
        else str(ioc.first_seen),
        last_seen=ioc.last_seen.isoformat()
        if hasattr(ioc.last_seen, "isoformat")
        else str(ioc.last_seen),
        severity=ioc.severity,
        mitre_id=ioc.mitre_id,
        reference_urls=ioc.reference_urls,
        active=ioc.active,
    )


def _threat_to_response(threat: Threat) -> ThreatResponse:
    return ThreatResponse(
        id=threat.id,
        name=threat.name,
        description=threat.description,
        status=threat.status,
        source=threat.source,
        ioc_ids=threat.ioc_ids,
        mitre_techniques=threat.mitre_techniques,
        mitre_tactic=threat.mitre_tactic,
        score=threat.score,
        affected_systems=threat.affected_systems,
        actor=threat.actor,
        campaign=threat.campaign,
        created_at=threat.created_at.isoformat()
        if hasattr(threat.created_at, "isoformat")
        else str(threat.created_at),
        updated_at=threat.updated_at.isoformat()
        if hasattr(threat.updated_at, "isoformat")
        else str(threat.updated_at),
        tags=threat.tags,
    )
