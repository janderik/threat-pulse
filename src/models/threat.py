from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class ThreatStatus(str, enum.Enum):
    NEW = "new"
    ANALYZING = "analyzing"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"
    ARCHIVED = "archived"


class Threat(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    status: ThreatStatus = ThreatStatus.NEW
    source: str = "manual"
    ioc_ids: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_tactic: Optional[str] = None
    score: float = Field(default=0.0, ge=0.0, le=10.0)
    affected_systems: list[str] = Field(default_factory=list)
    actor: Optional[str] = None
    campaign: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tags: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    raw_data: Optional[Dict[str, Any]] = None

    def dict(self, **kwargs: Any) -> Dict[str, Any]:  # type: ignore[override]
        """JSON-ready dict (datetimes as ISO strings, enums as values).

        Note: a method named ``dict`` shadows the builtin inside this class,
        so field annotations here must use ``typing.Dict``.
        """
        return self.model_dump(mode="json", **kwargs)


class ThreatCreate(BaseModel):
    name: str
    description: Optional[str] = None
    source: str = "manual"
    ioc_ids: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_tactic: Optional[str] = None
    affected_systems: list[str] = Field(default_factory=list)
    actor: Optional[str] = None
    campaign: Optional[str] = None
    tags: list[str] = Field(default_factory=list)


class ThreatResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    status: ThreatStatus
    source: str
    ioc_ids: list[str]
    mitre_techniques: list[str]
    mitre_tactic: Optional[str] = None
    score: float
    affected_systems: list[str]
    actor: Optional[str] = None
    campaign: Optional[str] = None
    created_at: str
    updated_at: str
    tags: list[str]
