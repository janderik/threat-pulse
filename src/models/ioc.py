from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class IOCType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    CVE = "cve"
    EMAIL = "email"
    HASH = "hash"


class Confidence(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IOC(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: IOCType
    value: str
    description: Optional[str] = None
    source: str = "manual"
    confidence: Confidence = Confidence.MEDIUM
    tags: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: float = Field(default=5.0, ge=0.0, le=10.0)
    mitre_id: Optional[str] = None
    reference_urls: list[str] = Field(default_factory=list)
    raw_data: Optional[Dict[str, Any]] = None
    active: bool = True

    def dict(self, **kwargs: Any) -> Dict[str, Any]:  # type: ignore[override]
        """JSON-ready dict (datetimes as ISO strings, enums as values).

        Note: a method named ``dict`` shadows the builtin inside this class,
        so field annotations here must use ``typing.Dict``.
        """
        return self.model_dump(mode="json", **kwargs)


class IocCreate(BaseModel):
    type: IOCType
    value: str
    description: Optional[str] = None
    source: str = "manual"
    confidence: Confidence = Confidence.MEDIUM
    tags: list[str] = Field(default_factory=list)
    severity: float = Field(default=5.0, ge=0.0, le=10.0)
    mitre_id: Optional[str] = None
    reference_urls: list[str] = Field(default_factory=list)


class IocResponse(BaseModel):
    id: str
    type: IOCType
    value: str
    description: Optional[str] = None
    source: str
    confidence: Confidence
    tags: list[str]
    first_seen: str
    last_seen: str
    severity: float
    mitre_id: Optional[str] = None
    reference_urls: list[str]
    active: bool
