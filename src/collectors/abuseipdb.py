from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

from src.collectors.base import BaseCollector
from src.models.ioc import IOC, Confidence, IOCType

logger = logging.getLogger(__name__)


class AbuseIPDBCollector(BaseCollector):
    name = "abuseipdb"
    description = "AbuseIPDB blacklist feed"

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, config: Optional[dict] = None):
        super().__init__(config)
        self.api_key: str = self.config.get("api_key", "")
        self.confidence_minimum: int = self.config.get("confidence_minimum", 50)
        self.max_results: int = self.config.get("max_results", 100)
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.BASE_URL,
                headers={
                    "Key": self.api_key,
                    "Accept": "application/json",
                    "User-Agent": "ThreatPulse/1.0",
                },
                timeout=30.0,
            )
        return self._client

    async def collect(self) -> list[IOC]:
        if not self.api_key:
            self.logger.warning("No AbuseIPDB API key configured")
            return []

        client = await self._get_client()
        iocs: list[IOC] = []

        try:
            resp = await client.get(
                "/blacklist",
                params={
                    "confidenceMinimum": self.confidence_minimum,
                    "limit": self.max_results,
                },
            )
            resp.raise_for_status()
            data = resp.json()

            for entry in data.get("data", []):
                ioc = self._parse_entry(entry)
                if ioc:
                    iocs.append(ioc)

        except httpx.HTTPStatusError as e:
            self.logger.error("HTTP error fetching AbuseIPDB blacklist: %s", e)
        except httpx.RequestError as e:
            self.logger.error("Request error fetching AbuseIPDB blacklist: %s", e)
        except Exception as e:
            self.logger.exception("Unexpected error in AbuseIPDB collector: %s", e)

        return iocs

    def _parse_entry(self, entry: dict) -> Optional[IOC]:
        ip_address = entry.get("ipAddress") or entry.get("ip")
        if not ip_address:
            return None

        abuse_confidence = entry.get("abuseConfidenceScore", 50)
        domain = entry.get("domain")
        country = entry.get("countryCode")
        total_reports = entry.get("totalReports", 0)
        last_reported = self._parse_timestamp(entry.get("lastReportedAt"))
        is_whitelisted = entry.get("isWhitelisted", False)

        if is_whitelisted:
            return None

        tags = []
        if country:
            tags.append(f"country:{country}")
        if domain:
            tags.append(f"domain:{domain}")
        if total_reports > 10:
            tags.append("highly_reported")

        severity = min(10.0, (abuse_confidence / 100.0) * 10.0)

        return IOC(
            type=IOCType.IP,
            value=ip_address,
            description=f"AbuseIPDB reported IP (confidence: {abuse_confidence}%, reports: {total_reports})",
            source="abuseipdb",
            confidence=self._score_to_confidence(abuse_confidence),
            tags=tags,
            severity=severity,
            raw_data=entry,
            **({"last_seen": last_reported} if last_reported else {}),
        )

    @staticmethod
    def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
        """Parse AbuseIPDB's ISO 8601 timestamps (e.g. 2025-01-01T00:00:00+00:00)."""
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    def _score_to_confidence(self, score: int) -> Confidence:
        if score >= 75:
            return Confidence.HIGH
        elif score >= 50:
            return Confidence.MEDIUM
        return Confidence.LOW
