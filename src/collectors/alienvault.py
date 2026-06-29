from __future__ import annotations

import logging
from typing import Optional

import httpx

from src.collectors.base import BaseCollector
from src.models.ioc import IOC, Confidence, IOCType

logger = logging.getLogger(__name__)


class AlienVaultOTXCollector(BaseCollector):
    name = "alienvault_otx"
    description = "AlienVault OTX threat intelligence feed"

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, config: Optional[dict] = None):
        super().__init__(config)
        self.api_key: str = self.config.get("api_key", "")
        self.pulse_limit: int = self.config.get("pulse_limit", 10)
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.BASE_URL,
                headers={
                    "X-OTX-API-KEY": self.api_key,
                    "User-Agent": "ThreatPulse/1.0",
                },
                timeout=30.0,
            )
        return self._client

    async def collect(self) -> list[IOC]:
        if not self.api_key:
            self.logger.warning("No AlienVault OTX API key configured")
            return []

        client = await self._get_client()
        iocs: list[IOC] = []

        try:
            resp = await client.get(
                "/pulses/subscribed",
                params={"limit": self.pulse_limit},
            )
            resp.raise_for_status()
            data = resp.json()

            for pulse in data.get("results", []):
                pulse_iocs = self._parse_pulse(pulse)
                iocs.extend(pulse_iocs)

        except httpx.HTTPStatusError as e:
            self.logger.error("HTTP error fetching OTX pulses: %s", e)
        except httpx.RequestError as e:
            self.logger.error("Request error fetching OTX pulses: %s", e)
        except Exception as e:
            self.logger.exception("Unexpected error in OTX collector: %s", e)

        return iocs

    def _parse_pulse(self, pulse: dict) -> list[IOC]:
        iocs: list[IOC] = []
        pulse_name = pulse.get("name", "Unknown")
        pulse_description = pulse.get("description", "")
        pulse_tags = [t.get("name", "") for t in pulse.get("tags", []) if t.get("name")]
        pulse_id = pulse.get("id", "")

        for indicator in pulse.get("indicators", []):
            raw_type = (indicator.get("type") or "").lower()
            value = indicator.get("indicator", "")
            if not value:
                continue

            ioc_type = self._map_type(raw_type)
            if ioc_type is None:
                continue

            ioc = IOC(
                type=ioc_type,
                value=value,
                description=f"[OTX Pulse: {pulse_name}] {pulse_description}",
                source="alienvault_otx",
                confidence=self._parse_confidence(indicator.get("confidence", 50)),
                tags=pulse_tags,
                reference_urls=[
                    f"https://otx.alienvault.com/pulse/{pulse_id}",
                ],
                raw_data=indicator,
            )
            iocs.append(ioc)

        return iocs

    def _map_type(self, raw: str) -> Optional[IOCType]:
        mapping = {
            "ipv4": IOCType.IP,
            "ipv6": IOCType.IP,
            "domain": IOCType.DOMAIN,
            "hostname": IOCType.DOMAIN,
            "url": IOCType.URL,
            "md5": IOCType.MD5,
            "sha1": IOCType.SHA1,
            "sha256": IOCType.SHA256,
            "cve": IOCType.CVE,
            "email": IOCType.EMAIL,
            "hash": IOCType.HASH,
        }
        return mapping.get(raw)

    def _parse_confidence(self, value: int) -> Confidence:
        if value >= 80:
            return Confidence.HIGH
        elif value >= 50:
            return Confidence.MEDIUM
        return Confidence.LOW
