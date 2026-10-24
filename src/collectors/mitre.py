from __future__ import annotations

import logging
from typing import Optional

import httpx

from src.collectors.base import BaseCollector
from src.models.ioc import IOC, Confidence, IOCType

logger = logging.getLogger(__name__)


class MitreAttackCollector(BaseCollector):
    name = "mitre_attack"
    description = "MITRE ATT&CK framework data collector"

    BASE_URL = "https://raw.githubusercontent.com/mitre/cti/master"

    def __init__(self, config: Optional[dict] = None):
        super().__init__(config)
        self.collect_techniques: bool = self.config.get("collect_techniques", True)
        self.collect_software: bool = self.config.get("collect_software", True)
        self.collect_groups: bool = self.config.get("collect_groups", True)
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=60.0,
                headers={"User-Agent": "ThreatPulse/1.0"},
            )
        return self._client

    BUNDLE_URL = f"{BASE_URL}/enterprise-attack/enterprise-attack.json"
    SOFTWARE_TYPES = {"malware", "tool"}  # STIX types for ATT&CK software

    async def collect(self) -> list[IOC]:
        client = await self._get_client()
        # One download: the bundle is large and holds techniques, software
        # and groups alike.
        objects = [
            obj
            for obj in await self._fetch_json(client, self.BUNDLE_URL)
            if not obj.get("revoked") and not obj.get("x_mitre_deprecated")
        ]

        iocs: list[IOC] = []
        if self.collect_techniques:
            iocs.extend(self._parse_techniques(objects))
        if self.collect_software:
            iocs.extend(self._parse_software(objects))
        if self.collect_groups:
            iocs.extend(self._parse_groups(objects))

        self.logger.info("Collected %d MITRE ATT&CK entries", len(iocs))
        return iocs

    async def _fetch_json(self, client: httpx.AsyncClient, url: str) -> list[dict]:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
            return data.get("objects", []) if isinstance(data, dict) else data
        except (httpx.HTTPError, ValueError) as e:
            self.logger.error("Failed to fetch %s: %s", url, e)
            return []

    @staticmethod
    def _attack_reference(obj: dict) -> tuple[str, list[str]]:
        """Return the ATT&CK external ID and every reference URL of an object."""
        refs = obj.get("external_references", [])
        mitre_id = next(
            (
                ref.get("external_id", "")
                for ref in refs
                if ref.get("source_name") == "mitre-attack"
            ),
            "",
        )
        urls = [ref["url"] for ref in refs if ref.get("url")]
        return mitre_id, urls

    def _parse_techniques(self, objects: list[dict]) -> list[IOC]:
        iocs: list[IOC] = []
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            mitre_id, urls = self._attack_reference(obj)
            if not mitre_id:
                continue
            tactic = self._extract_tactic(obj)
            iocs.append(
                IOC(
                    type=IOCType.URL,
                    value=f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/",
                    description=obj.get("description", "") or obj.get("name", ""),
                    source="mitre_attack",
                    confidence=Confidence.HIGH,
                    tags=["mitre", "attack-pattern", tactic]
                    if tactic
                    else ["mitre", "attack-pattern"],
                    mitre_id=mitre_id,
                    severity=7.0,
                    reference_urls=urls,
                    raw_data=obj,
                )
            )
        return iocs

    def _parse_software(self, objects: list[dict]) -> list[IOC]:
        iocs: list[IOC] = []
        for obj in objects:
            if obj.get("type") not in self.SOFTWARE_TYPES:
                continue
            mitre_id, urls = self._attack_reference(obj)
            if not mitre_id:
                continue
            name = obj.get("name", "")
            description = obj.get("description", "") or ""
            iocs.append(
                IOC(
                    type=IOCType.URL,
                    value=f"https://attack.mitre.org/software/{mitre_id}/",
                    description=f"[MITRE Software] {name}: {description[:500]}",
                    source="mitre_attack",
                    confidence=Confidence.HIGH,
                    tags=["mitre", "software", obj["type"]],
                    mitre_id=mitre_id,
                    severity=6.0,
                    reference_urls=urls,
                    raw_data=obj,
                )
            )
        return iocs

    def _parse_groups(self, objects: list[dict]) -> list[IOC]:
        iocs: list[IOC] = []
        for obj in objects:
            if obj.get("type") != "intrusion-set":
                continue
            mitre_id, urls = self._attack_reference(obj)
            if not mitre_id:
                continue
            name = obj.get("name", "")
            description = obj.get("description", "") or ""
            iocs.append(
                IOC(
                    type=IOCType.URL,
                    value=f"https://attack.mitre.org/groups/{mitre_id}/",
                    description=f"[MITRE Group] {name}: {description[:500]}",
                    source="mitre_attack",
                    confidence=Confidence.HIGH,
                    tags=["mitre", "threat-group"],
                    mitre_id=mitre_id,
                    severity=8.0,
                    reference_urls=urls,
                    raw_data=obj,
                )
            )
        return iocs

    def _extract_tactic(self, obj: dict) -> str:
        phases = obj.get("kill_chain_phases", [])
        for phase in phases:
            if phase.get("kill_chain_name") == "mitre-attack":
                return phase.get("phase_name", "")
        return ""
