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

    async def collect(self) -> list[IOC]:
        client = await self._get_client()
        iocs: list[IOC] = []

        tasks = []
        if self.collect_techniques:
            tasks.append(self._fetch_techniques(client))
        if self.collect_software:
            tasks.append(self._fetch_software(client))
        if self.collect_groups:
            tasks.append(self._fetch_groups(client))

        results = await asyncio_gather(*tasks)

        for result in results:
            iocs.extend(result)

        self.logger.info("Collected %d MITRE ATT&CK entries", len(iocs))
        return iocs

    async def _fetch_json(self, client: httpx.AsyncClient, url: str) -> list[dict]:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
            return data.get("objects", []) if isinstance(data, dict) else data
        except Exception as e:
            self.logger.error("Failed to fetch %s: %s", url, e)
            return []

    async def _fetch_techniques(self, client: httpx.AsyncClient) -> list[IOC]:
        url = f"{self.BASE_URL}/enterprise-attack/enterprise-attack.json"
        objects = await self._fetch_json(client, url)
        iocs: list[IOC] = []

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            tactic = self._extract_tactic(obj)
            kill_chain = obj.get("kill_chain_phases", [])
            external_refs = obj.get("external_references", [])

            mitre_id = ""
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref.get("external_id", "")
                    break

            ioc = IOC(
                type=IOCType.URL,
                value=f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/",
                description=obj.get("description", "") or obj.get("name", ""),
                source="mitre_attack",
                confidence=Confidence.HIGH,
                tags=["mitre", "attack-pattern", tactic] if tactic else ["mitre", "attack-pattern"],
                mitre_id=mitre_id,
                severity=7.0,
                reference_urls=[ref.get("url", "") for ref in external_refs if ref.get("url")],
                raw_data=obj,
            )
            iocs.append(ioc)

        return iocs

    async def _fetch_software(self, client: httpx.AsyncClient) -> list[IOC]:
        url = f"{self.BASE_URL}/enterprise-attack/enterprise-attack.json"
        objects = await self._fetch_json(client, url)
        iocs: list[IOC] = []

        for obj in objects:
            if obj.get("type") != "software" and obj.get("type") != "tool":
                continue
            name = obj.get("name", "")
            description = obj.get("description", "") or ""

            external_refs = obj.get("external_references", [])
            mitre_id = ""
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref.get("external_id", "")
                    break

            ioc = IOC(
                type=IOCType.URL,
                value=name,
                description=f"[MITRE Software] {name}: {description[:500]}",
                source="mitre_attack",
                confidence=Confidence.HIGH,
                tags=["mitre", "software"],
                mitre_id=mitre_id,
                severity=6.0,
                reference_urls=[ref.get("url", "") for ref in external_refs if ref.get("url")],
                raw_data=obj,
            )
            iocs.append(ioc)

        return iocs

    async def _fetch_groups(self, client: httpx.AsyncClient) -> list[IOC]:
        url = f"{self.BASE_URL}/enterprise-attack/enterprise-attack.json"
        objects = await self._fetch_json(client, url)
        iocs: list[IOC] = []

        for obj in objects:
            if obj.get("type") != "intrusion-set":
                continue
            name = obj.get("name", "")
            description = obj.get("description", "") or ""

            external_refs = obj.get("external_references", [])
            mitre_id = ""
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref.get("external_id", "")
                    break

            ioc = IOC(
                type=IOCType.URL,
                value=name,
                description=f"[MITRE Group] {name}: {description[:500]}",
                source="mitre_attack",
                confidence=Confidence.HIGH,
                tags=["mitre", "threat-group"],
                mitre_id=mitre_id,
                severity=8.0,
                reference_urls=[ref.get("url", "") for ref in external_refs if ref.get("url")],
                raw_data=obj,
            )
            iocs.append(ioc)

        return iocs

    def _extract_tactic(self, obj: dict) -> str:
        phases = obj.get("kill_chain_phases", [])
        for phase in phases:
            if phase.get("kill_chain_name") == "mitre-attack":
                return phase.get("phase_name", "")
        return ""


async def asyncio_gather(*aws, return_exceptions=True):
    import asyncio
    return await asyncio.gather(*aws, return_exceptions=return_exceptions)
