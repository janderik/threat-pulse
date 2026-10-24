from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import httpx
import yaml

from src.collectors.base import BaseCollector
from src.models.ioc import IOC, IOCType, Confidence

logger = logging.getLogger(__name__)


class CustomFeedCollector(BaseCollector):
    name = "custom_feed"
    description = "Custom JSON/YAML/CSV threat feed collector"

    def __init__(self, config: Optional[dict] = None):
        super().__init__(config)
        self.feeds: list[dict] = self.config.get("feeds", [])
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=30.0,
                headers={"User-Agent": "ThreatPulse/1.0"},
            )
        return self._client

    async def collect(self) -> list[IOC]:
        if not self.feeds:
            self.logger.warning("No custom feeds configured")
            return []

        iocs: list[IOC] = []

        for feed in self.feeds:
            try:
                feed_iocs = await self._process_feed(feed)
                iocs.extend(feed_iocs)
            except Exception as e:
                self.logger.exception(
                    "Error processing feed %s: %s", feed.get("name", "unknown"), e
                )

        return iocs

    async def _process_feed(self, feed: dict) -> list[IOC]:
        source_name = feed.get("name", "custom")
        url = feed.get("url", "")
        file_path = feed.get("file_path", "")
        format_type = feed.get("format", "json")
        default_confidence = Confidence(feed.get("confidence", "medium"))
        default_type = (
            IOCType(feed.get("ioc_type", "ip")) if feed.get("ioc_type") else None
        )
        default_tags = feed.get("tags", [])

        raw_data = await self._fetch_source(url, file_path)
        if not raw_data:
            return []

        return self._parse_data(
            raw_data=raw_data,
            format_type=format_type,
            source_name=source_name,
            default_confidence=default_confidence,
            default_type=default_type,
            default_tags=default_tags,
            feed_config=feed,
        )

    async def _fetch_source(self, url: str, file_path: str) -> Optional[str]:
        if url:
            client = await self._get_client()
            try:
                resp = await client.get(url)
                resp.raise_for_status()
                return resp.text
            except Exception as e:
                self.logger.error("Failed to fetch URL %s: %s", url, e)
                return None

        if file_path:
            path = Path(file_path)
            if path.exists():
                try:
                    return path.read_text(encoding="utf-8")
                except Exception as e:
                    self.logger.error("Failed to read file %s: %s", file_path, e)
                    return None
            else:
                self.logger.warning("File not found: %s", file_path)
                return None

        self.logger.warning("No URL or file_path provided for feed")
        return None

    def _parse_data(
        self,
        raw_data: str,
        format_type: str,
        source_name: str,
        default_confidence: Confidence,
        default_type: Optional[IOCType],
        default_tags: list[str],
        feed_config: dict,
    ) -> list[IOC]:
        if format_type == "json":
            return self._parse_json(
                raw_data,
                source_name,
                default_confidence,
                default_type,
                default_tags,
                feed_config,
            )
        elif format_type == "yaml":
            return self._parse_yaml(
                raw_data,
                source_name,
                default_confidence,
                default_type,
                default_tags,
                feed_config,
            )
        elif format_type == "csv":
            return self._parse_csv(
                raw_data,
                source_name,
                default_confidence,
                default_type,
                default_tags,
                feed_config,
            )
        else:
            self.logger.warning("Unsupported format: %s", format_type)
            return []

    def _parse_json(
        self,
        raw: str,
        source: str,
        conf: Confidence,
        default_type: Optional[IOCType],
        tags: list[str],
        feed: dict,
    ) -> list[IOC]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            self.logger.error("Invalid JSON: %s", e)
            return []

        items = (
            data
            if isinstance(data, list)
            else data.get("iocs", data.get("indicators", [data]))
        )
        if isinstance(items, dict):
            items = [items]

        return [
            self._entry_to_ioc(e, source, conf, default_type, tags, feed) for e in items
        ]

    def _parse_yaml(
        self,
        raw: str,
        source: str,
        conf: Confidence,
        default_type: Optional[IOCType],
        tags: list[str],
        feed: dict,
    ) -> list[IOC]:
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as e:
            self.logger.error("Invalid YAML: %s", e)
            return []

        items = (
            data
            if isinstance(data, list)
            else data.get("iocs", data.get("indicators", [data]))
        )
        if isinstance(items, dict):
            items = [items]

        return [
            self._entry_to_ioc(e, source, conf, default_type, tags, feed) for e in items
        ]

    def _parse_csv(
        self,
        raw: str,
        source: str,
        conf: Confidence,
        default_type: Optional[IOCType],
        tags: list[str],
        feed: dict,
    ) -> list[IOC]:
        import csv
        import io

        iocs: list[IOC] = []
        reader = csv.DictReader(io.StringIO(raw))
        for row in reader:
            ioc = self._entry_to_ioc(dict(row), source, conf, default_type, tags, feed)
            iocs.append(ioc)
        return iocs

    def _entry_to_ioc(
        self,
        entry: dict,
        source: str,
        default_conf: Confidence,
        default_type: Optional[IOCType],
        default_tags: list[str],
        feed: dict,
    ) -> IOC:
        value = entry.get("value") or entry.get("indicator") or entry.get("ioc") or ""
        raw_type = entry.get("type") or (default_type.value if default_type else "")
        raw_confidence = entry.get("confidence") or default_conf.value

        try:
            ioc_type = IOCType(raw_type.lower() if raw_type else "ip")
        except ValueError:
            ioc_type = default_type or IOCType.IP

        try:
            confidence = Confidence(raw_confidence.lower())
        except ValueError:
            confidence = default_conf

        entry_tags = entry.get("tags", [])
        if isinstance(entry_tags, str):
            entry_tags = [t.strip() for t in entry_tags.split(",") if t.strip()]
        merged_tags = list(set(default_tags + entry_tags))

        raw_severity = entry.get("severity", 5.0)
        try:
            severity = min(10.0, max(0.0, float(raw_severity)))
        except (ValueError, TypeError):
            severity = 5.0

        return IOC(
            type=ioc_type,
            value=str(value),
            description=entry.get("description", f"IOC from {source}"),
            source=source,
            confidence=confidence,
            tags=merged_tags,
            severity=severity,
            mitre_id=entry.get("mitre_id"),
            reference_urls=entry.get("reference_urls", []),
            raw_data=entry,
        )
