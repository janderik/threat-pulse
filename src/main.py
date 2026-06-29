from __future__ import annotations

import asyncio
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Optional

from src.collectors.alienvault import AlienVaultOTXCollector
from src.collectors.abuseipdb import AbuseIPDBCollector
from src.collectors.mitre import MitreAttackCollector
from src.collectors.custom import CustomFeedCollector
from src.storage.database import Database
from src.analyzer.scorer import ThreatScorer
from src.analyzer.correlator import Correlator

logger = logging.getLogger(__name__)


class ThreatPulseEngine:
    """Core engine for threat intelligence collection and analysis."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db or Database()
        self.scorer = ThreatScorer()
        self.correlator = Correlator()
        self.collectors: list = []

    def setup_collectors(self, config: Optional[dict] = None):
        cfg = config or {}
        self.collectors = []

        alienvault_key = cfg.get("alienvault_api_key") or os.getenv("ALIENVAULT_API_KEY", "")
        if alienvault_key:
            self.collectors.append(AlienVaultOTXCollector({"api_key": alienvault_key}))

        abuseipdb_key = cfg.get("abuseipdb_api_key") or os.getenv("ABUSEIPDB_API_KEY", "")
        if abuseipdb_key:
            self.collectors.append(AbuseIPDBCollector({"api_key": abuseipdb_key}))

        if cfg.get("mitre_enabled", True):
            self.collectors.append(MitreAttackCollector({
                "collect_techniques": cfg.get("mitre_collect_techniques", True),
                "collect_software": cfg.get("mitre_collect_software", True),
                "collect_groups": cfg.get("mitre_collect_groups", True),
            }))

        custom_feeds = cfg.get("custom_feeds", [])
        if custom_feeds:
            self.collectors.append(CustomFeedCollector({"feeds": custom_feeds}))

        logger.info("Configured %d collector(s)", len(self.collectors))

    async def run_collectors(self) -> list:
        """Run all configured collectors and return collected IOCs."""
        all_iocs = []
        for collector in self.collectors:
            iocs = await collector.run()
            for ioc in iocs:
                score = self.scorer.score_ioc(ioc)
                ioc.severity = score
            self.db.store_iocs(iocs)
            all_iocs.extend(iocs)
        logger.info("Total IOCs collected: %d", len(all_iocs))
        return all_iocs

    def run_correlation(self) -> list:
        """Run correlation on all stored IOCs."""
        iocs = self.db.search_iocs(active_only=True, limit=10000)
        if not iocs:
            return []
        groups = self.correlator.correlate_iocs(iocs)
        logger.info("Found %d IOC correlation group(s)", len(groups))
        return groups


def setup_logging(level: str = "INFO"):
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )


async def collector_worker(interval_minutes: int = 15):
    """Periodic collector worker."""
    engine = ThreatPulseEngine()
    engine.setup_collectors()

    while True:
        logger.info("=== Collector cycle started ===")
        try:
            await engine.run_collectors()
            groups = engine.run_correlation()
            logger.info("Correlation groups: %d", len(groups))
        except Exception as e:
            logger.exception("Collector cycle failed: %s", e)
        logger.info("=== Collector cycle finished ===")
        await asyncio.sleep(interval_minutes * 60)


def main():
    setup_logging(os.getenv("LOG_LEVEL", "INFO"))
    logger.info("ThreatPulse starting...")

    mode = sys.argv[1] if len(sys.argv) > 1 else "server"

    if mode == "server":
        import uvicorn
        uvicorn.run(
            "src.api.server:app",
            host=os.getenv("HOST", "0.0.0.0"),
            port=int(os.getenv("PORT", "8000")),
            reload=os.getenv("DEV", "").lower() == "true",
        )
    elif mode == "collect":
        interval = int(os.getenv("COLLECTOR_INTERVAL_MINUTES", "15"))
        asyncio.run(collector_worker(interval))
    elif mode == "collect-once":
        async def run_once():
            engine = ThreatPulseEngine()
            engine.setup_collectors()
            await engine.run_collectors()
            engine.run_correlation()
        asyncio.run(run_once())
    else:
        print(f"Usage: {sys.argv[0]} [server|collect|collect-once]")
        sys.exit(1)


if __name__ == "__main__":
    main()
