from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Optional

from src.models.ioc import IOC

logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    name: str = "base"
    description: str = "Base threat intelligence collector"

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.logger = logging.getLogger(f"{__name__}.{self.name}")

    @abstractmethod
    async def collect(self) -> list[IOC]:
        """Collect IOCs from the source. Must be implemented by subclasses."""
        ...

    async def validate(self) -> bool:
        """Validate that the collector can connect to its source."""
        try:
            result = await self.collect()
            return len(result) > 0
        except Exception as e:
            self.logger.error("Validation failed for %s: %s", self.name, e)
            return False

    async def run(self) -> list[IOC]:
        """Run the collector with error handling and logging."""
        self.logger.info("Starting collection from %s", self.name)
        try:
            iocs = await self.collect()
            self.logger.info("Collected %d IOC(s) from %s", len(iocs), self.name)
            return iocs
        except Exception as e:
            self.logger.exception("Collection failed for %s: %s", self.name, e)
            return []
