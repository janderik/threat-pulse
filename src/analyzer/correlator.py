from __future__ import annotations

import logging
from collections import defaultdict

from src.models.ioc import IOC, IOCType
from src.models.threat import Threat

logger = logging.getLogger(__name__)


class Correlator:
    """Correlates IOCs and threats to find related entities.

    Relatedness is scored from *evidence* that two indicators belong together
    (a shared ATT&CK technique, shared tags). Same type or same source is only
    weak context: on its own it must not relate two indicators, otherwise every
    IP from the same feed would correlate with every other one.
    """

    MITRE_WEIGHT = 3.0
    TAG_WEIGHT = 1.0
    CONTEXT_WEIGHT = 0.25  # same type / same source

    def correlate_iocs(
        self, iocs: list[IOC], threshold: float = 3.0
    ) -> list[list[str]]:
        """Group related IOCs by shared attributes. Returns list of IOC ID groups."""
        groups: list[set[str]] = []
        grouped_ids: set[str] = set()

        for ioc in iocs:
            if ioc.id in grouped_ids:
                continue

            group = {ioc.id}

            for other in iocs:
                if other.id in grouped_ids or other.id == ioc.id:
                    continue
                if self._are_related(ioc, other, threshold):
                    group.add(other.id)

            if len(group) > 1:
                for gid in group:
                    grouped_ids.add(gid)
                groups.append(group)

        return [sorted(list(g)) for g in groups]

    def correlate_with_threat(
        self,
        threat: Threat,
        all_iocs: list[IOC],
        threshold: float = 1.0,
    ) -> list[IOC]:
        """Find IOCs related to a given threat's IOCs."""
        threat_ioc_ids = set(threat.ioc_ids)
        threat_iocs = [i for i in all_iocs if i.id in threat_ioc_ids]
        if not threat_iocs:
            return []

        correlated_ids: set[str] = set()
        for ioc in threat_iocs:
            for other in all_iocs:
                if other.id in threat_ioc_ids or other.id in correlated_ids:
                    continue
                if self._are_related(ioc, other, threshold):
                    correlated_ids.add(other.id)

        return [i for i in all_iocs if i.id in correlated_ids]

    def find_iocs_by_type(self, iocs: list[IOC], ioc_type: IOCType) -> list[IOC]:
        """Filter IOCs by type."""
        return [i for i in iocs if i.type == ioc_type]

    def find_iocs_by_tag(self, iocs: list[IOC], tag: str) -> list[IOC]:
        """Filter IOCs by tag."""
        return [i for i in iocs if tag.lower() in (t.lower() for t in i.tags)]

    def find_iocs_by_source(self, iocs: list[IOC], source: str) -> list[IOC]:
        """Filter IOCs by source."""
        return [i for i in iocs if i.source == source]

    def find_shared_iocs_across_threats(
        self, threats: list[Threat], all_iocs: list[IOC]
    ) -> dict[str, list[str]]:
        """Find IOCs shared across multiple threats. Returns {ioc_id: [threat_id, ...]}."""
        ioc_to_threats: dict[str, list[str]] = defaultdict(list)
        for threat in threats:
            for ioc_id in threat.ioc_ids:
                ioc_to_threats[ioc_id].append(threat.id)
        return {
            ioc_id: threat_ids
            for ioc_id, threat_ids in ioc_to_threats.items()
            if len(threat_ids) > 1
        }

    def _are_related(self, a: IOC, b: IOC, threshold: float) -> bool:
        """Determine if two IOCs are related based on shared evidence."""
        return self._relation_score(a, b) >= threshold

    def _relation_score(self, a: IOC, b: IOC) -> float:
        score = 0.0

        if a.mitre_id and b.mitre_id and a.mitre_id == b.mitre_id:
            score += self.MITRE_WEIGHT

        shared_tags = {t.lower() for t in a.tags} & {t.lower() for t in b.tags}
        score += len(shared_tags) * self.TAG_WEIGHT

        if a.type == b.type:
            score += self.CONTEXT_WEIGHT
        if a.source == b.source:
            score += self.CONTEXT_WEIGHT

        return score
