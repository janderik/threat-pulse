from __future__ import annotations

import logging
from typing import Optional

from src.models.ioc import IOC, Confidence, IOCType
from src.models.threat import Threat

logger = logging.getLogger(__name__)


class ThreatScorer:
    """Calculates threat scores for IOCs and threats based on multiple factors."""

    # Weights for different scoring factors
    CONFIDENCE_WEIGHTS = {
        Confidence.LOW: 2.0,
        Confidence.MEDIUM: 5.0,
        Confidence.HIGH: 8.0,
        Confidence.CRITICAL: 10.0,
    }

    IOC_TYPE_MULTIPLIERS = {
        IOCType.IP: 1.0,
        IOCType.DOMAIN: 1.2,
        IOCType.URL: 1.3,
        IOCType.MD5: 1.0,
        IOCType.SHA1: 1.0,
        IOCType.SHA256: 1.1,
        IOCType.CVE: 2.0,
        IOCType.EMAIL: 0.8,
        IOCType.HASH: 1.0,
    }

    SOURCE_REPUTATION: dict[str, float] = {
        "alienvault_otx": 0.9,
        "abuseipdb": 0.85,
        "mitre_attack": 1.0,
        "custom": 0.7,
        "manual": 0.8,
    }

    def score_ioc(self, ioc: IOC) -> float:
        """Compute a severity score for a single IOC (0-10)."""
        confidence_score = self.CONFIDENCE_WEIGHTS.get(ioc.confidence, 5.0)
        type_multiplier = self.IOC_TYPE_MULTIPLIERS.get(ioc.type, 1.0)
        source_reputation = self.SOURCE_REPUTATION.get(ioc.source, 0.7)
        tag_bonus = self._compute_tag_bonus(ioc.tags)

        raw_score = confidence_score * type_multiplier * source_reputation + tag_bonus

        return round(min(10.0, max(0.0, raw_score)), 2)

    def score_threat(self, threat: Threat, iocs: Optional[list[IOC]] = None) -> float:
        """Compute a severity score for a threat based on its IOCs and attributes."""
        if iocs:
            ioc_scores = [self.score_ioc(ioc) for ioc in iocs]
            avg_ioc_score = sum(ioc_scores) / len(ioc_scores) if ioc_scores else 0.0
        else:
            avg_ioc_score = 0.0

        num_iocs_factor = min(2.0, len(threat.ioc_ids) * 0.2)
        mitre_bonus = 1.0 if threat.mitre_techniques else 0.0
        tag_bonus = self._compute_tag_bonus(threat.tags)
        status_penalty = self._status_penalty(threat.status)

        raw_score = (
            avg_ioc_score * 0.5 + num_iocs_factor + mitre_bonus + tag_bonus
        ) * status_penalty

        return round(min(10.0, max(0.0, raw_score)), 2)

    def _compute_tag_bonus(self, tags: list[str]) -> float:
        bonus = 0.0
        high_severity_tags = {
            "ransomware",
            "apt",
            "malware",
            "c2",
            "botnet",
            "critical",
        }
        for tag in tags:
            if tag.lower() in high_severity_tags:
                bonus += 0.5
        return min(3.0, bonus)

    def _status_penalty(self, status: str) -> float:
        penalties = {
            "new": 1.0,
            "analyzing": 0.9,
            "confirmed": 1.0,
            "false_positive": 0.2,
            "remediated": 0.3,
            "archived": 0.1,
        }
        return penalties.get(status, 1.0)
