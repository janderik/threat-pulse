from __future__ import annotations

import pytest

from src.analyzer.scorer import ThreatScorer
from src.analyzer.correlator import Correlator
from src.models.ioc import IOC, IOCType, Confidence
from src.models.threat import Threat, ThreatStatus


class TestThreatScorer:
    def setup_method(self):
        self.scorer = ThreatScorer()

    def test_score_ioc_low_confidence(self):
        ioc = IOC(type=IOCType.IP, value="1.1.1.1", confidence=Confidence.LOW, source="manual")
        score = self.scorer.score_ioc(ioc)
        assert 0.0 <= score <= 10.0
        assert score < 5.0

    def test_score_ioc_high_confidence(self):
        ioc = IOC(type=IOCType.IP, value="2.2.2.2", confidence=Confidence.HIGH, source="mitre_attack")
        score = self.scorer.score_ioc(ioc)
        assert 0.0 <= score <= 10.0
        assert score > 0

    def test_score_ioc_cve_type(self):
        ioc = IOC(type=IOCType.CVE, value="CVE-2024-1234", confidence=Confidence.CRITICAL, source="mitre_attack")
        score = self.scorer.score_ioc(ioc)
        # CVE type has 2.0 multiplier, critical confidence is 10.0, mitre source is 1.0
        assert score > 5.0

    def test_score_ioc_tag_bonus(self):
        ioc = IOC(
            type=IOCType.IP, value="3.3.3.3",
            confidence=Confidence.LOW, source="custom",
            tags=["ransomware", "c2"],
        )
        score = self.scorer.score_ioc(ioc)
        # Tag bonus adds 0.5 per matching tag (ransomware, c2) up to 3.0 max
        assert score > 0

    def test_score_ioc_clamps(self):
        ioc = IOC(
            type=IOCType.CVE, value="CVE-2025-9999",
            confidence=Confidence.CRITICAL, source="mitre_attack",
            severity=10.0, tags=["ransomware", "apt", "critical", "botnet", "malware", "c2"],
        )
        score = self.scorer.score_ioc(ioc)
        assert score <= 10.0
        assert score >= 0.0

    def test_score_threat_no_iocs(self):
        threat = Threat(name="Test Threat", source="manual")
        score = self.scorer.score_threat(threat, iocs=[])
        assert score >= 0.0

    def test_score_threat_with_iocs(self):
        iocs = [
            IOC(type=IOCType.IP, value="1.1.1.1", confidence=Confidence.HIGH, source="mitre_attack"),
            IOC(type=IOCType.DOMAIN, value="evil.com", confidence=Confidence.MEDIUM, source="manual"),
        ]
        threat = Threat(name="Campaign Alpha", source="manual", ioc_ids=[i.id for i in iocs])
        score = self.scorer.score_threat(threat, iocs=iocs)
        assert 0.0 <= score <= 10.0

    def test_score_threat_false_positive_penalty(self):
        threat = Threat(name="FP", status=ThreatStatus.FALSE_POSITIVE)
        score = self.scorer.score_threat(threat, iocs=[])
        assert score < 5.0

    def test_score_threat_remediated_penalty(self):
        threat = Threat(name="Remediated", status=ThreatStatus.REMEDIATED)
        score = self.scorer.score_threat(threat, iocs=[])
        assert score < 5.0

    def test_confidence_weights(self):
        assert self.scorer.CONFIDENCE_WEIGHTS[Confidence.LOW] < self.scorer.CONFIDENCE_WEIGHTS[Confidence.HIGH]
        assert self.scorer.CONFIDENCE_WEIGHTS[Confidence.CRITICAL] == 10.0

    def test_ioc_type_multipliers(self):
        assert self.scorer.IOC_TYPE_MULTIPLIERS[IOCType.CVE] > self.scorer.IOC_TYPE_MULTIPLIERS[IOCType.IP]


class TestCorrelator:
    def setup_method(self):
        self.correlator = Correlator()

    def _make_ioc(self, ioc_id, ioc_type, source, tags=None, mitre_id=None, severity=5.0, value=""):
        return IOC(
            id=ioc_id,
            type=ioc_type,
            value=value or f"{ioc_id}.example.com",
            source=source,
            tags=tags or [],
            mitre_id=mitre_id,
            severity=severity,
        )

    def test_correlate_iocs_shared_tags(self):
        iocs = [
            self._make_ioc("ioc-1", IOCType.IP, "abuseipdb", tags=["malware", "c2"]),
            self._make_ioc("ioc-2", IOCType.DOMAIN, "alienvault_otx", tags=["malware", "c2"]),
            self._make_ioc("ioc-3", IOCType.IP, "manual", tags=["benign"]),
        ]
        groups = self.correlator.correlate_iocs(iocs, threshold=1.0)
        assert len(groups) >= 1
        group_ids = set(groups[0])
        assert "ioc-1" in group_ids
        assert "ioc-2" in group_ids

    def test_correlate_iocs_same_mitre_id(self):
        iocs = [
            self._make_ioc("a", IOCType.URL, "mitre_attack", mitre_id="T1059", severity=7.0),
            self._make_ioc("b", IOCType.URL, "mitre_attack", mitre_id="T1059", severity=8.0),
            self._make_ioc("c", IOCType.IP, "manual", mitre_id=None, severity=1.0),
        ]
        groups = self.correlator.correlate_iocs(iocs, threshold=1.0)
        found = False
        for g in groups:
            if "a" in g and "b" in g:
                found = True
                break
        assert found

    def test_correlate_iocs_returns_empty(self):
        iocs = [
            self._make_ioc("x", IOCType.IP, "src1", tags=["a"]),
            self._make_ioc("y", IOCType.DOMAIN, "src2", tags=["b"]),
            self._make_ioc("z", IOCType.URL, "src3", tags=["c"]),
        ]
        groups = self.correlator.correlate_iocs(iocs, threshold=10.0)
        assert len(groups) == 0

    def test_correlate_with_threat(self):
        threat_ioc = self._make_ioc("t1", IOCType.IP, "abuseipdb", tags=["malware"])
        related_ioc = self._make_ioc("t2", IOCType.DOMAIN, "manual", tags=["malware"])
        unrelated_ioc = self._make_ioc("t3", IOCType.URL, "manual", tags=["benign"])

        threat = Threat(id="thr-1", name="Test", ioc_ids=["t1"])
        result = self.correlator.correlate_with_threat(threat, [threat_ioc, related_ioc, unrelated_ioc])
        assert "t2" in [i.id for i in result]
        assert "t3" not in [i.id for i in result]

    def test_find_iocs_by_type(self):
        iocs = [
            self._make_ioc("a", IOCType.IP, "src"),
            self._make_ioc("b", IOCType.DOMAIN, "src"),
            self._make_ioc("c", IOCType.IP, "src"),
        ]
        ips = self.correlator.find_iocs_by_type(iocs, IOCType.IP)
        assert len(ips) == 2
        assert all(i.type == IOCType.IP for i in ips)

    def test_find_iocs_by_tag(self):
        iocs = [
            self._make_ioc("a", IOCType.IP, "src", tags=["malware", "c2"]),
            self._make_ioc("b", IOCType.DOMAIN, "src", tags=["benign"]),
        ]
        tagged = self.correlator.find_iocs_by_tag(iocs, "malware")
        assert len(tagged) == 1
        assert tagged[0].id == "a"

    def test_find_iocs_by_source(self):
        iocs = [
            self._make_ioc("a", IOCType.IP, "abuseipdb"),
            self._make_ioc("b", IOCType.DOMAIN, "manual"),
        ]
        from_abuse = self.correlator.find_iocs_by_source(iocs, "abuseipdb")
        assert len(from_abuse) == 1
        assert from_abuse[0].id == "a"

    def test_find_shared_iocs_across_threats(self):
        threats = [
            Threat(id="t1", name="T1", ioc_ids=["ioc-a", "ioc-b"]),
            Threat(id="t2", name="T2", ioc_ids=["ioc-b", "ioc-c"]),
            Threat(id="t3", name="T3", ioc_ids=["ioc-d"]),
        ]
        shared = self.correlator.find_shared_iocs_across_threats(threats, [])
        assert "ioc-b" in shared
        assert len(shared["ioc-b"]) == 2
        assert "ioc-d" not in shared

    def test_are_related_same_type_source(self):
        a = self._make_ioc("a", IOCType.IP, "same_source", tags=["foo"])
        b = self._make_ioc("b", IOCType.IP, "same_source", tags=["foo"])
        assert self.correlator._are_related(a, b, threshold=2.0)

    def test_are_related_different(self):
        a = self._make_ioc("a", IOCType.IP, "src1", tags=["x"])
        b = self._make_ioc("b", IOCType.DOMAIN, "src2", tags=["y"])
        assert not self.correlator._are_related(a, b, threshold=5.0)
