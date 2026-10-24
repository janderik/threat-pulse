from __future__ import annotations

import httpx
import pytest

from src.collectors.alienvault import AlienVaultOTXCollector
from src.collectors.abuseipdb import AbuseIPDBCollector
from src.collectors.mitre import MitreAttackCollector
from src.collectors.custom import CustomFeedCollector
from src.models.ioc import IOC, IOCType, Confidence


class TestAlienVaultCollector:
    def test_init(self):
        collector = AlienVaultOTXCollector({"api_key": "test-key"})
        assert collector.name == "alienvault_otx"
        assert collector.api_key == "test-key"

    @pytest.mark.asyncio
    async def test_no_api_key(self):
        collector = AlienVaultOTXCollector({})
        assert collector.api_key == ""
        # Without a key the collector must skip the network call entirely.
        assert await collector.collect() == []

    def test_map_type(self):
        collector = AlienVaultOTXCollector({})
        assert collector._map_type("ipv4") == IOCType.IP
        assert collector._map_type("domain") == IOCType.DOMAIN
        assert collector._map_type("url") == IOCType.URL
        assert collector._map_type("sha256") == IOCType.SHA256
        assert collector._map_type("cve") == IOCType.CVE
        assert collector._map_type("email") == IOCType.EMAIL
        assert collector._map_type("unknown_format") is None

    def test_parse_confidence(self):
        collector = AlienVaultOTXCollector({})
        assert collector._parse_confidence(90) == Confidence.HIGH
        assert collector._parse_confidence(60) == Confidence.MEDIUM
        assert collector._parse_confidence(30) == Confidence.LOW

    def test_parse_pulse(self):
        collector = AlienVaultOTXCollector({})
        pulse = {
            "name": "Test Pulse",
            "description": "A test pulse",
            "id": "pulse123",
            "tags": [{"name": "malware"}, {"name": "c2"}],
            "indicators": [
                {"type": "IPv4", "indicator": "192.168.1.1", "confidence": 80},
                {"type": "domain", "indicator": "evil.example.com", "confidence": 50},
                {"type": "sha256", "indicator": "a" * 64, "confidence": 30},
            ],
        }
        iocs = collector._parse_pulse(pulse)
        assert len(iocs) == 3
        assert iocs[0].type == IOCType.IP
        assert iocs[0].value == "192.168.1.1"
        assert iocs[0].confidence == Confidence.HIGH
        assert "malware" in iocs[0].tags
        assert "c2" in iocs[0].tags

        assert iocs[1].type == IOCType.DOMAIN
        assert iocs[1].value == "evil.example.com"
        assert iocs[1].confidence == Confidence.MEDIUM

        assert iocs[2].type == IOCType.SHA256
        assert iocs[2].confidence == Confidence.LOW


class TestAbuseIPDBCollector:
    def test_init(self):
        collector = AbuseIPDBCollector({"api_key": "test-key"})
        assert collector.name == "abuseipdb"
        assert collector.api_key == "test-key"

    def test_no_api_key(self):
        collector = AbuseIPDBCollector({})
        assert collector.api_key == ""

    def test_parse_entry(self):
        collector = AbuseIPDBCollector({})
        entry = {
            "ipAddress": "203.0.113.42",
            "abuseConfidenceScore": 85,
            "countryCode": "US",
            "totalReports": 25,
            "lastReportedAt": "2025-01-01T00:00:00Z",
            "isWhitelisted": False,
        }
        ioc = collector._parse_entry(entry)
        assert ioc is not None
        assert ioc.type == IOCType.IP
        assert ioc.value == "203.0.113.42"
        assert ioc.confidence == Confidence.HIGH
        assert "country:US" in ioc.tags
        assert ioc.severity == 8.5
        assert ioc.last_seen.isoformat() == "2025-01-01T00:00:00+00:00"

    def test_parse_entry_whitelisted(self):
        collector = AbuseIPDBCollector({})
        entry = {
            "ipAddress": "192.0.2.1",
            "abuseConfidenceScore": 90,
            "isWhitelisted": True,
        }
        assert collector._parse_entry(entry) is None

    def test_score_to_confidence(self):
        collector = AbuseIPDBCollector({})
        assert collector._score_to_confidence(80) == Confidence.HIGH
        assert collector._score_to_confidence(60) == Confidence.MEDIUM
        assert collector._score_to_confidence(30) == Confidence.LOW


class TestMitreCollector:
    def test_init(self):
        collector = MitreAttackCollector({"collect_techniques": True})
        assert collector.name == "mitre_attack"

    def test_extract_tactic(self):
        collector = MitreAttackCollector({})
        obj = {
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
            ],
        }
        assert collector._extract_tactic(obj) == "execution"

    def test_extract_tactic_empty(self):
        collector = MitreAttackCollector({})
        assert collector._extract_tactic({}) == ""


def _attack(obj_type, mitre_id, name, **extra):
    refs = (
        [
            {
                "source_name": "mitre-attack",
                "external_id": mitre_id,
                "url": f"https://attack.mitre.org/x/{mitre_id}",
            }
        ]
        if mitre_id
        else []
    )
    return {"type": obj_type, "name": name, "external_references": refs, **extra}


ATTACK_BUNDLE = {
    "type": "bundle",
    "objects": [
        _attack(
            "attack-pattern",
            "T1059.001",
            "PowerShell",
            kill_chain_phases=[
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
            ],
        ),
        _attack("attack-pattern", "T9999", "Old technique", revoked=True),
        _attack("attack-pattern", "T9998", "Deprecated", x_mitre_deprecated=True),
        _attack("attack-pattern", "", "No ATT&CK id"),
        _attack("malware", "S0002", "Mimikatz"),
        _attack("tool", "S0039", "Net"),
        _attack("intrusion-set", "G0007", "APT28"),
    ],
}


@pytest.mark.asyncio
async def test_mitre_collect_parses_bundle_with_single_download():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url)
        return httpx.Response(200, json=ATTACK_BUNDLE)

    collector = MitreAttackCollector({})
    collector._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    iocs = await collector.collect()

    assert len(requests) == 1
    by_id = {i.mitre_id: i for i in iocs}
    assert set(by_id) == {"T1059.001", "S0002", "S0039", "G0007"}
    assert by_id["T1059.001"].value == "https://attack.mitre.org/techniques/T1059/001/"
    assert "execution" in by_id["T1059.001"].tags
    assert by_id["S0002"].value == "https://attack.mitre.org/software/S0002/"
    assert "malware" in by_id["S0002"].tags
    assert by_id["G0007"].value == "https://attack.mitre.org/groups/G0007/"


@pytest.mark.asyncio
async def test_mitre_collect_survives_download_failure():
    collector = MitreAttackCollector({})
    collector._client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(503))
    )
    assert await collector.collect() == []


class TestCustomFeedCollector:
    def test_init(self):
        collector = CustomFeedCollector({"feeds": []})
        assert collector.name == "custom_feed"

    def test_parse_json_list(self, tmp_path):
        json_data = """
        [
            {"value": "5.5.5.5", "type": "ip", "confidence": "high"},
            {"value": "evil.com", "type": "domain", "confidence": "medium"}
        ]
        """
        collector = CustomFeedCollector({})
        iocs = collector._parse_json(
            json_data, "test_feed", Confidence.MEDIUM, IOCType.IP, [], {}
        )
        assert len(iocs) == 2
        assert iocs[0].value == "5.5.5.5"
        assert iocs[0].type == IOCType.IP
        assert iocs[0].confidence == Confidence.HIGH
        assert iocs[1].value == "evil.com"
        assert iocs[1].type == IOCType.DOMAIN

    def test_parse_json_with_iocs_key(self):
        json_data = '{"iocs": [{"value": "1.2.3.4", "type": "ip"}]}'
        collector = CustomFeedCollector({})
        iocs = collector._parse_json(json_data, "test", Confidence.LOW, None, [], {})
        assert len(iocs) == 1
        assert iocs[0].value == "1.2.3.4"

    def test_parse_csv(self):
        csv_data = "value,type,confidence\n6.6.6.6,ip,high\nmalware.net,domain,medium\n"
        collector = CustomFeedCollector({})
        iocs = collector._parse_csv(
            csv_data, "csv_feed", Confidence.LOW, IOCType.IP, [], {}
        )
        assert len(iocs) >= 1
        assert iocs[0].type == IOCType.IP
        if len(iocs) > 1:
            assert iocs[1].type == IOCType.DOMAIN

    def test_parse_yaml(self):
        yaml_data = """
        - value: 7.7.7.7
          type: ip
          confidence: critical
        - value: bad.org
          type: domain
        """
        collector = CustomFeedCollector({})
        iocs = collector._parse_yaml(
            yaml_data, "yaml_feed", Confidence.MEDIUM, IOCType.IP, [], {}
        )
        assert len(iocs) == 2
        assert iocs[0].confidence == Confidence.CRITICAL
        assert iocs[1].value == "bad.org"

    def test_entry_to_ioc_with_tags_string(self):
        collector = CustomFeedCollector({})
        entry = {
            "value": "10.0.0.1",
            "type": "ip",
            "tags": "ransomware, c2, critical",
        }
        ioc = collector._entry_to_ioc(
            entry, "test", Confidence.MEDIUM, None, ["global"], {}
        )
        assert "ransomware" in ioc.tags
        assert "c2" in ioc.tags
        assert "global" in ioc.tags

    def test_entry_to_ioc_defaults(self):
        collector = CustomFeedCollector({})
        entry = {"value": "unknown-ioc"}
        ioc = collector._entry_to_ioc(
            entry, "test", Confidence.LOW, IOCType.HASH, ["auto"], {}
        )
        assert ioc.value == "unknown-ioc"
        assert ioc.type == IOCType.HASH
        assert ioc.confidence == Confidence.LOW


class TestIOCModel:
    def test_ioc_creation(self):
        ioc = IOC(
            type=IOCType.IP,
            value="8.8.8.8",
            source="test",
            confidence=Confidence.HIGH,
            tags=["dns", "public"],
        )
        assert ioc.type == IOCType.IP
        assert ioc.value == "8.8.8.8"
        assert ioc.confidence == Confidence.HIGH
        assert ioc.active is True
        assert ioc.severity == 5.0

    def test_ioc_dict_serialization(self):
        ioc = IOC(type=IOCType.DOMAIN, value="test.com", source="manual")
        result = ioc.dict()
        assert isinstance(result["first_seen"], str)
        assert isinstance(result["last_seen"], str)
        assert result["type"] == "domain"

    def test_ioc_type_values(self):
        assert IOCType.IP.value == "ip"
        assert IOCType.DOMAIN.value == "domain"
        assert IOCType.CVE.value == "cve"
