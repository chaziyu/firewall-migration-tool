from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.cisco_asa.extractor import extract_cisco_asa_config


def test_asa_coverage_matches_semantic_support_tiers():
    result = extract_cisco_asa_config("""hostname edge
object network WEB
 host 192.0.2.10
nat (inside,outside) source static WEB interface
crypto map OUTSIDE 10 match address VPN6
aaa authentication ssh console LOCAL
class-map inspection
 match default-inspection-traffic
dhcpd address 192.0.2.20-192.0.2.30 inside
dns server-group corp
 name-server 2001:db8::53
http server enable
failover
context tenant-a
foo unsupported
""")
    paths = {section.path: section.status for section in result.source_sections}
    assert paths["system hostname"] is ExtractionStatus.NORMALIZED
    assert paths["nat manual"] is ExtractionStatus.PARTIALLY_NORMALIZED
    assert paths["crypto map"] is ExtractionStatus.PARTIALLY_NORMALIZED
    assert paths["aaa"] is ExtractionStatus.PARTIALLY_NORMALIZED
    assert paths["class-map"] is ExtractionStatus.PARTIALLY_NORMALIZED
    assert paths["dhcpd"] is ExtractionStatus.PARTIALLY_NORMALIZED
    assert paths["dns"] is ExtractionStatus.PARTIALLY_NORMALIZED
    assert paths["http"] is ExtractionStatus.PARTIALLY_NORMALIZED
    assert paths["failover"] is ExtractionStatus.PARTIALLY_NORMALIZED
    assert paths["context"] is ExtractionStatus.PARTIALLY_NORMALIZED
    assert paths["other"] is ExtractionStatus.UNSUPPORTED
