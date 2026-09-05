from fwmigrate.parsers.palo_alto import PANOSSourceParser
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures/palo_alto/phase94_production.xml"

def test_pan_dns_proxy_and_monitor_are_typed():
    xml = '<config><devices><entry name="fw"><network><dns-proxy><entry name="p"><cache><cache-enabled>yes</cache-enabled></cache><interface><member>loopback.1</member></interface></entry></dns-proxy><profiles><monitor-profile><entry name="default"><interval>3</interval><threshold>5</threshold><action>wait-recover</action></entry></monitor-profile></profiles></network></entry></devices></config>'
    ir = PANOSSourceParser().parse(xml)
    assert ir.pan_dns_proxies[0].cache_enabled is True
    assert ir.pan_monitor_profiles[0].interval_seconds == 3

def test_pan_advanced_network_production_hierarchy():
    xml = '<config><devices><entry name="fw"><network><interface><loopback><entry name="loopback.78"/></loopback><tunnel><entry name="tunnel.78"/></tunnel></interface><dns-proxy><entry name="Subang ADS"><cache><enabled>yes</enabled><max-ttl><enabled>no</enabled></max-ttl></cache><default><primary>10.1.4.2</primary><secondary>10.1.4.1</secondary></default><tcp-queries><enabled>no</enabled></tcp-queries><domain-servers><entry name="prasarana.com.my"><domain-name><member>*.prasarana.com.my</member></domain-name><primary>10.1.4.2</primary><secondary>10.1.4.1</secondary><cacheable>yes</cacheable></entry></domain-servers><interface><member>loopback.78</member><member>tunnel.78</member></interface></entry></dns-proxy><qos><profile><entry name="default"><class-bandwidth-type><mbps><class><entry name="real-time"/></class><class><entry name="high"/></class></mbps></class-bandwidth-type></entry></profile></qos></network></entry></devices></config>'
    ir = PANOSSourceParser().parse(xml)
    assert ir.pan_dns_proxies[0].default_primary == "10.1.4.2"
    assert ir.pan_dns_proxies[0].domain_servers[0].domain_names == ["*.prasarana.com.my"]
    assert ir.pan_qos_profiles[0].bandwidth_type == "mbps"
    assert [c.name for c in ir.pan_qos_profiles[0].classes] == ["real-time", "high"]
    assert ir.pan_dns_proxies[0].resolved_interfaces == ["loopback.78", "tunnel.78"]
    assert ir.pan_dns_proxies[0].unresolved_interfaces == []

def test_pan_advanced_network_unknown_nested_child_is_unsupported():
    result = PANOSSourceParser().extract('<config><devices><entry name="fw"><network><dns-proxy><entry name="p"><future-option><x>1</x></future-option></entry></dns-proxy></network></entry></devices></config>')
    assert any(item.status.value == "UNSUPPORTED" and "future-option" in item.source_path for item in result.inventory_items)


def test_phase94_dns_and_qos_exact_values():
    ir = PANOSSourceParser().parse(FIXTURE.read_text())
    dns = ir.pan_dns_proxies[0]
    assert (dns.name, dns.cache_enabled, dns.max_ttl_enabled, dns.default_primary, dns.default_secondary, dns.tcp_queries_enabled) == ("Subang ADS", True, False, "10.1.4.2", "10.1.4.1", False)
    assert (dns.domain_servers[0].name, dns.domain_servers[0].domain_names, dns.domain_servers[0].cacheable) == ("prasarana.com.my", ["prasarana.com.my", "*.prasarana.com.my"], True)
    assert dns.interfaces == ["loopback.78", "tunnel.78"] and dns.resolved_interfaces == dns.interfaces
    qos = ir.pan_qos_profiles[0]
    assert (qos.name, qos.bandwidth_type, [c.name for c in qos.classes], [c.priority for c in qos.classes]) == ("default", "mbps", [f"class{i}" for i in range(1, 9)], [str(i) for i in range(1, 9)])


def test_phase94_malformed_dns_boolean_and_qos_numeric_are_retained_for_review():
    xml = FIXTURE.read_text().replace("<cacheable>yes</cacheable>", "<cacheable>maybe</cacheable>").replace("<priority>8</priority>", "<priority>bad</priority>")
    result = PANOSSourceParser().extract(xml)
    dns = result.canonical_ir.pan_dns_proxies[0].domain_servers[0]
    assert dns.cacheable is None and dns.review_reasons
    assert result.canonical_ir.pan_qos_profiles[0].classes[-1].priority == "bad"
