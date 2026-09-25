from fwmigrate.vendors.fortigate.config import ExtractionConfig
from fwmigrate.vendors.fortigate.extraction.coverage import typed_source_paths
from fwmigrate.vendors.fortigate.extraction.extractor import extract_fortigate_config
from fwmigrate.vendors.fortigate.parser import parse_fortigate_config
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from fwmigrate.vendors.fortigate.section_registry import registered_sections


def test_static6_keeps_its_native_source_fields():
    source = """config router static6
    edit 21
        set dst 2001:db8:1::/64
        set device port1
        set gateway 2001:db8::1
        set distance 7
        set sdwan-zone virtual-wan-link
        set weight 3
        set vendor-option preserve-me
    next
end
"""
    extracted = extract_fortigate_config(parse_fortigate_config(source), config=ExtractionConfig())
    route = extracted.config.static_routes[0]

    assert route.address_family == "ipv6"
    assert route.dst == "2001:db8:1::/64"
    assert route.device == "port1"
    assert route.distance == 7
    assert route.sdwan_zone == ["virtual-wan-link"]
    assert route.raw_extra["vendor-option"] == "preserve-me"
    assert "router static6" in typed_source_paths()


def test_ippool6_has_independent_namespace_and_policy_reference():
    from fwmigrate.vendors.fortigate.model.ippool import FGIPPool
    from fwmigrate.vendors.fortigate.model.ippool6 import FGIPPool6
    from fwmigrate.vendors.fortigate.model.policy import FGPolicy
    from fwmigrate.vendors.fortigate.model.source import FGConfig
    from fwmigrate.vendors.fortigate.relationships.references import (
        ReferenceKind,
        build_reference_index,
        collect_broken_references,
    )

    config = FGConfig(
        ip_pools=[FGIPPool(name="shared")],
        ip_pools6=[FGIPPool6(name="shared", startip="2001:db8::1", nat46="enable")],
        policies=[FGPolicy(policy_id=1, poolname6=["shared", "missing-v6"])],
    )
    index = build_reference_index(config)
    assert index.get(ReferenceKind.IP_POOL, vdom="root", name="shared") is config.ip_pools[0]
    assert index.get(ReferenceKind.IP_POOL6, vdom="root", name="shared") is config.ip_pools6[0]
    assert [(item.source_field, item.reference, item.expected_kinds) for item in collect_broken_references(config)] == [
        ("poolname6", "missing-v6", (ReferenceKind.IP_POOL6,))
    ]

def test_ippool6_extraction_preserves_unknowns_and_family():
    source = """config firewall ippool6
    edit v6-pool
        set startip 2001:db8::10
        set endip 2001:db8::20
        set nat46 enable
        set future-pool-setting keep-me
    next
end
"""
    reporter = FortiGateSourceReporter()
    analysis = reporter.analyze_source(source)
    pool = analysis.extracted.config.ip_pools6[0]
    assert pool.startip == "2001:db8::10"
    assert pool.nat46 == "enable"
    assert pool.raw_extra["future-pool-setting"] == "keep-me"
    assert pool.address_family == "ipv6"


def test_vip6_and_vipgrp6_keep_separate_namespaces():
    from fwmigrate.vendors.fortigate.model.vip import FGVIP, FGVIPGroup
    from fwmigrate.vendors.fortigate.model.vip6 import FGVIP6, FGVIPGroup6
    from fwmigrate.vendors.fortigate.model.source import FGConfig
    from fwmigrate.vendors.fortigate.relationships.references import (
        ReferenceKind,
        build_reference_index,
        collect_broken_references,
    )

    config = FGConfig(
        vips=[FGVIP(name="same")], vips6=[FGVIP6(name="same")],
        vip_groups=[FGVIPGroup(name="group")],
        vip_groups6=[FGVIPGroup6(name="group", members=["same", "missing-v6"])],
    )
    index = build_reference_index(config)
    assert index.get(ReferenceKind.VIP, vdom="root", name="same") is config.vips[0]
    assert index.get(ReferenceKind.VIP6, vdom="root", name="same") is config.vips6[0]
    assert not index.duplicates
    assert [(item.source_field, item.reference) for item in collect_broken_references(config)] == [
        ("members", "missing-v6")
    ]

    source = """config firewall vip6
    edit same
        set extip 2001:db8::1
        set mappedip 2001:db8:1::1
        set nat64 enable
        set vendor-option preserve-me
    next
end
config firewall vipgrp6
    edit group
        set member same
    next
end
"""
    reporter = FortiGateSourceReporter()
    analysis = reporter.analyze_source(source)
    assert analysis.extracted.config.vips6[0].extip == "2001:db8::1"
    assert analysis.extracted.config.vips6[0].raw_extra["vendor-option"] == "preserve-me"
    assert analysis.extracted.config.vip_groups6[0].members == ["same"]

