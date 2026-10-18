from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


SOURCE = '''config vdom
edit blue
config firewall central-snat-map
    edit 20
        set srcintf "lan"
        set dstintf "wan"
        set orig-addr "missing-address"
        set dst-addr "all"
        set nat-ippool "missing-pool"
        set protocol 6
        set orig-port 1000-2000
        set nat-port 3000-4000
        set port-preserve disable
        set nat enable
        set status enable
        set type ipv4
        set future-option retained
    next
    edit 3
        set status disable
        set nat disable
        set type ipv4
    next
    edit 20
        append srcintf "dmz"
        unset nat-port
    next
    edit 0
        set status disable
    next
    edit 0
        set status disable
    next
end
config firewall policy
    edit 9
        set nat enable
        set fixedport enable
        set port-preserve enable
    next
end
next
end
'''


def test_central_nat_preserves_scope_order_edits_absence_and_unknown_evidence():
    analysis = FortiGateSourceReporter().analyze_source(SOURCE)
    config = analysis.extracted.config
    assert [row.policy_id for row in config.central_snat] == [20, 3, 0, 0]
    rule = config.central_snat[0]
    assert rule.vdom == "blue" and rule.srcintf == ["lan", "dmz"]
    assert rule.orig_port == "1000-2000" and rule.nat_port is None
    assert "nat_port" not in rule.explicit_fields
    assert rule.port_preserve == "disable" and rule.raw_extra["future-option"] == "retained"
    assert config.central_snat[1].srcintf is None
    assert analysis.derived.central_nat[0].translation_type == "ip_pool"
    assert analysis.derived.central_nat[1].translation_type == "no_nat"
    assert analysis.derived.central_nat[2].issues
    assert any(row.source_kind == "central_snat" and row.reference == "missing-pool"
               for row in analysis.derived.broken_references)
    assert config.policies[0].fixedport == "enable"
    assert analysis.derived.nat[0].fixedport == "enable"
    assert analysis.derived.nat[0].port_preserve == "enable"
    assert sum(row.source_path == "firewall central-snat-map"
               for row in analysis.extracted.source_objects) == 5
    preview = FortiGateSourceReporter().build_preview(analysis)
    assert preview["sections"]["central_snat"][0]["port_preserve"] == "disable"
