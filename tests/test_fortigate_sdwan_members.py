from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def _member(config: str):
    result = extract_fortigate_config(config)
    sdwan = result.canonical_ir.sdwan
    assert sdwan is not None
    return sdwan.members[0], result


def test_sdwan_member_types_all_fortios_fields_and_preserves_provenance():
    member, _ = _member('''
config system sdwan
    config members
        edit 10
            set interface "wan1"
            set zone "Underlay"
            set gateway 192.0.2.1
            set gateway6 2001:db8::1
            set preferred-source 192.0.2.10
            set source 192.0.2.20
            set source6 2001:db8::20
            set cost 100
            set priority 5
            set priority6 50
            set spillover-threshold 1000
            set ingress-spillover-threshold 2000
            set status enable
            set transport-group 10
            set volume-ratio 3
            set weight 20
            set comment "Primary WAN"
        next
    end
end
''')
    assert member.model_dump(exclude={"source_attributes", "review_reasons"}) == {
        "source_id": 10, "source_context": "root", "interface": "wan1",
        "zone": "Underlay", "gateway": "192.0.2.1", "source": "192.0.2.20",
        "gateway6": "2001:db8::1", "source6": "2001:db8::20",
        "preferred_source": "192.0.2.10", "transport_group": 10, "cost": 100,
        "weight": 20, "priority": 5, "priority6": 50,
        "spillover_threshold": 1000, "ingress_spillover_threshold": 2000,
        "volume_ratio": 3, "status": "enable", "description": "Primary WAN",
        "source_explicit_fields": sorted(member.source_explicit_fields),
        "migration_status": "EXTRACT_ONLY", "requires_manual_review": True,
    }
    assert not member.review_reasons


def test_sdwan_member_defaults_and_unset_restore_without_fabricating_addresses():
    member, result = _member('''
config system sdwan
    config members
        edit 1
            set interface "wan1"
            set weight 50
            unset weight
            set priority6 20
            unset priority6
            set transport-group 5
            unset transport-group
            set preferred-source 192.0.2.10
            unset preferred-source
        next
    end
end
''')
    assert (member.zone, member.cost, member.weight, member.priority,
            member.priority6, member.spillover_threshold,
            member.ingress_spillover_threshold, member.transport_group,
            member.volume_ratio, member.status) == (
        "virtual-wan-link", 0, 1, 1, 1024, 0, 0, 0, 1, "enable"
    )
    assert all(getattr(member, field) is None for field in (
        "gateway", "gateway6", "source", "source6", "preferred_source"
    ))
    assert not {"weight", "priority6", "transport_group", "preferred_source"} & set(
        member.source_explicit_fields
    )
    assert any(command.operation == "unset" and command.key == "weight"
               for item in result.inventory_items for command in item.commands)


def test_sdwan_member_invalid_values_are_retained_and_reviewed():
    member, _ = _member('''
config system sdwan
    config members
        edit 1
            set interface "wan1"
            set gateway bad-address
            set gateway6 192.0.2.1
            set weight 256
            set transport-group 256
            set status mystery
        next
    end
end
''')
    assert member.gateway == "bad-address"
    assert member.gateway6 == "192.0.2.1"
    assert member.weight == 256
    assert member.transport_group == 256
    assert any("gateway" in reason for reason in member.review_reasons)
    assert any("weight" in reason for reason in member.review_reasons)
    assert any("transport-group" in reason for reason in member.review_reasons)
    assert any("status" in reason for reason in member.review_reasons)


def test_sdwan_member_unknown_fields_and_source_order_survive():
    result = extract_fortigate_config('''
config system sdwan
    config members
        edit 30
            set interface "wan3"
            set future-member-option "retained"
        next
        edit 10
            set interface "wan1"
        next
        edit 20
            set interface "wan2"
        next
    end
end
''')
    sdwan = result.canonical_ir.sdwan
    assert sdwan is not None
    assert [member.source_id for member in sdwan.members] == [30, 10, 20]
    assert sdwan.members[0].source_attributes["future_member_option"] == "retained"
