from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.vendors.juniper_srx.source_report import extract_juniper_source
from fwmigrate.vendors.juniper_srx.web_report import build_juniper_preview


def test_hierarchical_quoted_values_survive_normalization():
    result = extract_juniper_source(
        """interfaces {
    ge-0/0/0 {
        description "WAN Uplink";
    }
}
"""
    )

    assert result.config.get_context().interfaces["ge-0/0/0"].description == "WAN Uplink"


def test_hierarchical_escaped_quotes_survive_normalization():
    result = extract_juniper_source(
        """interfaces {
    ge-0/0/0 {
        description "Edge \\"WAN\\" Uplink";
    }
}
"""
    )

    assert result.config.get_context().interfaces["ge-0/0/0"].description == 'Edge "WAN" Uplink'


def test_same_static_prefix_in_different_ribs_remains_distinct():
    result = extract_juniper_source(
        """set routing-options rib inet.0 static route 10.0.0.0/24 next-hop 192.0.2.1
set routing-options rib mgmt.inet.0 static route 10.0.0.0/24 next-hop 198.51.100.1
"""
    )

    routes = result.config.get_context().routes
    assert len(routes) == 2
    assert {(route.rib, route.next_hops[0].value) for route in routes} == {
        ("inet.0", "192.0.2.1"),
        ("mgmt.inet.0", "198.51.100.1"),
    }


def test_unknown_next_hop_children_are_preserved_and_marked_partial():
    result = extract_juniper_source(
        "set routing-options static route 10.0.0.0/24 "
        "qualified-next-hop 192.0.2.1 bfd-liveness-detection minimum-interval 300"
    )

    route = result.config.get_context().routes[0]
    next_hop = route.next_hops[0]
    assert next_hop.source_attributes["unknown_children"][0]["tokens"] == [
        "bfd-liveness-detection",
        "minimum-interval",
        "300",
    ]
    command = result.inventory_items[0].commands[0]
    assert command.status == ExtractionStatus.PARTIAL
    assert command.requires_manual_review is True


def test_local_address_definition_shadows_inherited_definition():
    result = extract_juniper_source(
        """set groups G security address-book global address A 192.0.2.1/32
set apply-groups G
set security address-book global address A 198.51.100.1/32
"""
    )

    inherited = [
        item
        for item in result.derived.inheritance_view["effective_statements"]
        if item["origin"] == "inherited-group"
        and item["target_path"][:5] == (
            "security",
            "address-book",
            "global",
            "address",
            "A",
        )
    ]
    assert len(inherited) == 1
    assert inherited[0]["status"] == "SHADOWED"


def test_scheduler_exclude_is_preserved_as_explicit_source():
    result = extract_juniper_source(
        "set schedulers scheduler WORK exclude start-date 2026-12-25.00:00 "
        "stop-date 2026-12-26.00:00"
    )

    scheduler = result.config.get_context().schedulers["WORK"]
    assert scheduler.exclusions == [{
        "values": [
            "start-date",
            "2026-12-25.00:00",
            "stop-date",
            "2026-12-26.00:00",
        ],
        "raw": (
            "set schedulers scheduler WORK exclude start-date 2026-12-25.00:00 "
            "stop-date 2026-12-26.00:00"
        ),
    }]
    assert result.inventory_items[0].commands[0].status == ExtractionStatus.SOURCE_ONLY


def test_unmodeled_permit_child_is_partial_not_extracted():
    result = extract_juniper_source(
        "set security policies from-zone trust to-zone untrust policy P "
        "then permit unsupported-child value"
    )

    policy = result.config.get_context().policies[0]
    assert policy.action == "permit"
    assert "unsupported-child_value" in policy.permit_options
    command = result.inventory_items[0].commands[0]
    assert command.status == ExtractionStatus.PARTIAL
    assert command.requires_manual_review is True


def test_nat_preview_does_not_label_action_metadata_as_addresses():
    result = extract_juniper_source(
        "set security nat source rule-set RS rule R then source-nat interface"
    )

    row = build_juniper_preview(result)["sections"]["nat"][0]
    assert row["translated_addresses"] == []
    assert row["translation"] == {"type": "interface"}



def test_legacy_zone_address_book_is_preserved_without_synthetic_book():
    result = extract_juniper_source(
        "set security zones security-zone trust address-book address "
        "legacy_host 192.0.2.10/32"
    )

    context = result.config.get_context()
    assert context.address_books == {}
    preserved = context.source_attributes["legacy_zone_address_book"][0]
    assert preserved["zone"] == "trust"
    assert preserved["tokens"] == [
        "address-book",
        "address",
        "legacy_host",
        "192.0.2.10/32",
    ]
    command = result.inventory_items[0].commands[0]
    assert command.status == ExtractionStatus.SOURCE_ONLY
    assert command.requires_manual_review is True



def test_configuration_groups_are_modeled_explicit_source_not_source_only():
    result = extract_juniper_source(
        """set groups G interfaces ge-0/0/0 description inherited
set apply-groups G
"""
    )
    commands = [command for item in result.inventory_items for command in item.commands]
    assert commands
    assert all(command.status == ExtractionStatus.EXTRACTED for command in commands)
    assert not result.review_required



def test_group_keywords_used_as_object_names_are_not_group_commands():
    result = extract_juniper_source(
        """set applications application groups protocol tcp
set applications application apply-groups protocol udp
"""
    )

    context = result.config.get_context()
    assert set(context.applications) >= {"groups", "apply-groups"}
    assert context.applications["groups"].top_level.protocol == "tcp"
    assert context.applications["apply-groups"].top_level.protocol == "udp"
    assert not result.config.configuration_groups


def test_top_level_application_settings_do_not_create_synthetic_term():
    result = extract_juniper_source(
        """set applications application WEB protocol tcp
set applications application WEB destination-port 443
"""
    )

    application = result.config.get_context().applications["WEB"]
    assert application.terms == []
    assert application.top_level.protocol == "tcp"
    assert application.top_level.destination_ports == ["443"]

    service = build_juniper_preview(result)["sections"]["services"][0]
    assert service["term"] is None
    assert service["protocol"] == "tcp"
    assert service["port"] == ["443"]


def test_modeled_utm_and_idp_commands_are_reported_as_extracted():
    result = extract_juniper_source(
        """set security utm feature-profile anti-virus profile AV type juniper-express-engine
set security idp idp-policy IDP rulebase-ips rule R action drop
"""
    )

    commands = [command for item in result.inventory_items for command in item.commands]
    by_handler = {command.parser_handler: command for command in commands}
    assert by_handler["utm"].status == ExtractionStatus.EXTRACTED
    assert by_handler["idp"].status == ExtractionStatus.EXTRACTED
