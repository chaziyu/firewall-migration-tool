from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_unset_removes_active_semantic_values_and_is_preserved_as_evidence():
    config = """config firewall service custom
    edit "icmp-test"
        set protocol ICMP
        set icmptype 8
        set icmpcode 0
        set options one two
        unset options
        unset icmptype
        unset icmpcode
    next
end
"""

    parsed = parse_fortigate_config(config)
    service = parsed.services[0]

    assert service.icmptype is None
    assert service.icmpcode is None
    assert "options" not in service.extra_settings

    extracted = extract_fortigate_config(config)
    commands = extracted.inventory_items[0].commands
    unset_commands = [command for command in commands if command.operation == "unset"]
    assert [(command.key, command.values) for command in unset_commands] == [
        ("options", []),
        ("icmptype", []),
        ("icmpcode", []),
    ]


def test_append_updates_list_semantics_and_retains_original_operation():
    config = """config firewall service group
    edit "web-services"
        set member "HTTP"
        append member "HTTPS"
    next
end
"""

    parsed = parse_fortigate_config(config)
    assert parsed.service_groups[0].member == ["HTTP", "HTTPS"]

    extracted = extract_fortigate_config(config)
    append = next(
        command
        for command in extracted.inventory_items[0].commands
        if command.operation == "append"
    )
    assert append.key == "member"
    assert append.values == ["HTTPS"]

