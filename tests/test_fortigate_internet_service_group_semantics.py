from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def _extract(direction: str | None, field: str = "internet-service-src-group"):
    direction_line = f"set direction {direction}" if direction else ""
    section = "firewall local-in-policy6" if field.endswith("6-src-group") else "firewall local-in-policy"
    return extract_fortigate_config(f'''config firewall internet-service-group
    edit "GROUP-A"
        {direction_line}
        set member "IS-A" "IS-B"
    next
end
config {section}
    edit 1
        set {field} "GROUP-A"
    next
end
''')


def test_inventory_preserves_group_direction_and_members():
    result = _extract("source")
    item = next(item for item in result.inventory_items if item.source_path == "firewall internet-service-group")
    assert [(command.key, command.values) for command in item.commands] == [
        ("direction", ["source"]), ("member", ["IS-A", "IS-B"])
    ]


def test_source_and_both_are_compatible():
    for direction in ("source", "both", None):
        result = _extract(direction)
        assert result.dependencies[0].result == "RESOLVED"
        assert not any(entry.category == "FortiGate Semantic Validation" for entry in result.canonical_ir.audit_entries)


def test_destination_is_resolved_but_requires_semantic_review():
    result = _extract("destination")
    dependency = result.dependencies[0]
    assert dependency.result == "RESOLVED"
    assert dependency.target_path == "firewall internet-service-group"
    assert any(entry.category == "FortiGate Semantic Validation" for entry in result.canonical_ir.audit_entries)
    item = next(item for item in result.inventory_items if item.source_path == "firewall local-in-policy")
    assert "incompatible-internet-service-group-direction:GROUP-A" in item.notes
    assert not any("unresolved-reference:GROUP-A" in note for note in item.notes)


def test_ipv6_direction_mismatch_keeps_exact_field_name():
    result = _extract("destination", "internet-service6-src-group")
    audit = next(entry for entry in result.canonical_ir.audit_entries if entry.category == "FortiGate Semantic Validation")
    assert "internet-service6-src-group" in audit.message


def test_unknown_direction_is_manual_review_without_coercion():
    result = _extract("future")
    assert "direction 'future'" in next(
        entry.message for entry in result.canonical_ir.audit_entries
        if entry.category == "FortiGate Semantic Validation"
    )
