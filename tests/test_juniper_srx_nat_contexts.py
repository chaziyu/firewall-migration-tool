from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_nat_context_direction_rules_and_tenant_normalization():
    config = JuniperSRXParser("""
    set security nat source rule-set src from zone trust
    set security nat source rule-set src to zone untrust
    set security nat destination rule-set dst from zone untrust
    set security nat destination rule-set dst to zone trust
    set security nat static rule-set st from zone untrust
    set security nat static rule-set st to zone trust
    set tenants tenant-a security nat source rule-set src from zone trust
    set tenants tenant-a security nat source rule-set src to zone untrust
    """).parse_raw()
    root = config.contexts["root"].nat
    assert root.source_rule_sets["src"].to_context.zones == ["untrust"]
    assert root.destination_rule_sets["dst"].to_context is None
    assert root.destination_rule_sets["dst"].source_attributes["unsupported_contexts"]
    assert root.static_rule_sets["st"].to_context is None
    tenant = config.contexts["tenant-a"].nat.source_rule_sets["src"]
    assert tenant.from_context.zones == ["trust"]
    assert tenant.to_context.zones == ["untrust"]


def test_invalid_context_is_partial_and_requires_review():
    parser = JuniperSRXParser(
        "set security nat destination rule-set dst to interface ge-0/0/0"
    )
    config = parser.parse_raw()
    command = parser.tokenizer.tokenize(parser.content)[0]
    from fwmigrate.parsers.juniper_srx.handlers.nat import handle_nat_command
    handle_nat_command(command, config.contexts["root"])
    assert command.extraction_status is ExtractionStatus.PARTIALLY_NORMALIZED
    assert command.requires_manual_review
