from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.model import JuniperPersistentNAT
from fwmigrate.parsers.juniper_srx.handlers.nat import handle_nat_command
from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser
from fwmigrate.parsers.juniper_srx.provenance import record_inactive_candidate
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand, JunosOperation


def _rule(config, name="r"):
    return config.contexts["root"].nat.source_rule_sets["rs"].rules[0]


def test_persistent_nat_pool_and_interface_children_are_structured():
    config = JuniperSRXParser("""
    set security nat source rule-set rs rule r then source-nat pool p persistent-nat address-mapping
    set security nat source rule-set rs rule r then source-nat pool p persistent-nat inactivity-timeout 60
    set security nat source rule-set rs rule r then source-nat pool p persistent-nat max-session-number 10
    set security nat source rule-set rs rule r then source-nat pool p persistent-nat permit target-host
    set security nat source rule-set rs rule i then source-nat interface persistent-nat permit any-remote-host
    """).parse_raw()
    rule = config.contexts["root"].nat.source_rule_sets["rs"].rules[0]
    persistent = rule.action["persistent_nat"]
    assert rule.action["pool_name"] == "p"
    assert persistent.address_mapping and persistent.inactivity_timeout == 60
    assert persistent.max_session_number == 10 and persistent.permit == "target-host"
    interface = config.contexts["root"].nat.source_rule_sets["rs"].rules[1]
    assert interface.action["type"] == "interface"
    assert interface.action["persistent_nat"].permit == "any-remote-host"


def test_unknown_persistent_nat_child_is_partial_and_preserved():
    text = """
    set security nat source rule-set rs rule r then source-nat pool p persistent-nat future-mode x
    """
    parser = JuniperSRXParser(text)
    config = parser.parse_raw()
    command = parser.tokenizer.tokenize(text)[0]
    handle_nat_command(command, config.contexts["root"])
    persistent = _rule(config).action["persistent_nat"]
    assert command.extraction_status is ExtractionStatus.PARTIALLY_NORMALIZED
    assert command.requires_manual_review
    assert persistent.source_attributes["unknown_children"]


def test_persistent_nat_field_candidates_shadow_inherited_values():
    config = JuniperSRXParser("""
    set groups base security nat source rule-set rs rule r then source-nat pool p persistent-nat inactivity-timeout 30
    set apply-groups base
    set security nat source rule-set rs rule r then source-nat pool p persistent-nat inactivity-timeout 60
    """).parse_raw()
    history = _rule(config).action["persistent_nat"].field_candidate_history["inactivity_timeout"]
    assert [candidate.value for candidate in history] == [30, 60]
    assert history[0].shadowed and history[1].effective


def test_inactive_persistent_nat_candidate_is_available_from_provenance_helper():
    persistent = JuniperPersistentNAT()
    cmd = JunosCommand(operation=JunosOperation.SET, tokens=["set", "persistent-nat"],
                       raw_sanitized="set persistent-nat", line_number=1)
    record_inactive_candidate(persistent.field_candidate_history, "inactivity_timeout", 30, cmd)
    assert persistent.field_candidate_history["inactivity_timeout"][0].status.value == "INACTIVE"
