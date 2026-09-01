from pathlib import Path

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


FIXTURE = Path(__file__).parent / "fixtures" / "palo_alto" / "policy_families.xml"
FAMILIES = {"decryption", "application-override", "authentication", "pbf", "qos", "dos",
            "tunnel-inspect", "sdwan", "network-packet-broker"}


def _result(xml_text=None):
    return PANOSSourceParser().extract(
        xml_text if xml_text is not None else FIXTURE.read_text(encoding="utf-8")
    )


def _pbf(result, name):
    return next(item for item in result.inventory_items if item.domain == "policy:pbf" and item.name == name)


def _pbf_xml(entry):
    return f"""<config version='11.1.0'><devices><entry name='fw1'><vsys><entry name='vsys1'>
      <pre-rulebase><pbf><rules>{entry}</rules></pbf></pre-rulebase>
    </entry></vsys></entry></devices></config>"""


def test_each_requested_policy_family_has_structured_terminal_extraction():
    items = [item for item in _result().inventory_items if item.domain.startswith("policy:")]
    structured = [item for item in items if item.domain.removeprefix("policy:") in FAMILIES]
    assert {item.domain.removeprefix("policy:") for item in structured} == FAMILIES
    assert all(item.status == ExtractionStatus.EXTRACT_ONLY for item in structured)
    assert all(item.source_attributes["pan_source_rule_id"] for item in structured)


def test_pre_local_post_positions_and_duplicate_names_preserve_identity():
    items = [item for item in _result().inventory_items if item.name == "duplicate-name"]
    assert {item.source_attributes["pan_rulebase_position"] for item in items} == {"pre", "post"}
    assert len({item.source_attributes["pan_source_rule_id"] for item in items}) == 2


def test_common_and_family_specific_fields_are_preserved():
    decrypt = next(item for item in _result().inventory_items if item.name == "decrypt-web")
    assert decrypt.source_attributes["pan_from"] == ["trust"]
    assert decrypt.source_attributes["pan_action"] == "decrypt"
    assert "profile" in decrypt.source_attributes["pan_family_specific"]
    assert "future-decrypt" in decrypt.source_attributes["pan_unknown_fields"]


def test_pbf_zone_selector_uses_pan_os_from_zone_hierarchy():
    pbf = _pbf(_result(), "pbf-zone-forward")
    attributes = pbf.source_attributes

    assert attributes["pan_from_zones"] == ["trust"]
    assert attributes["pan_from_interfaces"] == []
    assert attributes["pan_from"] == []
    assert attributes["pan_pbf_egress_interface"] == "ethernet1/3"
    assert attributes["pan_pbf_from_source"] == {
        "from": {"zone": {"member": {"text": "trust"}}}
    }


def test_pbf_interface_selectors_are_separate_and_preserve_order():
    pbf = _pbf(_result(), "pbf-interface-forward")
    attributes = pbf.source_attributes

    assert attributes["pan_from_interfaces"] == ["ethernet1/1", "ethernet1/2"]
    assert attributes["pan_from_zones"] == []
    assert attributes["pan_from"] == []
    assert attributes["pan_pbf_from_source"] == {
        "from": {
            "interface": {
                "member": [{"text": "ethernet1/1"}, {"text": "ethernet1/2"}]
            }
        }
    }


def test_pbf_forward_action_uses_nested_pan_os_hierarchy():
    pbf = _pbf(_result(), "pbf-zone-forward")
    attributes = pbf.source_attributes

    assert pbf.status == ExtractionStatus.EXTRACT_ONLY
    assert pbf.requires_manual_review is False
    assert attributes["pan_pbf_review_reasons"] == []
    assert attributes["pan_pbf_action"] == "forward"
    assert attributes["pan_pbf_action_source"] == {
        "action": {
            "forward": {
                "egress-interface": {"text": "ethernet1/3"},
            }
        }
    }
    assert "forward" not in attributes["pan_unknown_fields"]
    assert attributes["pan_pbf_action_source"]
    assert attributes["pan_pbf_forward_source"]
    assert attributes["pan_source_entry"]


def test_pbf_forward_fields_are_extracted_from_nested_forward_node():
    pbf = _pbf(_result(), "pbf-next-hop")
    attributes = pbf.source_attributes

    assert attributes["pan_pbf_egress_interface"] == "ethernet1/3"
    assert attributes["pan_pbf_next_hop_type"] == "ip-address"
    assert attributes["pan_pbf_next_hop"] == "192.0.2.1"
    assert attributes["pan_pbf_nexthop_source"] == {
        "nexthop": {"ip-address": {"text": "192.0.2.1"}}
    }
    assert attributes["pan_pbf_forward_source"]
    assert "egress-interface" not in attributes["pan_unknown_fields"]


def test_pbf_forward_monitor_symmetric_return_and_ha_binding_are_preserved():
    monitor = _pbf(_result(), "pbf-monitor").source_attributes
    assert monitor["pan_pbf_monitor_enabled"] is True
    assert monitor["pan_pbf_monitor_profile"] == "default"
    assert monitor["pan_pbf_monitor_ip"] == "198.51.100.1"
    assert monitor["pan_pbf_monitor_disable_if_unreachable"] == "yes"
    assert monitor["pan_pbf_monitor_source"]

    symmetric = _pbf(_result(), "pbf-symmetric-return").source_attributes
    assert symmetric["pan_pbf_enforce_symmetric_return"] is True
    assert symmetric["pan_pbf_symmetric_return_source"]

    binding = _pbf(_result(), "pbf-active-active-binding").source_attributes
    assert binding["pan_pbf_active_active_device_binding"] == "both"
    assert "active-active-device-binding" not in binding["pan_unknown_fields"]


def test_pbf_nested_action_fields_are_not_reported_as_flat_unknowns():
    for name in ("pbf-zone-forward", "pbf-next-hop", "pbf-monitor"):
        attributes = _pbf(_result(), name).source_attributes
        assert "action" not in attributes["pan_unknown_fields"]
        assert "egress-interface" not in attributes["pan_unknown_fields"]


def test_pbf_discard_is_source_extractable_without_forwarding_values():
    pbf = _pbf(_result(), "pbf-local-discard")
    attributes = pbf.source_attributes

    assert pbf.status == ExtractionStatus.EXTRACT_ONLY
    assert pbf.requires_manual_review is False
    assert attributes["pan_rulebase_position"] == "local"
    assert attributes["pan_pbf_action"] == "discard"
    assert attributes["pan_pbf_action_source"] == {"action": {"discard": True}}
    assert "pan_pbf_egress_interface" not in attributes
    assert "pan_pbf_next_hop" not in attributes
    assert "pan_pbf_next_vr" not in attributes


def test_pbf_no_pbf_is_explicit_and_does_not_create_routes():
    result = _result()
    pbf = _pbf(result, "pbf-post-no-pbf")

    assert pbf.status == ExtractionStatus.EXTRACT_ONLY
    assert pbf.requires_manual_review is False
    assert pbf.source_attributes["pan_rulebase_position"] == "post"
    assert pbf.source_attributes["pan_pbf_action"] == "no-pbf"
    assert pbf.source_attributes["pan_pbf_action_source"] == {"action": {"no-pbf": True}}
    assert "pan_pbf_egress_interface" not in pbf.source_attributes
    assert "pan_pbf_next_hop" not in pbf.source_attributes
    assert not result.canonical_ir.routes
    assert not result.canonical_ir.policies


def test_pbf_unknown_nested_forward_child_is_preserved_for_review():
    pbf = _pbf(_result(), "pbf-unknown-field")
    attributes = pbf.source_attributes

    assert attributes["pan_pbf_action"] == "forward"
    assert attributes["pan_unknown_pbf_forward_fields"] == {"future-forward-option": "keep"}
    assert attributes["pan_pbf_forward_source"]
    assert attributes["pan_pbf_forward_source"]["forward"]["future-forward-option"] == {
        "text": "keep"
    }
    assert pbf.requires_manual_review is True
    assert attributes["pan_pbf_review_reasons"] == ["unknown-forward-fields"]


def test_pbf_unknown_nested_nexthop_child_is_preserved_without_dropping_rule():
    entry = """<entry name='pbf-unknown-nexthop'><from><zone><member>trust</member></zone></from>
      <action><forward><egress-interface>ethernet1/3</egress-interface>
        <nexthop><ip-address>192.0.2.1</ip-address><future-nexthop-option>keep</future-nexthop-option>
        </nexthop></forward></action></entry>"""
    pbf = _pbf(_result(_pbf_xml(entry)), "pbf-unknown-nexthop")
    attributes = pbf.source_attributes

    assert attributes["pan_pbf_action"] == "forward"
    assert attributes["pan_pbf_next_hop_type"] == "ip-address"
    assert attributes["pan_pbf_next_hop"] == "192.0.2.1"
    assert attributes["pan_unknown_pbf_nexthop_fields"] == {"future-nexthop-option": "keep"}
    assert attributes["pan_pbf_nexthop_source"]["nexthop"]["future-nexthop-option"] == {
        "text": "keep"
    }
    assert pbf.status == ExtractionStatus.EXTRACT_ONLY


def test_pbf_unknown_action_child_is_preserved_without_dropping_rule():
    entry = """<entry name='pbf-unknown-action'><from><zone><member>trust</member></zone></from>
      <action><future-action-option>keep</future-action-option><forward>
        <egress-interface>ethernet1/3</egress-interface></forward></action></entry>"""
    pbf = _pbf(_result(_pbf_xml(entry)), "pbf-unknown-action")
    attributes = pbf.source_attributes

    assert attributes["pan_pbf_action"] == "forward"
    assert attributes["pan_unknown_pbf_action_fields"] == {"future-action-option": "keep"}
    assert attributes["pan_pbf_action_source"]
    assert pbf.status == ExtractionStatus.EXTRACT_ONLY
    assert pbf.source_attributes["pan_pbf_review_reasons"] == ["unknown-action-fields"]


def test_pbf_unknown_action_type_is_unsupported_not_parse_error():
    entry = """<entry name='pbf-unsupported-action'><from><zone><member>trust</member></zone></from>
      <action><future-action-type><target>blue</target></future-action-type></action></entry>"""
    pbf = _pbf(_result(_pbf_xml(entry)), "pbf-unsupported-action")

    assert pbf.status == ExtractionStatus.UNSUPPORTED
    assert pbf.requires_manual_review is True
    assert pbf.source_attributes["pan_pbf_action"] is None
    assert pbf.source_attributes["pan_unknown_pbf_action_fields"] == {
        "future-action-type": "[Complex subtree]"
    }
    assert pbf.source_attributes["pan_pbf_action_source"]
    assert pbf.source_attributes["pan_pbf_review_reasons"] == ["unsupported-action"]


def test_pbf_unsupported_nexthop_type_is_distinct_from_invalid_known_value():
    entry = """<entry name='pbf-unsupported-nexthop'><from><zone><member>trust</member></zone></from>
      <action><forward><egress-interface>ethernet1/3</egress-interface>
        <nexthop><future-nexthop-type>203.0.113.1</future-nexthop-type></nexthop>
      </forward></action></entry>"""
    pbf = _pbf(_result(_pbf_xml(entry)), "pbf-unsupported-nexthop")

    assert pbf.status == ExtractionStatus.UNSUPPORTED
    assert pbf.requires_manual_review is True
    assert pbf.source_attributes["pan_pbf_nexthop_source"]
    assert pbf.source_attributes["pan_unknown_pbf_nexthop_fields"] == {
        "future-nexthop-type": "203.0.113.1"
    }
    assert pbf.source_attributes["pan_pbf_review_reasons"] == ["unsupported-nexthop"]


def test_pbf_invalid_known_ip_nexthop_is_parse_error_and_preserves_source():
    entry = """<entry name='pbf-invalid-nexthop'><from><zone><member>trust</member></zone></from>
      <action><forward><nexthop><ip-address>not-an-ip</ip-address></nexthop></forward></action></entry>"""
    pbf = _pbf(_result(_pbf_xml(entry)), "pbf-invalid-nexthop")

    assert pbf.status == ExtractionStatus.PARSE_ERROR
    assert pbf.source_attributes["pan_pbf_next_hop"] == "not-an-ip"
    assert pbf.source_attributes["pan_pbf_nexthop_source"]
    assert pbf.source_attributes["pan_pbf_review_reasons"] == ["invalid-next-hop"]


def test_pbf_unknown_monitor_field_requires_review_without_parse_error():
    entry = """<entry name='pbf-unknown-monitor'><from><zone><member>trust</member></zone></from>
      <action><forward><egress-interface>ethernet1/3</egress-interface>
        <monitor><profile>default</profile><future-monitor-option>keep</future-monitor-option></monitor>
      </forward></action></entry>"""
    pbf = _pbf(_result(_pbf_xml(entry)), "pbf-unknown-monitor")

    assert pbf.status == ExtractionStatus.EXTRACT_ONLY
    assert pbf.requires_manual_review is True
    assert pbf.source_attributes["pan_unknown_pbf_monitor_fields"] == {
        "future-monitor-option": "keep"
    }
    assert pbf.source_attributes["pan_pbf_review_reasons"] == ["unknown-monitor-fields"]


def test_pbf_unknown_active_active_binding_is_preserved_as_unsupported():
    entry = """<entry name='pbf-unknown-binding'><action><discard /></action>
      <active-active-device-binding>future-binding</active-active-device-binding></entry>"""
    pbf = _pbf(_result(_pbf_xml(entry)), "pbf-unknown-binding")

    assert pbf.status == ExtractionStatus.UNSUPPORTED
    assert pbf.source_attributes["pan_pbf_active_active_device_binding"] == "future-binding"
    assert pbf.source_attributes["pan_pbf_review_reasons"] == [
        "unsupported-active-active-device-binding"
    ]


def test_pbf_review_reason_order_is_deterministic_and_one_record_is_emitted():
    entry = """<entry name='pbf-multiple-review-reasons'><from><zone><member>trust</member></zone>
        <future-from-option>keep</future-from-option></from>
      <action><future-action-option>keep</future-action-option><forward>
        <egress-interface>ethernet1/3</egress-interface><future-forward-option>keep</future-forward-option>
      </forward></action><future-rule-option>keep</future-rule-option></entry>"""
    result = _result(_pbf_xml(entry))
    pbf = _pbf(result, "pbf-multiple-review-reasons")

    assert pbf.status == ExtractionStatus.EXTRACT_ONLY
    assert pbf.source_attributes["pan_pbf_review_reasons"] == [
        "unknown-rule-fields",
        "unknown-from-fields",
        "unknown-action-fields",
        "unknown-forward-fields",
    ]
    assert len([
        item for item in result.inventory_items
        if item.domain == "policy:pbf" and item.name == "pbf-multiple-review-reasons"
    ]) == 1


def test_pbf_mixed_statuses_are_reflected_in_section_accounting():
    entries = """
      <entry name='pbf-valid'><action><discard /></action></entry>
      <entry name='pbf-unsupported'><action><future-action-type /></action></entry>
      <entry name='pbf-parse-error'><action><forward><nexthop><ip-address>bad</ip-address></nexthop></forward></action></entry>
    """
    result = _result(_pbf_xml(entries))
    section = next(
        section for section in result.source_sections
        if section.path == "pre-rulebase/pbf/rules"
    )

    assert section.status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert section.object_count_source == 3
    assert section.object_count_parsed == 2
    assert section.object_count_normalized == 0
    assert len([item for item in result.inventory_items if item.domain == "policy:pbf"]) == 3


def test_pbf_missing_action_is_preserved_as_parse_error_without_inventing_action():
    entry = """<entry name='pbf-missing-action'><from><zone><member>trust</member></zone></from></entry>"""
    pbf = _pbf(_result(_pbf_xml(entry)), "pbf-missing-action")

    assert pbf.status == ExtractionStatus.PARSE_ERROR
    assert pbf.source_attributes["pan_pbf_action"] is None
    assert "pan_pbf_action_source" not in pbf.source_attributes
    assert "missing its action subtree" in pbf.notes[0]
    assert pbf.source_attributes["pan_pbf_review_reasons"] == ["missing-action"]
    assert pbf.source_attributes["pan_source_entry"]


def test_pbf_conflicting_actions_are_not_classified_by_first_child():
    entry = """<entry name='pbf-conflicting-action'><from><zone><member>trust</member></zone></from>
      <action><forward><egress-interface>ethernet1/3</egress-interface></forward><discard /></action></entry>"""
    pbf = _pbf(_result(_pbf_xml(entry)), "pbf-conflicting-action")

    assert pbf.status == ExtractionStatus.PARSE_ERROR
    assert pbf.source_attributes["pan_pbf_action"] is None
    assert "conflicting action types" in pbf.notes[0]
    assert pbf.source_attributes["pan_pbf_action_source"]


def test_pbf_malformed_symmetric_return_value_is_preserved_and_reviewed():
    entry = """<entry name='pbf-malformed-symmetric'><from><zone><member>trust</member></zone></from>
      <action><discard /></action><enforce-symmetric-return><enabled>maybe</enabled></enforce-symmetric-return></entry>"""
    pbf = _pbf(_result(_pbf_xml(entry)), "pbf-malformed-symmetric")

    assert pbf.status == ExtractionStatus.PARSE_ERROR
    assert "pan_pbf_enforce_symmetric_return" not in pbf.source_attributes
    assert pbf.source_attributes["pan_pbf_enforce_symmetric_return_source"] == "maybe"
    assert "Malformed PAN-OS yes/no value" in pbf.notes[-1]
    assert pbf.requires_manual_review is True
    assert "invalid-enforce-symmetric-return" in pbf.source_attributes["pan_pbf_review_reasons"]


def test_pbf_rulebase_provenance_and_section_accounting_cover_pre_local_post():
    result = _result()
    for name, position in (
        ("pbf-zone-forward", "pre"),
        ("pbf-local-discard", "local"),
        ("pbf-post-no-pbf", "post"),
    ):
        item = _pbf(result, name)
        attributes = item.source_attributes
        assert attributes["pan_policy_family"] == "pbf"
        assert attributes["pan_rulebase_position"] == position
        assert attributes["pan_source_rule_id"]
        assert attributes["pan_source_rule_index"] >= 0
        assert attributes["pan_scope_kind"] == "vsys"
        assert attributes["pan_scope_name"] == "vsys1"
        assert attributes["pan_source_entry"]

    expected = {
        "pre-rulebase/pbf/rules": 7,
        "rulebase/pbf/rules": 1,
        "post-rulebase/pbf/rules": 1,
    }
    for path, count in expected.items():
        sections = [section for section in result.source_sections if section.path == path]
        assert len(sections) == 1
        section = sections[0]
        assert section.status == ExtractionStatus.EXTRACT_ONLY
        assert section.object_count_source == count
        assert section.object_count_parsed == count
        assert section.object_count_normalized == 0


def test_unknown_future_policy_family_remains_unsupported_per_rule():
    item = next(item for item in _result().inventory_items if item.domain == "policy:future-policy")
    assert item.name == "future-rule"
    assert item.status == ExtractionStatus.UNSUPPORTED
    assert "future-action" in str(item.source_attributes["pan_source_entry"])


def test_unknown_field_in_new_family_is_not_lost():
    broker = next(item for item in _result().inventory_items if item.domain == "policy:network-packet-broker")
    assert "future-broker" in broker.source_attributes["pan_unknown_fields"]
