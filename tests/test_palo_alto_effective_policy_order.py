from pathlib import Path

from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


FIXTURE = Path(__file__).parent / "fixtures" / "palo_alto" / "panorama_effective_policy.xml"


def _result():
    return PANOSSourceParser().extract(FIXTURE.read_text(encoding="utf-8"))


def _security(result):
    return [item for item in result.inventory_items if item.domain in {"policies", "default_security_rules"}]


def test_shared_parent_child_local_post_and_default_effective_order():
    context = "vsys:vsys1"
    ordered = []
    for item in _security(_result()):
        position = item.source_attributes.get("pan_effective_order_by_context", {}).get(context)
        if position:
            ordered.append((position["effective_policy_rank"], item.name, position["effective_policy_layer"]))
    ordered.sort()
    assert [(name, layer) for _, name, layer in ordered[:9]] == [
        ("shared-pre", "shared-pre-rules"),
        ("grand-pre", "ancestor-device-group-pre-rules"),
        ("duplicate", "ancestor-device-group-pre-rules"),
        ("child-pre", "current-device-group-pre-rules"),
        ("local", "local-firewall-rules"),
        ("child-post", "current-device-group-post-rules"),
        ("parent-post", "ancestor-device-group-post-rules"),
        ("grand-post", "ancestor-device-group-post-rules"),
        ("duplicate", "shared-post-rules"),
    ]
    assert all(position == index for index, (position, _, _) in enumerate(ordered))


def test_original_source_index_id_scope_and_position_are_not_overwritten():
    result = _result()
    parent_pre = next(item for item in _security(result)
                      if item.name == "duplicate" and item.source_attributes["scope_name"] == "parent")
    assert parent_pre.source_attributes["pan_source_rule_index"] == 0
    assert parent_pre.source_attributes["pan_rulebase_position"] == "pre"
    assert ":parent:pre:0:duplicate" in parent_pre.source_attributes["pan_source_rule_id"]
    assert parent_pre.source_attributes["effective_policy_rank"] != parent_pre.source_attributes["pan_source_rule_index"]


def test_multiple_parent_levels_scope_chain_and_completion_are_explicit():
    child = next(item for item in _security(_result()) if item.name == "child-pre")
    position = child.source_attributes["pan_effective_order_by_context"]["device-group:child"]
    assert position["effective_scope_chain"] == ["shared", "grand", "parent", "child"]
    assert position["effective_order_complete"] is True


def test_default_override_uses_lowest_context_without_duplicate_terminal_records():
    result = _result()
    defaults = [item for item in _security(result) if item.domain == "default_security_rules"]
    assert len(defaults) == 3
    vsys_order = [item for item in defaults
                  if "vsys:vsys1" in item.source_attributes.get("pan_effective_order_by_context", {})]
    assert {item.source_attributes["scope_kind"] for item in vsys_order} == {"shared", "vsys"}


def test_missing_and_cycle_hierarchy_mark_order_incomplete_without_recursing():
    xml = """<config><shared><pre-rulebase><security><rules><entry name='s'><from><member>any</member></from><to><member>any</member></to><source><member>any</member></source><destination><member>any</member></destination><application><member>any</member></application><service><member>any</member></service><action>deny</action></entry></rules></security></pre-rulebase></shared><devices><entry name='p'><device-group><entry name='a'><parent-dg>b</parent-dg><pre-rulebase><security><rules><entry name='a-rule'><from><member>any</member></from><to><member>any</member></to><source><member>any</member></source><destination><member>any</member></destination><application><member>any</member></application><service><member>any</member></service><action>deny</action></entry></rules></security></pre-rulebase></entry><entry name='b'><parent-dg>a</parent-dg></entry><entry name='missing'><parent-dg>absent</parent-dg></entry></device-group></entry></devices></config>"""
    result = PANOSSourceParser().extract(xml)
    item = next(item for item in result.inventory_items if item.name == "a-rule")
    assert item.source_attributes["pan_effective_order_by_context"]["device-group:a"]["effective_order_complete"] is False
