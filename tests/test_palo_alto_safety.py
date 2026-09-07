import pytest

from fwmigrate.core.optimizer import RuleOptimizer
from fwmigrate.generators.palo_alto.transformer import IRToPANOSTransformer
from fwmigrate.ir.core import IRConfig
from fwmigrate.ir.enums import PolicyAction
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


# Phase 2: permanent fail-closed regression contract.
# Missing, empty, malformed, or unresolved source semantics must never be
# converted into permissive canonical defaults.


def _policy_xml(*, fields=None, action="allow"):
    values = {
        "from": "<from><member>trust</member></from>",
        "to": "<to><member>untrust</member></to>",
        "source": "<source><member>10.0.0.1</member></source>",
        "destination": "<destination><member>8.8.8.8</member></destination>",
        "application": "<application><member>any</member></application>",
        "service": "<service><member>application-default</member></service>",
    }
    if fields:
        values.update(fields)
    action_xml = f"<action>{action}</action>" if action is not None else ""
    return f"""<?xml version="1.0"?>
    <config version="11.2.0">
      <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
        <rulebase><security><rules>
          <entry name="Rule1">
            {values['from']}{values['to']}{values['source']}
            {values['destination']}{values['application']}{values['service']}
            {action_xml}
          </entry>
        </rules></security></rulebase>
      </entry></vsys></entry></devices>
    </config>
    """


def _nat_xml(*, fields=None, source_translation=None, destination_translation=""):
    values = {
        "from": "<from><member>trust</member></from>",
        "to": "<to><member>untrust</member></to>",
        "source": "<source><member>any</member></source>",
        "destination": "<destination><member>any</member></destination>",
        "service": "<service>any</service>",
    }
    if fields:
        values.update(fields)
    if source_translation is None:
        source_translation = """
        <source-translation>
          <dynamic-ip-and-port>
            <translated-address><member>203.0.113.10</member></translated-address>
          </dynamic-ip-and-port>
        </source-translation>
        """
    return f"""<?xml version="1.0"?>
    <config version="11.2.0">
      <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
        <rulebase><nat><rules>
          <entry name="Nat1">
            {values['from']}{values['to']}{values['source']}
            {values['destination']}{values['service']}
            {source_translation}{destination_translation}
          </entry>
        </rules></nat></rulebase>
      </entry></vsys></entry></devices>
    </config>
    """


def _route_xml(*, destination="10.0.0.0/24", metric=None, admin_distance=None,
               nexthop="<nexthop><ip-address>192.0.2.1</ip-address></nexthop>"):
    destination_xml = f"<destination>{destination}</destination>" if destination is not None else ""
    metric_xml = f"<metric>{metric}</metric>" if metric is not None else ""
    admin_xml = f"<admin-dist>{admin_distance}</admin-dist>" if admin_distance is not None else ""
    return f"""<?xml version="1.0"?>
    <config version="11.2.0">
      <devices><entry name="localhost.localdomain">
        <network><virtual-router><entry name="default">
          <routing-table><ip><static-route>
            <entry name="route1">
              {destination_xml}{nexthop}{metric_xml}{admin_xml}
            </entry>
          </static-route></ip></routing-table>
        </entry></virtual-router></network>
        <vsys><entry name="vsys1"/></vsys>
      </entry></devices>
    </config>
    """


def _extract(xml):
    return PANOSSourceParser().extract(xml)


@pytest.mark.parametrize("field", ["from", "to", "source", "destination", "application", "service"])
@pytest.mark.parametrize("representation", ["missing", "empty", "blank-member"])
def test_missing_or_empty_policy_dimensions_never_broaden_to_any(field, representation):
    replacement = {
        "missing": "",
        "empty": f"<{field}/>",
        "blank-member": f"<{field}><member>   </member></{field}>",
    }[representation]
    extraction = _extract(_policy_xml(fields={field: replacement}))

    assert extraction.canonical_ir.policies == []
    items = [item for item in extraction.inventory_items if item.domain == "policies"]
    assert items
    assert any("missing required fields" in " ".join(item.notes).lower() for item in items)


def test_missing_action_does_not_broaden_to_allow():
    extraction = _extract(_policy_xml(action=None))

    assert extraction.canonical_ir.policies == []
    items = [item for item in extraction.inventory_items if item.domain == "policies"]
    assert items
    assert any("missing required action" in " ".join(item.notes).lower() for item in items)


def test_explicit_any_is_preserved_as_explicit_source_semantics():
    extraction = _extract(_policy_xml(fields={
        "source": "<source><member>any</member></source>",
        "destination": "<destination><member>any</member></destination>",
    }))

    assert len(extraction.canonical_ir.policies) == 1
    policy = extraction.canonical_ir.policies[0]
    assert policy.source == ["any"]
    assert policy.destination == ["any"]
    assert policy.source_address_references == ["any"]
    assert policy.destination_address_references == ["any"]


def test_unresolved_policy_reference_is_preserved_but_not_generation_safe():
    extraction = _extract(_policy_xml(fields={
        "source": "<source><member>Missing-Address</member></source>",
    }))

    assert len(extraction.canonical_ir.policies) == 1
    policy = extraction.canonical_ir.policies[0]
    assert policy.source == ["Missing-Address"]
    assert policy.source_extra_settings["pan_unresolved_sources"] == ["Missing-Address"]
    assert policy.requires_manual_review is True
    assert policy.migration_status == "PARTIALLY_NORMALIZED"
    assert policy.safe_for_target_generation is False


@pytest.mark.parametrize(
    ("source_action", "expected"),
    [
        ("drop", PolicyAction.DROP),
        ("reset-client", PolicyAction.RESET_CLIENT),
        ("reset-server", PolicyAction.RESET_SERVER),
        ("reset-both", PolicyAction.RESET_BOTH),
    ],
)
def test_pan_action_variants_are_exact_and_generation_safe_at_source_layer(source_action, expected):
    extraction = _extract(_policy_xml(action=source_action))

    assert len(extraction.canonical_ir.policies) == 1
    policy = extraction.canonical_ir.policies[0]
    assert policy.action == expected
    assert policy.source_action == source_action
    assert "source-action-variant" not in policy.review_reasons
    assert policy.requires_manual_review is False
    assert policy.safe_for_target_generation is True

    pan = IRToPANOSTransformer(extraction.canonical_ir).transform()
    assert pan.vsys.security_rules[0].action == source_action


def test_optimizer_never_repairs_or_broadens_unsafe_policy():
    extraction = _extract(_policy_xml(action="reset-client"))
    policy = extraction.canonical_ir.policies[0]
    # Shape the rule so the optimizer's outbound-threat heuristic would broaden
    # its source to any if the fail-closed guard were ever removed.
    policy.destination = ["bad-one", "bad-two", "bad-three", "bad-four", "bad-five"]
    original_source = list(policy.source)
    original_review = list(policy.review_reasons)

    RuleOptimizer(extraction.canonical_ir).fix_outbound_threat_source_anomalies()

    assert policy.source == original_source
    assert policy.review_reasons == original_review
    # Reset-client is exact canonical semantics and is not the optimizer's
    # generic DENY action, so it remains unchanged without parser taint.
    assert policy.safe_for_target_generation is True


def test_phase2_safety_state_survives_ir_json_round_trip():
    extraction = _extract(_policy_xml(action="reset-client"))
    original = extraction.canonical_ir.policies[0]
    assert original.safe_for_target_generation is True

    restored = IRConfig.model_validate_json(extraction.canonical_ir.model_dump_json())
    policy = restored.policies[0]
    assert policy.source_action == "reset-client"
    assert policy.action == PolicyAction.RESET_CLIENT
    assert policy.migration_status == "NORMALIZED"
    assert policy.requires_manual_review is False
    assert "source-action-variant" not in policy.review_reasons
    assert policy.safe_for_target_generation is True


@pytest.mark.parametrize("field", ["from", "to", "source", "destination", "service"])
def test_missing_nat_match_dimension_never_becomes_any(field):
    extraction = _extract(_nat_xml(fields={field: ""}))

    assert extraction.canonical_ir.nat_rules == []
    items = [item for item in extraction.inventory_items if item.domain == "nat"]
    assert items
    assert any("missing required nat match fields" in " ".join(item.notes).lower() for item in items)


def test_invalid_nat_translation_is_preserved_and_withheld():
    source_translation = """
    <source-translation>
      <dynamic-ip-and-port>
        <translated-address><member>203.0.113.20-203.0.113.10</member></translated-address>
      </dynamic-ip-and-port>
    </source-translation>
    """
    extraction = _extract(_nat_xml(source_translation=source_translation))

    assert len(extraction.canonical_ir.nat_rules) == 1
    rule = extraction.canonical_ir.nat_rules[0]
    assert "invalid-translated-source" in rule.review_reasons
    assert rule.requires_manual_review is True
    assert rule.safe_for_target_generation is False

    pan = IRToPANOSTransformer(extraction.canonical_ir).transform()
    assert pan.vsys.nat_rules == []
    assert any(
        entry.category == "PAN-OS NAT" and "withheld" in entry.message.lower()
        for entry in extraction.canonical_ir.audit_entries
    )


def test_ambiguous_destination_translation_is_withheld():
    destination_translation = """
    <destination-translation>
      <translated-address>10.0.0.10</translated-address>
    </destination-translation>
    <dynamic-destination-translation>
      <translated-address><member>10.0.0.20</member></translated-address>
    </dynamic-destination-translation>
    """
    extraction = _extract(_nat_xml(destination_translation=destination_translation))

    assert len(extraction.canonical_ir.nat_rules) == 1
    rule = extraction.canonical_ir.nat_rules[0]
    assert "ambiguous-destination-translation" in rule.review_reasons
    assert rule.safe_for_target_generation is False


def test_missing_route_destination_does_not_become_default_route():
    extraction = _extract(_route_xml(destination=None))

    assert extraction.canonical_ir.routes == []
    items = [item for item in extraction.inventory_items if item.domain == "routes"]
    assert items
    assert any("missing required destination" in " ".join(item.notes).lower() for item in items)


def test_explicit_default_route_is_preserved():
    extraction = _extract(_route_xml(destination="0.0.0.0/0", metric=10, admin_distance=10))

    assert len(extraction.canonical_ir.routes) == 1
    route = extraction.canonical_ir.routes[0]
    assert route.destination == "0.0.0.0/0"
    assert route.source_destination == "0.0.0.0/0"
    assert route.metric == 10
    assert route.administrative_distance == 10


@pytest.mark.parametrize("metric", [0, -1, 65536])
def test_static_route_metric_out_of_range_is_parse_error(metric):
    extraction = _extract(_route_xml(metric=metric, admin_distance=10))

    assert extraction.canonical_ir.routes == []
    items = [item for item in extraction.inventory_items if item.domain == "routes"]
    assert items
    assert any("between 1 and 65535" in " ".join(item.notes) for item in items)


@pytest.mark.parametrize("admin_distance", [0, 9, 241, 999])
def test_static_route_admin_distance_out_of_range_is_parse_error(admin_distance):
    extraction = _extract(_route_xml(metric=1, admin_distance=admin_distance))

    assert extraction.canonical_ir.routes == []
    items = [item for item in extraction.inventory_items if item.domain == "routes"]
    assert items
    assert any("between 10 and 240" in " ".join(item.notes) for item in items)


@pytest.mark.parametrize(
    "metric,admin_distance",
    [(1, 10), (65535, 240)],
)
def test_static_route_numeric_boundaries_are_accepted(metric, admin_distance):
    extraction = _extract(_route_xml(metric=metric, admin_distance=admin_distance))

    assert len(extraction.canonical_ir.routes) == 1
    route = extraction.canonical_ir.routes[0]
    assert route.metric == metric
    assert route.administrative_distance == admin_distance
