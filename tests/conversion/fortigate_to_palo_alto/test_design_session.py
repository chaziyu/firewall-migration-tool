from types import SimpleNamespace

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto.automation import run_automation_until_stable
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import (
    PANDecisionMode,
    PANDecisionReviewState,
    PANMigrationDecision,
    PANMigrationDecisionSet,
    make_decision_key,
)
from fwmigrate.conversion.fortigate_to_palo_alto.design import (
    PANDecisionDependency,
    PANDecisionGraph,
    resolve_design_session_until_stable,
)
from fwmigrate.conversion.fortigate_to_palo_alto.design.graph import build_decision_graph


def _decision(kind, name, field, *, mode=PANDecisionMode.REQUIRED, value=None, state=PANDecisionReviewState.PENDING):
    return PANMigrationDecision(
        source_vdom="root",
        source_kind=kind,
        source_name=name,
        target_field=field,
        value=value,
        mode=mode,
        review_state=state,
    )


def test_graph_orders_vdom_interface_and_zone_decisions_and_finds_ready_wave():
    config = SimpleNamespace(
        interfaces=[SimpleNamespace(vdom="root", name="port1", interface=None)],
        zones=[SimpleNamespace(vdom="root", name="inside", members=["port1"])],
    )
    decisions = PANMigrationDecisionSet((
        _decision("vdom", "root", "vsys"),
        _decision("vdom", "root", "virtual_router"),
        _decision("interface", "port1", "target_interface"),
        _decision("interface", "port1", "target_zone"),
        _decision("zone", "inside", "target_zone"),
    ))
    requirements = {"vdoms": [{"source_vdom": "root", "requires": ["vsys", "virtual_router"]}]}

    graph = build_decision_graph(config, SimpleNamespace(), decisions, requirements)
    order = graph.topological_order()
    assert order.index(make_decision_key("root", "vdom", "root", "vsys")) < order.index(
        make_decision_key("root", "interface", "port1", "target_interface")
    )
    assert set(graph.ready_decision_keys(decisions)) == {
        make_decision_key("root", "vdom", "root", "vsys"),
        make_decision_key("root", "vdom", "root", "virtual_router"),
    }


def test_graph_rejects_cycles_and_unknown_dependencies():
    with pytest.raises(ValueError, match="cycle"):
        PANDecisionGraph((
            PANDecisionDependency("a", ("b",)),
            PANDecisionDependency("b", ("a",)),
        ))
    with pytest.raises(ValueError, match="existing decisions"):
        PANDecisionGraph((PANDecisionDependency("a", ("missing",)),))


def test_design_resolver_preserves_legacy_options_and_source():
    config = SimpleNamespace(interfaces=[], zones=[])
    derived = SimpleNamespace()
    decisions = PANMigrationDecisionSet((
        _decision("vdom", "root", "vsys", mode=PANDecisionMode.REQUIRED,
                  value="vsys1", state=PANDecisionReviewState.CONFIRMED),
        _decision("zone", "inside", "target_zone", mode=PANDecisionMode.UNSUPPORTED),
    ))
    original = decisions.to_dict()
    previous = run_automation_until_stable(config, derived, decisions)

    session = resolve_design_session_until_stable(
        config,
        derived,
        decisions,
        requirements={"vdoms": [], "interfaces": []},
    )

    assert session.decisions.to_options() == previous.decisions.to_options()
    assert session.decisions.to_dict() == original
    assert session.resolved == (decisions.decisions[0].key,)
    assert session.unsupported == (decisions.decisions[1].key,)
    assert session.stable
