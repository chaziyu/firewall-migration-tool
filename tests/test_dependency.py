from copy import deepcopy

from fwmigrate.ir.core import (
    IRAddressGroup, IRConfig, IRMetadata, IRPolicy, IRSchedule, IRServiceGroup
)
from fwmigrate.ir.enums import PolicyAction
from fwmigrate.ir.dependency import DependencyGraph

def test_schedule_before_policy():
    ir = IRConfig(
        metadata=IRMetadata(hostname="dep-test", source_vendor="fortigate"),
        schedules=[
            IRSchedule(name="weekend_sched")
        ],
        policies=[
            IRPolicy(
                name="Allow_Weekend",
                from_zone=["any"],
                to_zone=["any"],
                source=["any"],
                destination=["any"],
                service=["any"],
                action=PolicyAction.ALLOW,
                schedule="weekend_sched"
            )
        ]
    )

    dep_graph = DependencyGraph(ir)
    ordered = dep_graph.get_ordered_components()

    assert "schedules" in ordered
    assert "policies" in ordered
    
    keys = list(ordered.keys())
    schedule_idx = keys.index("schedules")
    policy_idx = keys.index("policies")
    
    assert schedule_idx < policy_idx, "Schedules must be emitted before policies in the topological sort."
    assert ordered["policies"][0].schedule == "weekend_sched"


def test_group_cycles_are_reported_without_mutating_ir_or_duplicating_issues():
    ir = IRConfig(
        metadata=IRMetadata(hostname="cycle-test"),
        address_groups=[
            IRAddressGroup(name="a", members=["b"]),
            IRAddressGroup(name="b", members=["a"]),
        ],
        service_groups=[
            IRServiceGroup(name="s1", members=["s2"]),
            IRServiceGroup(name="s2", members=["s1"]),
        ],
    )
    before = deepcopy(ir.model_dump())
    graph = DependencyGraph(ir)

    graph.get_ordered_components()
    first_issue_count = len(graph.issues)
    graph.get_ordered_components()

    assert ir.model_dump() == before
    assert not ir.audit_entries
    assert first_issue_count == 4
    assert len(graph.issues) == first_issue_count
    assert {issue.reason for issue in graph.issues} == {"circular dependency"}
