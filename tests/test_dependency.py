from fwmigrate.ir.core import (
    IRConfig, IRMetadata, IRPolicy, IRSchedule
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
