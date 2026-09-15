from fwmigrate.ir import (
    IRAddress,
    IRAddressGroup,
    IRConfig,
    IRMetadata,
    IRPolicy,
    IRService,
    IRServiceGroup,
)
from fwmigrate.ir.enums import AddressType, PolicyAction
from fwmigrate.ir.dependency import DependencyGraph


def test_dependency_graph_reaches_nested_groups_and_reports_missing_references():
    ir = IRConfig(
        metadata=IRMetadata(hostname="graph-test"),
        addresses=[IRAddress(name="web", type=AddressType.HOST, subnet="192.0.2.1/32")],
        address_groups=[
            IRAddressGroup(name="inner", members=["web"]),
            IRAddressGroup(name="outer", members=["inner"]),
        ],
        services=[IRService(name="https")],
        service_groups=[IRServiceGroup(name="web-services", members=["https"])],
        policies=[IRPolicy(
            name="allow-web",
            source=["outer"],
            destination=["missing-address"],
            service=["web-services"],
            action=PolicyAction.ALLOW,
        )],
    )

    graph = DependencyGraph(ir)
    used = graph.reachable_reference_names()

    assert {"outer", "inner", "web"} <= used["addresses"]
    assert {"outer", "inner"} <= used["address_groups"]
    assert {"web-services", "https"} <= used["services"]
    assert any(issue.reference == "missing-address" for issue in graph.issues)
