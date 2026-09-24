from fwmigrate.vendors.checkpoint.model.address import CPGroup, CPGroupWithExclusion, CPHost
from fwmigrate.vendors.checkpoint.model.service import CPService, CPServiceGroup
from fwmigrate.vendors.checkpoint.model.source import CheckPointConfig
from fwmigrate.vendors.checkpoint.model.common import CheckPointObjectReference
from fwmigrate.vendors.checkpoint.relationships.references import build_memberships, build_reference_index


def test_group_edges_keep_source_field_provenance():
    host = CPHost(uid="h", name="host")
    group = CPGroup(uid="g", name="group", members=[CheckPointObjectReference(uid="h")])
    excluded = CPGroupWithExclusion(uid="x", name="excluded", include="g", **{"except": "h"})
    service = CPService(uid="s", name="svc")
    services = CPServiceGroup(uid="sg", name="services", members=["s"])
    config = CheckPointConfig(hosts=[host], groups=[group], groups_with_exclusion=[excluded], services=[service], service_groups=[services])
    edges = build_memberships(config, build_reference_index(config))
    assert {(edge.owner.uid, edge.source_field, edge.resolved_target.uid if edge.resolved_target else None) for edge in edges} >= {("g", "members", "h"), ("x", "include", "g"), ("x", "except_", "h"), ("sg", "members", "s")}

