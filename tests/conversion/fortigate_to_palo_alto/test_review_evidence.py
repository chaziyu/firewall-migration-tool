from fwmigrate.conversion.fortigate_to_palo_alto.review_evidence import build_review_evidence
from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.route_static import FGStaticRoute
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.zone import FGZone


def test_review_evidence_keeps_source_and_derived_facts_separate_and_safe():
    config = FGConfig(
        interfaces=[FGInterface(name="port1", type="physical", explicit_fields={"type"},
                                raw_extra={"password": "never-export", "psksecret": "never-export"})],
        zones=[FGZone(name="inside", members=["port1"])],
        policies=[FGPolicy(policy_id=1, srcintf=["port1"], dstintf=["port1"])],
        static_routes=[FGStaticRoute(seq_num=1, device="port1")],
    )
    result = build_review_evidence(config, build_derived_views(config))[("root", "port1")]
    assert result["source_explicit"] == {"type": "physical", "zone_membership": ["inside"]}
    assert result["derived_relationships"]["policy_source_reference_count"] == 1
    assert result["derived_relationships"]["policy_destination_reference_count"] == 1
    assert result["derived_relationships"]["static_route_usage"] == 1
    assert "never-export" not in repr(result)
    assert "psksecret" not in repr(result).casefold()
