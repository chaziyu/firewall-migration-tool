from dataclasses import replace

import pytest

from fwmigrate.conversion.palo_alto_to_juniper_srx.design.deterministic import approve_draft, build_draft
from fwmigrate.conversion.palo_alto_to_juniper_srx.models import SRXMigrationPlan, SRXPlanItem
from fwmigrate.conversion.palo_alto_to_juniper_srx.options import SRXMigrationOptions
from fwmigrate.conversion.palo_alto_to_juniper_srx.plan_dependencies import validate_plan
from fwmigrate.conversion.palo_alto_to_juniper_srx.rendering.renderer import JunosSetRenderer
from fwmigrate.conversion.palo_alto_to_juniper_srx.review.workflow import build_review_report


def _address(key, **changes):
    return replace(SRXPlanItem(
        key, "address", "vsys1", "address", key, f"/address/{key}", key,
        (("address_type", "prefix"), ("value", "192.0.2.1/32")),
    ), **changes)


def _plan(*items):
    return SRXMigrationPlan("vsys1", "root", "25.2R1", items)


@pytest.mark.parametrize(("items", "reason"), [
    ((_address("a", dependencies=("b",)), _address("b", dependencies=("a",))), "PLAN_DEPENDENCY_CYCLE"),
    ((_address("a", dependencies=("a",)),), "PLAN_DEPENDENCY_CYCLE"),
    ((_address("a", dependencies=("missing",)),), "PLAN_DEPENDENCY_UNRESOLVED"),
    ((_address("a"), _address("a", target_name="different-name")), "DUPLICATE_PLAN_IDENTITY"),
    ((_address("a"), _address("b", target_name="A")), "DUPLICATE_TARGET_OBJECT_NAME"),
    ((_address("a", family="future_family"),), "RENDER_FAMILY_UNSUPPORTED"),
    ((_address("a", target_disposition="BLOCK"),), "TARGET_DISPOSITION_BLOCKED"),
    ((_address("a", target_disposition="CONFIGURE"),), "TARGET_DISPOSITION_UNSUPPORTED"),
])
def test_review_design_and_renderer_agree_on_invalid_dependencies(items, reason):
    original = _plan(*items)
    validated = validate_plan(original)
    assert validate_plan(validated) == validated
    assert all(not row.blockers for row in original.items)

    report = build_review_report(original)
    rendered = JunosSetRenderer().render(original)
    assert report["plan_status"] == "BLOCKED"
    assert report["renderable_item_count"] == rendered.command_count == 0
    assert report["blocked_item_count"] == len(items)
    assert all(reason in row["blockers"] for row in report["items"])
    assert rendered.blocked_items == tuple((row.key, row.blockers) for row in validated.items)

    draft = build_draft(original, "a" * 64, SRXMigrationOptions())
    assert all(reason in row["blockers"] for row in draft["items"])
    with pytest.raises(ValueError, match="blocked|unavailable"):
        approve_draft(original, draft, [items[0].key])


def test_blockers_propagate_through_reverse_ordered_dependency_chain():
    plan = _plan(
        _address("child", dependencies=("parent",)),
        _address("parent", dependencies=("blocked",)),
        _address("blocked", dependencies=("missing",)),
        _address("independent"),
    )
    report = build_review_report(plan)
    rendered = JunosSetRenderer().render(plan)
    assert report["blocked_item_count"] == 3
    assert report["renderable_item_count"] == 1
    assert rendered.commands == ("set security address-book global address independent 192.0.2.1/32",)
    assert dict(rendered.blocked_items)["child"] == ("PLAN_DEPENDENCY_BLOCKED",)


def test_reuse_satisfies_group_dependency_without_recreating_object():
    member = _address("existing", target_disposition="REUSE")
    group = _address("group", family="address_group", dependencies=(member.key,),
                     settings=(("members", (member.target_name,)),))
    plan = _plan(group, member)
    report = build_review_report(plan)
    rendered = JunosSetRenderer().render(plan)
    assert report["reused_item_count"] == report["renderable_item_count"] == 1
    assert report["blocked_item_count"] == 0
    assert not rendered.blocked_items
    assert rendered.commands == ("set security address-book global address-set group address existing",)


def test_policy_names_remain_scoped_to_zone_pairs_and_order_is_stable():
    def policy(key, source_zone, order):
        return _address(key, family="policy", target_name="same-name", source_order=order,
                        settings=(("from_zone", source_zone), ("to_zone", "outside"),
                                  ("source_addresses", ("any",)), ("destination_addresses", ("any",)),
                                  ("applications", ("any",)), ("action", "permit")))

    plan = _plan(policy("later", "inside", 2), policy("earlier", "dmz", 1))
    rendered = JunosSetRenderer().render(plan)
    assert not rendered.blocked_items
    assert rendered.commands[0].startswith("set security policies from-zone dmz ")
    assert rendered.commands[-1].startswith("set security policies from-zone inside ")
