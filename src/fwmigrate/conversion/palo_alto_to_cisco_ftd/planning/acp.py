"""Plan a fresh FMC Access Control Policy container."""

from ..models import FTDPlanItem
from .objects import operation


def acp_key(source_scope, options):
    return f"acp:{source_scope}:{options.policy_name}"


def plan_new_acp(source_scope, options, domain_id, blockers=()):
    key = acp_key(source_scope, options)
    path = f"/api/fmc_config/v1/domain/{domain_id}/policy/accesspolicies"
    body = {
        "name": options.policy_name,
        "defaultAction": {"action": "BLOCK"},
        "type": "AccessPolicy",
    }
    settings = (
        operation(key, path, body, "AccessPolicy"),
        ("fmc_type", "AccessPolicy"),
    )
    return [
        FTDPlanItem(
            key=key,
            family="acp",
            source_scope=source_scope,
            source_name=options.policy_name,
            target_name=options.policy_name,
            settings=settings,
            dependencies=(),
            blockers=tuple(blockers),
            source_order=0,
            source_path="policy/accesspolicies",
            source_kind="AccessPolicy",
        )
    ]
