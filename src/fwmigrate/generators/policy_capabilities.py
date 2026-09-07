from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Optional

from fwmigrate.ir.core import IRPolicy, IRSecurityProfileGroup
from fwmigrate.ir.enums import PolicyAction


PROFILE_FIELDS = (
    ("antivirus_profiles", "antivirus"),
    ("vulnerability_profiles", "vulnerability"),
    ("antispyware_profiles", "anti-spyware"),
    ("url_filtering_profiles", "url-filtering"),
    ("file_blocking_profiles", "file-blocking"),
    ("wildfire_analysis_profiles", "wildfire-analysis"),
    ("data_filtering_profiles", "data-filtering"),
)


@dataclass(frozen=True)
class PolicyCapabilities:
    actions: FrozenSet[PolicyAction]
    url_categories: bool = False
    max_profile_groups: Optional[int] = 0
    direct_profile_limits: Dict[str, Optional[int]] = field(default_factory=dict)
    profile_group_family_limits: Dict[str, Optional[int]] = field(default_factory=dict)

    @staticmethod
    def _exceeds(values: list[str], limit: Optional[int]) -> bool:
        return limit is not None and len(values) > limit

    def unsupported_reasons(self, policy: IRPolicy) -> list[str]:
        reasons: list[str] = []
        if policy.action is None or policy.action not in self.actions:
            reasons.append(f"policy action {policy.action.value if policy.action else 'missing'}")

        category_matches = [
            value for value in policy.url_categories
            if value.lower() != "any"
        ]
        if category_matches and not self.url_categories:
            reasons.append("URL-category policy matching")

        if self._exceeds(policy.security_profile_groups, self.max_profile_groups):
            reasons.append(
                f"{len(policy.security_profile_groups)} security profile groups"
            )

        has_direct_profiles = any(
            bool(getattr(policy, field_name, []) or [])
            for field_name, _ in PROFILE_FIELDS
        )
        if policy.security_profile_groups and has_direct_profiles:
            reasons.append("mixed profile-group and direct profile assignment")

        for field_name, label in PROFILE_FIELDS:
            values = list(getattr(policy, field_name, []) or [])
            limit = self.direct_profile_limits.get(field_name, 0)
            if self._exceeds(values, limit):
                reasons.append(f"{len(values)} direct {label} profile references")
        return reasons

    def unsupported_profile_group_reasons(
        self, group: IRSecurityProfileGroup
    ) -> list[str]:
        reasons: list[str] = []
        for field_name, label in PROFILE_FIELDS:
            values = list(getattr(group, field_name, []) or [])
            limit = self.profile_group_family_limits.get(field_name, 0)
            if self._exceeds(values, limit):
                reasons.append(f"{len(values)} {label} members")
        return reasons


_ALL_PAN_ACTIONS = frozenset({
    PolicyAction.ALLOW,
    PolicyAction.DENY,
    PolicyAction.DROP,
    PolicyAction.RESET_CLIENT,
    PolicyAction.RESET_SERVER,
    PolicyAction.RESET_BOTH,
})
_UNLIMITED_PROFILES = {field_name: None for field_name, _ in PROFILE_FIELDS}
_NO_DIRECT_PROFILES: Dict[str, Optional[int]] = {
    field_name: 0 for field_name, _ in PROFILE_FIELDS
}
_SINGLE_PROFILE_MEMBERS: Dict[str, Optional[int]] = {
    field_name: 1 for field_name, _ in PROFILE_FIELDS
}


_CAPABILITIES = {
    "palo_alto_xml": PolicyCapabilities(
        actions=_ALL_PAN_ACTIONS,
        url_categories=True,
        max_profile_groups=None,
        direct_profile_limits=_UNLIMITED_PROFILES,
        profile_group_family_limits=_UNLIMITED_PROFILES,
    ),
    "palo_alto_terraform": PolicyCapabilities(
        actions=_ALL_PAN_ACTIONS,
        url_categories=True,
        max_profile_groups=1,
        direct_profile_limits=_NO_DIRECT_PROFILES,
        profile_group_family_limits=_UNLIMITED_PROFILES,
    ),
    "fortigate_cli": PolicyCapabilities(
        actions=frozenset({PolicyAction.ALLOW, PolicyAction.DENY}),
        max_profile_groups=1,
        direct_profile_limits=_NO_DIRECT_PROFILES,
        profile_group_family_limits=_NO_DIRECT_PROFILES,
    ),
    "fortigate_terraform": PolicyCapabilities(
        actions=frozenset({PolicyAction.ALLOW, PolicyAction.DENY}),
        max_profile_groups=0,
        direct_profile_limits=_NO_DIRECT_PROFILES,
        profile_group_family_limits=_NO_DIRECT_PROFILES,
    ),
    "juniper_srx_cli": PolicyCapabilities(
        actions=frozenset({PolicyAction.ALLOW, PolicyAction.DENY}),
        max_profile_groups=1,
        direct_profile_limits=_NO_DIRECT_PROFILES,
        profile_group_family_limits={
            **_NO_DIRECT_PROFILES,
            "antivirus_profiles": 1,
            "url_filtering_profiles": 1,
        },
    ),
    "cisco_asa_cli": PolicyCapabilities(
        actions=frozenset({PolicyAction.ALLOW, PolicyAction.DENY}),
        max_profile_groups=0,
        direct_profile_limits=_NO_DIRECT_PROFILES,
        profile_group_family_limits=_NO_DIRECT_PROFILES,
    ),
    "checkpoint_cli": PolicyCapabilities(
        actions=frozenset({PolicyAction.ALLOW, PolicyAction.DENY, PolicyAction.DROP}),
        max_profile_groups=1,
        direct_profile_limits=_NO_DIRECT_PROFILES,
        profile_group_family_limits=_NO_DIRECT_PROFILES,
    ),
}


def policy_capabilities(target: str) -> PolicyCapabilities:
    try:
        return _CAPABILITIES[target]
    except KeyError as exc:
        raise ValueError(f"Unknown policy capability target: {target}") from exc
