from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def write(rel: str, text: str) -> None:
    (ROOT / rel).write_text(text, encoding="utf-8")


def replace_once(rel: str, old: str, new: str) -> None:
    text = read(rel)
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{rel}: expected exactly one occurrence, found {count}: {old[:100]!r}")
    write(rel, text.replace(old, new, 1))


def sub_once(rel: str, pattern: str, replacement: str) -> None:
    text = read(rel)
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.S)
    if count != 1:
        raise RuntimeError(f"{rel}: regex replacement matched {count} times: {pattern[:100]!r}")
    write(rel, updated)


# ---------------------------------------------------------------------------
# IR enums + schema version
# ---------------------------------------------------------------------------
replace_once(
    "src/fwmigrate/ir/enums.py",
    'class PolicyAction(str, Enum):\n    ALLOW = "allow"\n    DENY = "deny"\n    DROP = "drop"\n    IPSEC = "ipsec"',
    'class PolicyAction(str, Enum):\n    ALLOW = "allow"\n    DENY = "deny"\n    DROP = "drop"\n    RESET_CLIENT = "reset-client"\n    RESET_SERVER = "reset-server"\n    RESET_BOTH = "reset-both"\n    IPSEC = "ipsec"',
)
replace_once(
    "src/fwmigrate/ir/version.py",
    'IR_SCHEMA_VERSION = "1.49"\nSUPPORTED_IR_SCHEMA_MAJOR = 1\nSUPPORTED_IR_SCHEMA_MINOR = 49',
    'IR_SCHEMA_VERSION = "1.50"\nSUPPORTED_IR_SCHEMA_MAJOR = 1\nSUPPORTED_IR_SCHEMA_MINOR = 50',
)


# ---------------------------------------------------------------------------
# Canonical IR: ordered security-profile collections + URL categories
# ---------------------------------------------------------------------------
profile_group_model = '''class IRSecurityProfileGroup(BaseModel):
    name: str
    source_context: Optional[str] = None

    # Ordered canonical profile memberships.  PAN-OS permits multiple members
    # per family; target generators decide whether that cardinality is portable.
    antivirus_profiles: List[str] = Field(default_factory=list)
    vulnerability_profiles: List[str] = Field(default_factory=list)
    antispyware_profiles: List[str] = Field(default_factory=list)
    url_filtering_profiles: List[str] = Field(default_factory=list)
    file_blocking_profiles: List[str] = Field(default_factory=list)
    wildfire_analysis_profiles: List[str] = Field(default_factory=list)
    data_filtering_profiles: List[str] = Field(default_factory=list)

    # Backward-compatible scalar projections.  They are authoritative only
    # when the corresponding ordered collection contains exactly one member.
    antivirus: Optional[str] = None
    vulnerability: Optional[str] = None
    anti_spyware: Optional[str] = None
    url_filtering: Optional[str] = None
    file_blocking: Optional[str] = None
    wildfire: Optional[str] = None
    data_filtering: Optional[str] = None
    ssl_decryption: Optional[str] = None
    description: Optional[str] = None
    migration_status: str = "PARTIALLY_NORMALIZED"
    requires_manual_review: bool = True
    source_profile_references: Dict[str, str] = Field(default_factory=dict)
    support_level: str = "TYPED_EXTRACT_ONLY"
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def normalize_profile_membership_compatibility(self):
        pairs = (
            ("antivirus", "antivirus_profiles"),
            ("vulnerability", "vulnerability_profiles"),
            ("anti_spyware", "antispyware_profiles"),
            ("url_filtering", "url_filtering_profiles"),
            ("file_blocking", "file_blocking_profiles"),
            ("wildfire", "wildfire_analysis_profiles"),
            ("data_filtering", "data_filtering_profiles"),
        )
        for scalar_field, list_field in pairs:
            values = list(getattr(self, list_field) or [])
            scalar = getattr(self, scalar_field)
            if values:
                setattr(self, scalar_field, values[0] if len(values) == 1 else None)
            elif scalar:
                setattr(self, list_field, [scalar])
        return self
'''
sub_once(
    "src/fwmigrate/ir/core.py",
    r'class IRSecurityProfileGroup\(BaseModel\):\n.*?\n\nclass IRApplication\(BaseModel\):',
    profile_group_model + '\nclass IRApplication(BaseModel):',
)

replace_once(
    "src/fwmigrate/ir/core.py",
    '''    # Advanced / UTM threat profiles
    security_profile_group: Optional[str] = None
    antivirus: Optional[str] = None
    ips_sensor: Optional[str] = None
    webfilter: Optional[str] = None
    application_list: Optional[str] = None
    ssl_ssh_profile: Optional[str] = None
    applications: List[str] = Field(default_factory=list)
    internet_service: List[str] = Field(default_factory=list)

    @property
    def safe_for_target_generation(self) -> bool:
''',
    '''    # Canonical policy match/profile semantics.  Ordered collections retain
    # source cardinality; legacy scalar fields below are compatibility views.
    url_categories: List[str] = Field(default_factory=list)
    url_category_reference_statuses: Dict[str, str] = Field(default_factory=dict)
    unresolved_url_categories: List[str] = Field(default_factory=list)
    security_profile_groups: List[str] = Field(default_factory=list)
    antivirus_profiles: List[str] = Field(default_factory=list)
    vulnerability_profiles: List[str] = Field(default_factory=list)
    antispyware_profiles: List[str] = Field(default_factory=list)
    url_filtering_profiles: List[str] = Field(default_factory=list)
    file_blocking_profiles: List[str] = Field(default_factory=list)
    wildfire_analysis_profiles: List[str] = Field(default_factory=list)
    data_filtering_profiles: List[str] = Field(default_factory=list)

    # Advanced / UTM threat-profile compatibility projections.
    security_profile_group: Optional[str] = None
    antivirus: Optional[str] = None
    ips_sensor: Optional[str] = None
    webfilter: Optional[str] = None
    application_list: Optional[str] = None
    ssl_ssh_profile: Optional[str] = None
    applications: List[str] = Field(default_factory=list)
    internet_service: List[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def normalize_policy_profile_compatibility(self):
        pairs = (
            ("security_profile_group", "security_profile_groups"),
            ("antivirus", "antivirus_profiles"),
            ("ips_sensor", "vulnerability_profiles"),
            ("webfilter", "url_filtering_profiles"),
        )
        for scalar_field, list_field in pairs:
            values = list(getattr(self, list_field) or [])
            scalar = getattr(self, scalar_field)
            if values:
                setattr(self, scalar_field, values[0] if len(values) == 1 else None)
            elif scalar:
                setattr(self, list_field, [scalar])
        return self

    @property
    def safe_for_target_generation(self) -> bool:
''',
)


# ---------------------------------------------------------------------------
# Explicit 1.49 -> 1.50 schema migration
# ---------------------------------------------------------------------------
replace_once(
    "src/fwmigrate/ir/migrations.py",
    '''    payload = _normalize_ssl_vpn_ciphersuite(payload)
    if version == "1.48":
        migrated = dict(payload)
        migrated["schema_version"] = IR_SCHEMA_VERSION
        return migrated
''',
    '''    payload = _normalize_ssl_vpn_ciphersuite(payload)
    if version in {"1.48", "1.49"}:
        return _migrate_1_50_policy_semantics(dict(payload))
''',
)

migration_helper = '''\n\ndef _migrate_1_50_policy_semantics(payload: dict[str, Any]) -> dict[str, Any]:
    """Add lossless policy/profile collections introduced in schema 1.50.

    Only existing canonical scalar fields seed one-item compatibility lists.
    Source-only PAN evidence is deliberately not promoted retroactively.
    """
    migrated = dict(payload)

    policy_pairs = {
        "security_profile_group": "security_profile_groups",
        "antivirus": "antivirus_profiles",
        "ips_sensor": "vulnerability_profiles",
        "webfilter": "url_filtering_profiles",
    }
    policy_list_defaults = (
        "security_profile_groups", "antivirus_profiles", "vulnerability_profiles",
        "antispyware_profiles", "url_filtering_profiles", "file_blocking_profiles",
        "wildfire_analysis_profiles", "data_filtering_profiles", "url_categories",
        "unresolved_url_categories",
    )
    for policy in migrated.get("policies", []):
        if not isinstance(policy, dict):
            continue
        for field in policy_list_defaults:
            policy.setdefault(field, [])
        policy.setdefault("url_category_reference_statuses", {})
        for scalar_field, list_field in policy_pairs.items():
            if not policy.get(list_field) and policy.get(scalar_field):
                policy[list_field] = [policy[scalar_field]]

    group_pairs = {
        "antivirus": "antivirus_profiles",
        "vulnerability": "vulnerability_profiles",
        "anti_spyware": "antispyware_profiles",
        "url_filtering": "url_filtering_profiles",
        "file_blocking": "file_blocking_profiles",
        "wildfire": "wildfire_analysis_profiles",
        "data_filtering": "data_filtering_profiles",
    }
    for group in migrated.get("security_profile_groups", []):
        if not isinstance(group, dict):
            continue
        for scalar_field, list_field in group_pairs.items():
            group.setdefault(list_field, [])
            if not group.get(list_field) and group.get(scalar_field):
                group[list_field] = [group[scalar_field]]

    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated
'''
replace_once(
    "src/fwmigrate/ir/migrations.py",
    '\n\ndef _migrate_1_44(payload: dict[str, Any]) -> dict[str, Any]:',
    migration_helper + '\n\ndef _migrate_1_44(payload: dict[str, Any]) -> dict[str, Any]:',
)


# ---------------------------------------------------------------------------
# PAN-OS parser: exact actions, ordered categories and profile references
# ---------------------------------------------------------------------------
replace_once(
    "src/fwmigrate/parsers/palo_alto/parser.py",
    '''        action_map = {
            "allow": PolicyAction.ALLOW,
            "deny": PolicyAction.DENY,
            "drop": PolicyAction.DENY,
            "reset-client": PolicyAction.DENY,
            "reset-server": PolicyAction.DENY,
            "reset-both": PolicyAction.DENY,
        }
''',
    '''        action_map = {
            "allow": PolicyAction.ALLOW,
            "deny": PolicyAction.DENY,
            "drop": PolicyAction.DROP,
            "reset-client": PolicyAction.RESET_CLIENT,
            "reset-server": PolicyAction.RESET_SERVER,
            "reset-both": PolicyAction.RESET_BOTH,
        }
''',
)

replace_once(
    "src/fwmigrate/parsers/palo_alto/parser.py",
    '''        if len(profile_groups) > 1:
            record_parse_error(
                extraction, "policies", source_path, scope, name, evidence,
                notes=["PAN-OS security rule contains multiple profile-group members."],
            )
            return

''',
    '',
)

replace_once(
    "src/fwmigrate/parsers/palo_alto/parser.py",
    '''        resolved_direct_profiles: Dict[str, List[str]] = {}
        unresolved_direct_profiles: Dict[str, List[str]] = {}
        for profile_type, values in direct_profiles.items():
            for value in values:
                resolved = self.resolver.resolve(
                    value, f"security-profile:{profile_family_alias[profile_type]}", scope
                )
                if resolved is None:
                    unresolved_direct_profiles.setdefault(profile_type, []).append(value)
                else:
                    resolved_direct_profiles.setdefault(profile_type, []).append(resolved.canonical_name or value)
''',
    '''        resolved_direct_profiles: Dict[str, List[str]] = {}
        unresolved_direct_profiles: Dict[str, List[str]] = {}
        canonical_direct_profiles: Dict[str, List[str]] = {}
        for profile_type, values in direct_profiles.items():
            for value in values:
                resolved = self.resolver.resolve(
                    value, f"security-profile:{profile_family_alias[profile_type]}", scope
                )
                if resolved is None:
                    unresolved_direct_profiles.setdefault(profile_type, []).append(value)
                    canonical_value = value
                else:
                    canonical_value = resolved.canonical_name or value
                    resolved_direct_profiles.setdefault(profile_type, []).append(canonical_value)
                canonical_direct_profiles.setdefault(profile_type, []).append(canonical_value)
''',
)

replace_once(
    "src/fwmigrate/parsers/palo_alto/parser.py",
    '''        profile_group = profile_groups[0] if profile_groups else None
        unresolved_profile_group: List[str] = []
        if profile_group:
            resolved_profile = self.resolver.resolve(profile_group, "profile-group", scope)
            if resolved_profile is None:
                unresolved_profile_group.append(profile_group)
            else:
                profile_group = resolved_profile.canonical_name or profile_group

        unresolved_sets = {
''',
    '''        canonical_profile_groups: List[str] = []
        unresolved_profile_group: List[str] = []
        for source_profile_group in profile_groups:
            resolved_profile = self.resolver.resolve(source_profile_group, "profile-group", scope)
            if resolved_profile is None:
                unresolved_profile_group.append(source_profile_group)
                canonical_profile_groups.append(source_profile_group)
            else:
                canonical_profile_groups.append(
                    resolved_profile.canonical_name or source_profile_group
                )
        profile_group = (
            canonical_profile_groups[0] if len(canonical_profile_groups) == 1 else None
        )

        canonical_url_categories: List[str] = []
        url_category_reference_statuses: Dict[str, str] = {}
        for index, value in enumerate(categories):
            key = f"category[{index}]"
            if value.lower() == "any":
                canonical_url_categories.append(value)
                url_category_reference_statuses[key] = "builtin"
                continue
            resolved_category = self.resolver.resolve(value, "custom-url-category", scope)
            if resolved_category is not None:
                canonical_url_categories.append(resolved_category.canonical_name or value)
                url_category_reference_statuses[key] = "custom-resolved"
            else:
                # PAN predefined URL categories are valid without a local
                # custom object.  Preserve the exact ordered category token.
                canonical_url_categories.append(value)
                url_category_reference_statuses[key] = "predefined"
        if url_category_reference_statuses:
            evidence["pan_url_category_reference_statuses"] = url_category_reference_statuses

        unresolved_sets = {
''',
)

replace_once(
    "src/fwmigrate/parsers/palo_alto/parser.py",
    '''            ("source-action-variant", source_action not in {"allow", "deny"}),
            ("source-user", bool(source_users) and [value.lower() for value in source_users] != ["any"]),
            ("category", bool(categories) and [value.lower() for value in categories] != ["any"]),
''',
    '''            ("source-user", bool(source_users) and [value.lower() for value in source_users] != ["any"]),
''',
)

replace_once(
    "src/fwmigrate/parsers/palo_alto/parser.py",
    '''            ("security-profiles", bool(direct_profiles)),
            ("unresolved-security-profiles", bool(unresolved_direct_profiles)),
            ("mixed-profile-assignment", bool(profile_group and direct_profiles)),
''',
    '''            ("unresolved-security-profiles", bool(unresolved_direct_profiles)),
            ("mixed-profile-assignment", bool(canonical_profile_groups and direct_profiles)),
''',
)

replace_once(
    "src/fwmigrate/parsers/palo_alto/parser.py",
    '''            source_profile_type="group" if profile_group and not direct_profiles else ("profiles" if direct_profiles and not profile_group else "mixed" if profile_group else None),
            source_profile_group=profile_groups[0] if profile_groups else None,
            source_extra_settings=evidence,
''',
    '''            source_profile_type=(
                "group" if canonical_profile_groups and not direct_profiles
                else "profiles" if direct_profiles and not canonical_profile_groups
                else "mixed" if canonical_profile_groups and direct_profiles
                else None
            ),
            source_profile_group=profile_groups[0] if len(profile_groups) == 1 else None,
            source_extra_settings=evidence,
''',
)

replace_once(
    "src/fwmigrate/parsers/palo_alto/parser.py",
    '''            security_profile_group=profile_group,
            antivirus=direct_profiles.get("virus", [None])[0],
            ips_sensor=direct_profiles.get("vulnerability", [None])[0],
            webfilter=direct_profiles.get("url-filtering", [None])[0],
            unresolved_security_profiles=(
                unresolved_profile_group
                + [value for values in unresolved_direct_profiles.values() for value in values]
            ),
            security_profile_semantics_review=bool(direct_profiles or unresolved_profile_group),
''',
    '''            url_categories=canonical_url_categories,
            url_category_reference_statuses=url_category_reference_statuses,
            security_profile_groups=canonical_profile_groups,
            antivirus_profiles=canonical_direct_profiles.get("virus", []),
            vulnerability_profiles=canonical_direct_profiles.get("vulnerability", []),
            antispyware_profiles=canonical_direct_profiles.get("spyware", []),
            url_filtering_profiles=canonical_direct_profiles.get("url-filtering", []),
            file_blocking_profiles=canonical_direct_profiles.get("file-blocking", []),
            wildfire_analysis_profiles=canonical_direct_profiles.get("wildfire-analysis", []),
            data_filtering_profiles=canonical_direct_profiles.get("data-filtering", []),
            unresolved_security_profiles=(
                unresolved_profile_group
                + [value for values in unresolved_direct_profiles.values() for value in values]
            ),
            security_profile_semantics_review=bool(
                unresolved_profile_group or unresolved_direct_profiles
            ),
''',
)

# Profile-group objects: cardinality and data-filtering are canonical semantics.
replace_once(
    "src/fwmigrate/parsers/palo_alto/parser.py",
    '''            cardinality = [key for key, values in members.items() if len(values) > 1]
            partial_reasons = []
            if cardinality:
                partial_reasons.append(f"multiple-members:{','.join(cardinality)}")
            if members["data-filtering"]:
                partial_reasons.append("data-filtering-source-only")
            if unresolved_members:
''',
    '''            canonical_members: Dict[str, List[str]] = {}
            for profile_type, values in members.items():
                family = profile_family_alias.get(profile_type, profile_type)
                for value in values:
                    resolved = self.resolver.resolve(
                        value, f"security-profile:{family}", scope
                    )
                    canonical_members.setdefault(profile_type, []).append(
                        resolved.canonical_name if resolved is not None and resolved.canonical_name else value
                    )

            partial_reasons = []
            if unresolved_members:
''',
)

replace_once(
    "src/fwmigrate/parsers/palo_alto/parser.py",
    '''            profile_group = IRSecurityProfileGroup(
                name=pg_name,
                antivirus=members["virus"][0] if len(members["virus"]) == 1 else None,
                vulnerability=members["vulnerability"][0] if len(members["vulnerability"]) == 1 else None,
                anti_spyware=members["spyware"][0] if len(members["spyware"]) == 1 else None,
                url_filtering=members["url-filtering"][0] if len(members["url-filtering"]) == 1 else None,
                file_blocking=members["file-blocking"][0] if len(members["file-blocking"]) == 1 else None,
                wildfire=members["wildfire-analysis"][0] if len(members["wildfire-analysis"]) == 1 else None,
                description=description,
                migration_status="PARTIALLY_NORMALIZED" if partial_reasons else "NORMALIZED",
                requires_manual_review=bool(partial_reasons),
                source_profile_references={key: values[0] for key, values in members.items() if len(values) == 1},
            )
''',
    '''            profile_group = IRSecurityProfileGroup(
                name=pg_name,
                antivirus_profiles=canonical_members.get("virus", []),
                vulnerability_profiles=canonical_members.get("vulnerability", []),
                antispyware_profiles=canonical_members.get("spyware", []),
                url_filtering_profiles=canonical_members.get("url-filtering", []),
                file_blocking_profiles=canonical_members.get("file-blocking", []),
                wildfire_analysis_profiles=canonical_members.get("wildfire-analysis", []),
                data_filtering_profiles=canonical_members.get("data-filtering", []),
                description=description,
                migration_status="PARTIALLY_NORMALIZED" if partial_reasons else "NORMALIZED",
                requires_manual_review=bool(partial_reasons),
                source_profile_references={
                    f"{key}[{index}]": value
                    for key, values in members.items()
                    for index, value in enumerate(values)
                },
            )
''',
)


# ---------------------------------------------------------------------------
# Shared target policy capability checks
# ---------------------------------------------------------------------------
capabilities = '''from __future__ import annotations

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
'''
write("src/fwmigrate/generators/policy_capabilities.py", capabilities)


# ---------------------------------------------------------------------------
# PAN-OS semantic/XML generator: exact native semantics
# ---------------------------------------------------------------------------
replace_once(
    "src/fwmigrate/generators/palo_alto/model.py",
    'from typing import List, Optional',
    'from typing import Dict, List, Optional',
)
replace_once(
    "src/fwmigrate/generators/palo_alto/model.py",
    '''    profile_setting_group: Optional[str] = None

class PANNATRuleEntry(BaseModel):
''',
    '''    profile_setting_group: Optional[str] = None
    profile_setting_groups: List[str] = Field(default_factory=list)
    profile_setting_profiles: Dict[str, List[str]] = Field(default_factory=dict)

class PANNATRuleEntry(BaseModel):
''',
)
sub_once(
    "src/fwmigrate/generators/palo_alto/model.py",
    r'class PANProfileGroupEntry\(BaseModel\):\n.*?\n\nclass PANVsysEntry\(BaseModel\):',
    '''class PANProfileGroupEntry(BaseModel):
    name: str
    virus: List[str] = Field(default_factory=list)
    vulnerability: List[str] = Field(default_factory=list)
    spyware: List[str] = Field(default_factory=list)
    url_filtering: List[str] = Field(default_factory=list)
    file_blocking: List[str] = Field(default_factory=list)
    wildfire_analysis: List[str] = Field(default_factory=list)
    data_filtering: List[str] = Field(default_factory=list)

class PANVsysEntry(BaseModel):''',
)

replace_once(
    "src/fwmigrate/generators/palo_alto/transformer.py",
    'from fwmigrate.generators.nat_capabilities import nat_capabilities',
    'from fwmigrate.generators.nat_capabilities import nat_capabilities\nfrom fwmigrate.generators.policy_capabilities import policy_capabilities',
)
replace_once(
    "src/fwmigrate/generators/palo_alto/transformer.py",
    '''            pan.vsys.profile_groups.append(PANProfileGroupEntry(
                name=pg.name,
                virus=[pg.antivirus] if pg.antivirus else ["default"],
                vulnerability=[pg.vulnerability] if pg.vulnerability else ["default"],
                spyware=[pg.anti_spyware] if pg.anti_spyware else ["default"],
                url_filtering=[pg.url_filtering] if pg.url_filtering else ["default"],
                file_blocking=[pg.file_blocking] if pg.file_blocking else ["basic-file-blocking"],
                wildfire_analysis=[pg.wildfire] if pg.wildfire else ["default"]
            ))
''',
    '''            unsupported_profiles = policy_capabilities(
                "palo_alto_xml"
            ).unsupported_profile_group_reasons(pg)
            if unsupported_profiles:
                self.ir.audit_entries.append(IRAuditEntry(
                    id=f"panos-profile-group-capability:{pg.name}",
                    category="PAN-OS Security Profile",
                    message=(
                        f"Security profile group '{pg.name}' was withheld: "
                        + "; ".join(unsupported_profiles)
                    ),
                    confidence=MigrationConfidence.MANUAL,
                ))
                continue
            pan.vsys.profile_groups.append(PANProfileGroupEntry(
                name=pg.name,
                virus=list(pg.antivirus_profiles),
                vulnerability=list(pg.vulnerability_profiles),
                spyware=list(pg.antispyware_profiles),
                url_filtering=list(pg.url_filtering_profiles),
                file_blocking=list(pg.file_blocking_profiles),
                wildfire_analysis=list(pg.wildfire_analysis_profiles),
                data_filtering=list(pg.data_filtering_profiles),
            ))
''',
)
replace_once(
    "src/fwmigrate/generators/palo_alto/transformer.py",
    '''        for p in self.ir.policies:
            if not p.safe_for_target_generation:
''',
    '''        for p in self.ir.policies:
            capability_reasons = policy_capabilities(
                "palo_alto_xml"
            ).unsupported_reasons(p)
            if capability_reasons:
                self.ir.audit_entries.append(IRAuditEntry(
                    id=f"panos-policy-capability:{p.source_rule_id or p.name}",
                    category="PAN-OS Policy",
                    message=(
                        f"Policy '{p.name}' was withheld because the PAN-OS XML "
                        "backend cannot reproduce: " + "; ".join(capability_reasons)
                    ),
                    confidence=MigrationConfidence.MANUAL,
                ))
                continue
            if not p.safe_for_target_generation:
''',
)
replace_once(
    "src/fwmigrate/generators/palo_alto/transformer.py",
    '''            rule_name = p.name
            action = "allow" if p.action == PolicyAction.ALLOW else "deny"
            disabled = "yes" if p.disabled else "no"

            # If policy references a profile group not yet in profile_groups, create a default entry
            if p.security_profile_group and p.security_profile_group not in existing_groups:
                existing_groups.add(p.security_profile_group)
                pan.vsys.profile_groups.append(PANProfileGroupEntry(name=p.security_profile_group))
''',
    '''            rule_name = p.name
            action = p.action.value
            disabled = "yes" if p.disabled else "no"

            # Preserve every referenced profile group.  Missing definitions are
            # emitted as empty named groups rather than fabricated defaults.
            for profile_group_name in p.security_profile_groups:
                if profile_group_name not in existing_groups:
                    existing_groups.add(profile_group_name)
                    pan.vsys.profile_groups.append(
                        PANProfileGroupEntry(name=profile_group_name)
                    )
''',
)
replace_once(
    "src/fwmigrate/generators/palo_alto/transformer.py",
    '''                application=rule_apps,
                service=rule_services,
                action=action,
                log_start="yes" if getattr(p, 'log_start', False) else "no",
                disabled=disabled,
                description=p.description,
                profile_setting_group=p.security_profile_group
            ))
''',
    '''                category=list(p.url_categories) or ["any"],
                application=rule_apps,
                service=rule_services,
                action=action,
                log_start="yes" if getattr(p, 'log_start', False) else "no",
                disabled=disabled,
                description=p.description,
                profile_setting_group=p.security_profile_group,
                profile_setting_groups=list(p.security_profile_groups),
                profile_setting_profiles={
                    "virus": list(p.antivirus_profiles),
                    "vulnerability": list(p.vulnerability_profiles),
                    "spyware": list(p.antispyware_profiles),
                    "url-filtering": list(p.url_filtering_profiles),
                    "file-blocking": list(p.file_blocking_profiles),
                    "wildfire-analysis": list(p.wildfire_analysis_profiles),
                    "data-filtering": list(p.data_filtering_profiles),
                },
            ))
''',
)

replace_once(
    "src/fwmigrate/generators/palo_alto/xml_generator.py",
    '''                if pg.wildfire_analysis:
                    wf_elem = etree.SubElement(pg_entry, "wildfire-analysis")
                    for m in pg.wildfire_analysis:
                        etree.SubElement(wf_elem, "member").text = m
''',
    '''                if pg.wildfire_analysis:
                    wf_elem = etree.SubElement(pg_entry, "wildfire-analysis")
                    for m in pg.wildfire_analysis:
                        etree.SubElement(wf_elem, "member").text = m
                if pg.data_filtering:
                    df_elem = etree.SubElement(pg_entry, "data-filtering")
                    for m in pg.data_filtering:
                        etree.SubElement(df_elem, "member").text = m
''',
)
replace_once(
    "src/fwmigrate/generators/palo_alto/xml_generator.py",
    '''                    if r.profile_setting_group:
                        ps = etree.SubElement(r_entry, "profile-setting")
                        grp = etree.SubElement(ps, "group")
                        etree.SubElement(grp, "member").text = r.profile_setting_group
''',
    '''                    profile_groups = list(r.profile_setting_groups)
                    if not profile_groups and r.profile_setting_group:
                        profile_groups = [r.profile_setting_group]
                    direct_profiles = {
                        family: values
                        for family, values in r.profile_setting_profiles.items()
                        if values
                    }
                    if profile_groups or direct_profiles:
                        ps = etree.SubElement(r_entry, "profile-setting")
                        if profile_groups:
                            grp = etree.SubElement(ps, "group")
                            for value in profile_groups:
                                etree.SubElement(grp, "member").text = value
                        if direct_profiles:
                            profiles = etree.SubElement(ps, "profiles")
                            for family, values in direct_profiles.items():
                                family_node = etree.SubElement(profiles, family)
                                for value in values:
                                    etree.SubElement(family_node, "member").text = value
''',
)

# PAN-OS Terraform supports exact action/category matching, but the current
# provider path cannot express multiple groups or direct profile assignments.
replace_once(
    "src/fwmigrate/generators/palo_alto/terraform_generator.py",
    'from fwmigrate.generators.nat_capabilities import nat_capabilities',
    'from fwmigrate.generators.nat_capabilities import nat_capabilities\nfrom fwmigrate.generators.policy_capabilities import policy_capabilities',
)
replace_once(
    "src/fwmigrate/generators/palo_alto/terraform_generator.py",
    '''        for p in policies:
            if (
                p.action == PolicyAction.IPSEC
                or not p.safe_for_target_generation
''',
    '''        for p in policies:
            capability_reasons = policy_capabilities(
                "palo_alto_terraform"
            ).unsupported_reasons(p)
            if capability_reasons:
                ir.audit_entries.append(IRAuditEntry(
                    id=f"panos-terraform-policy-capability:{p.source_rule_id or p.name}",
                    category="PAN-OS Terraform Policy",
                    message=(
                        f"Policy '{p.name}' was withheld because the target "
                        "provider cannot reproduce: " + "; ".join(capability_reasons)
                    ),
                    confidence=MigrationConfidence.MANUAL,
                ))
                continue
            if (
                p.action == PolicyAction.IPSEC
                or not p.safe_for_target_generation
''',
)
replace_once(
    "src/fwmigrate/generators/palo_alto/terraform_generator.py",
    '''            # Action mapping
            action = "allow" if p.action == PolicyAction.ALLOW else "deny"
            disabled_str = "true" if disabled else "false"
            log_end_str = "true" if p.log_end else "false"
            
            group_str = f'\\n      group                 = ["{self.sanitize_panos_name(p.security_profile_group)}"]' if p.security_profile_group else ''
''',
    '''            # Exact action/category mapping.  Capability checks above
            # withhold semantics that this Terraform resource cannot express.
            action = p.action.value
            disabled_str = "true" if disabled else "false"
            log_end_str = "true" if p.log_end else "false"
            categories = list(p.url_categories) or ["any"]
            group_str = (
                f'\\n      group                 = ["{self.sanitize_panos_name(p.security_profile_groups[0])}"]'
                if len(p.security_profile_groups) == 1 else ''
            )
''',
)
replace_once(
    "src/fwmigrate/generators/palo_alto/terraform_generator.py",
    '      categories            = ["any"]\n      action                = "{action}"',
    '      categories            = {json.dumps(categories)}\n      action                = "{action}"',
)


# ---------------------------------------------------------------------------
# Non-PAN target generators: fail closed on unsupported canonical semantics
# ---------------------------------------------------------------------------
for rel, import_anchor in (
    ("src/fwmigrate/generators/fortigate/cli_generator.py", "from fwmigrate.generators.nat_capabilities import nat_capabilities"),
    ("src/fwmigrate/generators/fortigate/terraform_generator.py", "from fwmigrate.generators.nat_capabilities import nat_capabilities"),
):
    replace_once(rel, import_anchor, import_anchor + "\nfrom fwmigrate.generators.policy_capabilities import policy_capabilities")

replace_once(
    "src/fwmigrate/generators/fortigate/cli_generator.py",
    '''            for idx, pol in enumerate(ir.policies, 1):
                if pol.action == PolicyAction.IPSEC or not pol.safe_for_target_generation:
''',
    '''            for idx, pol in enumerate(ir.policies, 1):
                capability_reasons = policy_capabilities(
                    "fortigate_cli"
                ).unsupported_reasons(pol)
                if capability_reasons:
                    lines.append(
                        f"    # Policy {pol.name} withheld: target capability does not support "
                        + "; ".join(capability_reasons)
                    )
                    continue
                if pol.action == PolicyAction.IPSEC or not pol.safe_for_target_generation:
''',
)
replace_once(
    "src/fwmigrate/generators/fortigate/cli_generator.py",
    '''            for pg in ir.security_profile_groups:
                if not is_generation_safe_object(pg):
''',
    '''            for pg in ir.security_profile_groups:
                capability_reasons = policy_capabilities(
                    "fortigate_cli"
                ).unsupported_profile_group_reasons(pg)
                if capability_reasons:
                    lines.append(
                        f"    # Security profile group {pg.name} withheld: target capability does not support "
                        + "; ".join(capability_reasons)
                    )
                    continue
                if not is_generation_safe_object(pg):
''',
)
replace_once(
    "src/fwmigrate/generators/fortigate/terraform_generator.py",
    '''        for idx, p in enumerate(ir.policies, 1):
            if p.action == PolicyAction.IPSEC or not p.safe_for_target_generation:
''',
    '''        for idx, p in enumerate(ir.policies, 1):
            capability_reasons = policy_capabilities(
                "fortigate_terraform"
            ).unsupported_reasons(p)
            if capability_reasons:
                main_tf_lines.append(
                    f"# Policy {p.name} withheld: target capability does not support "
                    + "; ".join(capability_reasons) + "\\n"
                )
                continue
            if p.action == PolicyAction.IPSEC or not p.safe_for_target_generation:
''',
)

for rel, target in (
    ("src/fwmigrate/generators/cisco_asa/cli_generator.py", "cisco_asa_cli"),
    ("src/fwmigrate/generators/checkpoint/cli_generator.py", "checkpoint_cli"),
    ("src/fwmigrate/generators/juniper_srx/cli_generator.py", "juniper_srx_cli"),
):
    replace_once(
        rel,
        'from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction',
        'from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction\nfrom fwmigrate.generators.policy_capabilities import policy_capabilities',
    )

replace_once(
    "src/fwmigrate/generators/cisco_asa/cli_generator.py",
    '''            for pol in ir.policies:
                if (
                    pol.action == PolicyAction.IPSEC
''',
    '''            for pol in ir.policies:
                capability_reasons = policy_capabilities(
                    "cisco_asa_cli"
                ).unsupported_reasons(pol)
                if capability_reasons:
                    lines.append(
                        f"! Policy {pol.name} withheld: target capability does not support "
                        + "; ".join(capability_reasons)
                    )
                    continue
                if (
                    pol.action == PolicyAction.IPSEC
''',
)
replace_once(
    "src/fwmigrate/generators/checkpoint/cli_generator.py",
    '''            for idx, pol in enumerate(ir.policies):
                if (
                    pol.action == PolicyAction.IPSEC
''',
    '''            for idx, pol in enumerate(ir.policies):
                capability_reasons = policy_capabilities(
                    "checkpoint_cli"
                ).unsupported_reasons(pol)
                if capability_reasons:
                    lines.append(
                        f"# Policy {pol.name} withheld: target capability does not support "
                        + "; ".join(capability_reasons)
                    )
                    continue
                if (
                    pol.action == PolicyAction.IPSEC
''',
)
replace_once(
    "src/fwmigrate/generators/checkpoint/cli_generator.py",
    '''                if p.safe_for_target_generation
                and not policy_references_unsafe_zone(p, unsafe_zones)
''',
    '''                if p.safe_for_target_generation
                and not policy_capabilities("checkpoint_cli").unsupported_reasons(p)
                and not policy_references_unsafe_zone(p, unsafe_zones)
''',
)
replace_once(
    "src/fwmigrate/generators/juniper_srx/cli_generator.py",
    '''            for pg in ir.security_profile_groups:
                if pg.requires_manual_review:
''',
    '''            for pg in ir.security_profile_groups:
                capability_reasons = policy_capabilities(
                    "juniper_srx_cli"
                ).unsupported_profile_group_reasons(pg)
                if capability_reasons:
                    lines.append(
                        f"# Security profile group {pg.name} withheld: target capability does not support "
                        + "; ".join(capability_reasons)
                    )
                    continue
                if pg.requires_manual_review:
''',
)
replace_once(
    "src/fwmigrate/generators/juniper_srx/cli_generator.py",
    '''            for pol in ir.policies:
                if (
                    pol.action == PolicyAction.IPSEC
''',
    '''            for pol in ir.policies:
                capability_reasons = policy_capabilities(
                    "juniper_srx_cli"
                ).unsupported_reasons(pol)
                if capability_reasons:
                    lines.append(
                        f"# Policy {pol.name} withheld: target capability does not support "
                        + "; ".join(capability_reasons)
                    )
                    continue
                if (
                    pol.action == PolicyAction.IPSEC
''',
)


# ---------------------------------------------------------------------------
# Regression tests
# ---------------------------------------------------------------------------
new_tests = '''import pytest

from fwmigrate.generators.fortigate.cli_generator import FortiGateCLIGenerator
from fwmigrate.generators.palo_alto.transformer import IRToPANOSTransformer
from fwmigrate.ir.migrations import migrate_ir_payload
from fwmigrate.ir.enums import PolicyAction
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


def _extract(*, profiles="", profile_groups="", profile_setting="", categories="", action="allow"):
    xml = f"""<?xml version="1.0"?>
    <config version="11.2.0">
      <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
        {profiles}
        {profile_groups}
        <rulebase><security><rules><entry name="Rule1">
          <from><member>trust</member></from>
          <to><member>untrust</member></to>
          <source><member>10.0.0.1</member></source>
          <destination><member>8.8.8.8</member></destination>
          <application><member>any</member></application>
          <service><member>application-default</member></service>
          {categories}
          <action>{action}</action>
          {profile_setting}
        </entry></rules></security></rulebase>
      </entry></vsys></entry></devices>
    </config>"""
    return PANOSSourceParser().extract(xml)


def _profile_definitions():
    return """
    <profiles>
      <virus><entry name="av1"/><entry name="av2"/></virus>
      <vulnerability><entry name="v1"/><entry name="v2"/></vulnerability>
      <spyware><entry name="as1"/><entry name="as2"/></spyware>
      <custom-url-category><entry name="custom-cat">
        <list><member>example.com</member></list>
      </entry></custom-url-category>
    </profiles>
    """


def test_multiple_security_profile_groups_and_members_are_canonical():
    groups = """
    <profile-group>
      <entry name="g1">
        <virus><member>av1</member><member>av2</member></virus>
        <vulnerability><member>v1</member><member>v2</member></vulnerability>
      </entry>
      <entry name="g2"><spyware><member>as1</member><member>as2</member></spyware></entry>
    </profile-group>
    """
    result = _extract(
        profiles=_profile_definitions(),
        profile_groups=groups,
        profile_setting="<profile-setting><group><member>g1</member><member>g2</member></group></profile-setting>",
    )

    assert len(result.canonical_ir.policies) == 1
    policy = result.canonical_ir.policies[0]
    assert policy.security_profile_groups == ["g1", "g2"]
    assert policy.security_profile_group is None
    assert policy.migration_status == "NORMALIZED"
    assert policy.requires_manual_review is False
    assert policy.security_profile_reference_statuses == {
        "profile-group[0]": "resolved",
        "profile-group[1]": "resolved",
    }

    by_name = {group.name: group for group in result.canonical_ir.security_profile_groups}
    assert by_name["g1"].antivirus_profiles == ["av1", "av2"]
    assert by_name["g1"].vulnerability_profiles == ["v1", "v2"]
    assert by_name["g1"].antivirus is None
    assert by_name["g1"].vulnerability is None
    assert by_name["g1"].migration_status == "NORMALIZED"
    assert by_name["g2"].antispyware_profiles == ["as1", "as2"]
    assert by_name["g2"].anti_spyware is None


def test_multiple_direct_profiles_are_ordered_and_normalized():
    setting = """
    <profile-setting><profiles>
      <virus><member>av1</member><member>av2</member></virus>
      <vulnerability><member>v1</member><member>v2</member></vulnerability>
      <spyware><member>as1</member><member>as2</member></spyware>
    </profiles></profile-setting>
    """
    result = _extract(profiles=_profile_definitions(), profile_setting=setting)
    policy = result.canonical_ir.policies[0]

    assert policy.antivirus_profiles == ["av1", "av2"]
    assert policy.vulnerability_profiles == ["v1", "v2"]
    assert policy.antispyware_profiles == ["as1", "as2"]
    assert policy.antivirus is None
    assert policy.ips_sensor is None
    assert policy.migration_status == "NORMALIZED"
    assert policy.requires_manual_review is False
    assert "security-profiles" not in policy.review_reasons


def test_url_category_match_is_canonical_and_preserved_for_panos():
    result = _extract(
        profiles=_profile_definitions(),
        categories="<category><member>custom-cat</member><member>malware</member></category>",
    )
    policy = result.canonical_ir.policies[0]

    assert policy.url_categories == ["custom-cat", "malware"]
    assert policy.url_category_reference_statuses == {
        "category[0]": "custom-resolved",
        "category[1]": "predefined",
    }
    assert policy.migration_status == "NORMALIZED"
    assert policy.requires_manual_review is False

    pan = IRToPANOSTransformer(result.canonical_ir).transform()
    assert pan.vsys.security_rules[0].category == ["custom-cat", "malware"]


@pytest.mark.parametrize(
    ("source_action", "expected"),
    [
        ("allow", PolicyAction.ALLOW),
        ("deny", PolicyAction.DENY),
        ("drop", PolicyAction.DROP),
        ("reset-client", PolicyAction.RESET_CLIENT),
        ("reset-server", PolicyAction.RESET_SERVER),
        ("reset-both", PolicyAction.RESET_BOTH),
    ],
)
def test_exact_pan_actions_are_canonical(source_action, expected):
    result = _extract(action=source_action)
    policy = result.canonical_ir.policies[0]
    assert policy.action == expected
    assert policy.source_action == source_action
    assert policy.migration_status == "NORMALIZED"
    assert policy.requires_manual_review is False

    pan = IRToPANOSTransformer(result.canonical_ir).transform()
    assert pan.vsys.security_rules[0].action == source_action


def test_unsupported_target_action_is_withheld_not_collapsed_to_deny():
    result = _extract(action="reset-both")
    artifacts = FortiGateCLIGenerator().generate(result.canonical_ir)
    output = artifacts[0].content

    assert "Policy Rule1 withheld: target capability does not support policy action reset-both" in output
    assert 'set name "Rule1"' not in output


def test_schema_149_migrates_legacy_scalar_profile_projections():
    migrated = migrate_ir_payload({
        "schema_version": "1.49",
        "metadata": {"source_vendor": "palo_alto"},
        "policies": [{
            "name": "p1",
            "from_zone": ["trust"],
            "to_zone": ["untrust"],
            "source": ["any"],
            "destination": ["any"],
            "service": ["any"],
            "action": "allow",
            "security_profile_group": "g1",
            "antivirus": "av1",
        }],
        "security_profile_groups": [{"name": "g1", "antivirus": "av1"}],
    })

    assert migrated["schema_version"] == "1.50"
    assert migrated["policies"][0]["security_profile_groups"] == ["g1"]
    assert migrated["policies"][0]["antivirus_profiles"] == ["av1"]
    assert migrated["policies"][0]["url_categories"] == []
    assert migrated["security_profile_groups"][0]["antivirus_profiles"] == ["av1"]
'''
write("tests/test_palo_alto_policy_ir_lossless.py", new_tests)

# Update the old fail-closed regression assertions: exact PAN actions are no
# longer parser taint; target portability is tested separately above.
replace_once(
    "tests/test_palo_alto_safety.py",
    '''@pytest.mark.parametrize("source_action", ["drop", "reset-client", "reset-server", "reset-both"])
def test_lossy_deny_action_variants_are_tainted_and_withheld(source_action):
    extraction = _extract(_policy_xml(action=source_action))

    assert len(extraction.canonical_ir.policies) == 1
    policy = extraction.canonical_ir.policies[0]
    assert policy.action == PolicyAction.DENY
    assert policy.source_action == source_action
    assert "source-action-variant" in policy.review_reasons
    assert policy.requires_manual_review is True
    assert policy.safe_for_target_generation is False

    pan = IRToPANOSTransformer(extraction.canonical_ir).transform()
    assert pan.vsys.security_rules == []
    assert any("withheld" in entry.message.lower() for entry in extraction.canonical_ir.audit_entries)
''',
    '''@pytest.mark.parametrize(
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
''',
)
replace_once(
    "tests/test_palo_alto_safety.py",
    '''    original_review = list(policy.review_reasons)

    RuleOptimizer(extraction.canonical_ir).fix_outbound_threat_source_anomalies()

    assert policy.source == original_source
    assert policy.review_reasons == original_review
    assert policy.safe_for_target_generation is False
''',
    '''    original_review = list(policy.review_reasons)

    RuleOptimizer(extraction.canonical_ir).fix_outbound_threat_source_anomalies()

    assert policy.source == original_source
    assert policy.review_reasons == original_review
    # Reset-client is exact canonical semantics and is not the optimizer's
    # generic DENY action, so it remains unchanged without parser taint.
    assert policy.safe_for_target_generation is True
''',
)
replace_once(
    "tests/test_palo_alto_safety.py",
    '''def test_phase2_safety_state_survives_ir_json_round_trip():
    extraction = _extract(_policy_xml(action="reset-client"))
    original = extraction.canonical_ir.policies[0]
    assert original.safe_for_target_generation is False

    restored = IRConfig.model_validate_json(extraction.canonical_ir.model_dump_json())
    policy = restored.policies[0]
    assert policy.source_action == "reset-client"
    assert policy.migration_status == "PARTIALLY_NORMALIZED"
    assert policy.requires_manual_review is True
    assert "source-action-variant" in policy.review_reasons
    assert policy.safe_for_target_generation is False
''',
    '''def test_phase2_safety_state_survives_ir_json_round_trip():
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
''',
)


# ---------------------------------------------------------------------------
# Documentation: make the parser/target boundary explicit for schema 1.50.
# ---------------------------------------------------------------------------
for rel, section in (
    (
        "documentation/IR_DATA_STRUCTURE.md",
        '''\n\n## Schema 1.50 — lossless security-policy profile and action semantics\n\n`IRPolicy.action` preserves `ALLOW`, `DENY`, `DROP`, `RESET_CLIENT`,\n`RESET_SERVER`, and `RESET_BOTH` as distinct canonical actions.  Ordered\n`url_categories` and ordered list-valued security-profile references are\ncanonical policy dimensions.  `IRSecurityProfileGroup` likewise preserves\nall ordered members for each profile family.  Legacy scalar profile fields\nare compatibility projections only when the corresponding list contains\nexactly one member.\n\nTarget generators must perform capability checks.  A target that cannot\nreproduce a canonical action, category match, profile family, or source\ncardinality must withhold the affected rule rather than downgrade the IR or\nmark successful source parsing as partial.\n''',
    ),
    (
        "documentation/EXTRACTION_DATA_MODEL.md",
        '''\n\n### PAN-OS security policy completeness (schema 1.50)\n\nValid PAN-OS security rules with multiple security profile groups, multiple\ndirect profile references, exact drop/reset actions, or URL-category matches\nare `NORMALIZED` when every required source reference is resolved and no other\nunmodeled source semantic is present.  Target incompatibility is evaluated by\nthe generator and does not by itself change source extraction status.\n''',
    ),
    (
        "documentation/PANOS_PHASE2_FAIL_CLOSED.md",
        '''\n\n## Schema 1.50 update\n\nThe earlier fail-closed treatment of PAN-OS `drop` and `reset-*` as lossy\n`DENY` projections is superseded by schema 1.50.  These actions are now\nrepresented exactly in canonical IR.  Fail-closed behavior remains mandatory,\nbut is applied by target capability checks when a target cannot reproduce the\nexact action.  The same parser/target boundary applies to canonical URL\ncategory matches and list-valued security-profile assignments.\n''',
    ),
):
    text = read(rel)
    marker = section.strip().splitlines()[0]
    if marker not in text:
        write(rel, text.rstrip() + section + "\n")

print("PAN-OS policy IR lossless patch applied successfully")
