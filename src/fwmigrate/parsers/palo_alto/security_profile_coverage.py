"""Coverage for PAN-OS Security Policy profile families missing from the base parser.

PAN-OS permits GTP, SCTP, and AI Security profiles in Security Policy direct
profile assignments and Security Profile Groups.  The older parser path only
recognized the traditional threat-profile families in those two locations.

This layer deliberately keeps the three families source-oriented: their
references and definitions are parsed, ordered, scope-resolved, and audited,
but they are not projected into unrelated portable IR fields.  That preserves
source semantics without implying target-vendor equivalence.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any, Dict, List

from fwmigrate.extraction.models import ExtractionStatus

from . import security_profiles as _security_profiles
from .source_model import PANScope
from .xml_utils import member_texts


# Families documented by PAN-OS for Security Policy profile-setting/profiles
# and profile-group membership that are not represented by the legacy typed
# profile fields in IRPolicy / IRSecurityProfileGroup.
ADDITIONAL_POLICY_SECURITY_PROFILE_FAMILIES = (
    "gtp",
    "sctp",
    "ai-security",
)

# GTP and SCTP definitions were already recognized by security_profiles.py.
# AI Security definitions use the same source-oriented definition extractor,
# so extend the runtime family inventory before any scope is parsed.  Keeping
# this here avoids teaching the generic definition parser false portable
# semantics; _definition() still retains the complete XML field inventory.
if "ai-security" not in _security_profiles.PROFILE_FAMILIES:
    _security_profiles.PROFILE_FAMILIES = (
        *_security_profiles.PROFILE_FAMILIES,
        "ai-security",
    )


class PANOSSecurityProfileCoverageMixin:
    """Post-process the registered PAN-OS parser for newer profile families."""

    @staticmethod
    def _additional_direct_profiles(entry: ET.Element) -> Dict[str, List[str]]:
        profiles = {
            family: member_texts(
                entry,
                f"./profile-setting/profiles/{family}/member",
            )
            for family in ADDITIONAL_POLICY_SECURITY_PROFILE_FAMILIES
        }
        return {family: values for family, values in profiles.items() if values}

    def _resolve_additional_profiles(
        self,
        scope: PANScope,
        profiles: Dict[str, List[str]],
    ) -> tuple[Dict[str, List[str]], Dict[str, List[str]], Dict[str, str]]:
        canonical: Dict[str, List[str]] = {}
        unresolved: Dict[str, List[str]] = {}
        statuses: Dict[str, str] = {}

        for family, values in profiles.items():
            for index, value in enumerate(values):
                resolved = self.resolver.resolve(
                    value,
                    f"security-profile:{family}",
                    scope,
                )
                if resolved is None:
                    canonical_value = value
                    unresolved.setdefault(family, []).append(value)
                    statuses[f"{family}[{index}]"] = "unresolved"
                else:
                    canonical_value = resolved.canonical_name or value
                    statuses[f"{family}[{index}]"] = "resolved"
                canonical.setdefault(family, []).append(canonical_value)

        return canonical, unresolved, statuses

    @staticmethod
    def _remove_recognized_unknown_profile_types(evidence: Dict[str, Any]) -> bool:
        """Remove only the newly recognized family nodes from unknown evidence.

        Returns True when other unknown profile-setting content remains.
        """
        unknown = evidence.get("pan_unknown_direct_profile_types")
        if isinstance(unknown, dict):
            for family in ADDITIONAL_POLICY_SECURITY_PROFILE_FAMILIES:
                unknown.pop(family, None)
            if unknown:
                evidence["pan_unknown_direct_profile_types"] = unknown
            else:
                evidence.pop("pan_unknown_direct_profile_types", None)

        return bool(
            evidence.get("pan_unknown_profile_setting")
            or evidence.get("pan_unknown_direct_profile_types")
        )

    @staticmethod
    def _strip_reason(review_reasons: List[str], reason: str) -> None:
        while reason in review_reasons:
            review_reasons.remove(reason)

    def _augment_security_policy(
        self,
        scope: PANScope,
        entry: ET.Element,
        extraction,
        policy,
    ) -> None:
        direct_profiles = self._additional_direct_profiles(entry)
        if not direct_profiles:
            return

        canonical, unresolved, statuses = self._resolve_additional_profiles(
            scope,
            direct_profiles,
        )
        evidence = policy.source_extra_settings

        # Merge into the same source evidence maps used by the traditional
        # profile families.  Source member order is retained exactly.
        all_direct = dict(evidence.get("pan_direct_profiles", {}))
        all_direct.update(direct_profiles)
        evidence["pan_direct_profiles"] = all_direct
        evidence["pan_additional_security_profiles"] = canonical

        resolved_evidence = dict(evidence.get("pan_resolved_direct_profiles", {}))
        unresolved_evidence = dict(evidence.get("pan_unresolved_direct_profiles", {}))
        for family, values in canonical.items():
            unresolved_values = set(unresolved.get(family, []))
            resolved_values = [
                canonical_value
                for source_value, canonical_value in zip(direct_profiles[family], values)
                if source_value not in unresolved_values
            ]
            if resolved_values:
                resolved_evidence[family] = resolved_values
        for family, values in unresolved.items():
            unresolved_evidence[family] = values

        if resolved_evidence:
            evidence["pan_resolved_direct_profiles"] = resolved_evidence
        if unresolved_evidence:
            evidence["pan_unresolved_direct_profiles"] = unresolved_evidence
        else:
            evidence.pop("pan_unresolved_direct_profiles", None)

        other_unknown_profile_content = self._remove_recognized_unknown_profile_types(
            evidence
        )
        if not other_unknown_profile_content:
            self._strip_reason(policy.review_reasons, "unknown-profile-fields")

        # Existing completeness fields are intentionally generic and therefore
        # suitable for these newer families without changing the IR schema.
        refs = dict(policy.source_security_profile_references)
        ref_statuses = dict(policy.security_profile_reference_statuses)
        unresolved_refs = dict(policy.unresolved_security_profile_references)
        for family, values in direct_profiles.items():
            for index, value in enumerate(values):
                key = f"{family}[{index}]"
                refs[key] = value
                ref_statuses[key] = statuses[key]
                if statuses[key] == "unresolved":
                    unresolved_refs[key] = value
                else:
                    unresolved_refs.pop(key, None)

        policy.source_security_profile_references = refs
        policy.security_profile_reference_statuses = ref_statuses
        policy.unresolved_security_profile_references = unresolved_refs

        for values in unresolved.values():
            for value in values:
                if value not in policy.unresolved_security_profiles:
                    policy.unresolved_security_profiles.append(value)

        if unresolved:
            if "unresolved-security-profiles" not in policy.review_reasons:
                policy.review_reasons.append("unresolved-security-profiles")
        else:
            # Do not remove the reason when a traditional family is unresolved.
            old_unresolved = evidence.get("pan_unresolved_direct_profiles", {})
            old_unresolved = {
                family: values
                for family, values in old_unresolved.items()
                if family not in ADDITIONAL_POLICY_SECURITY_PROFILE_FAMILIES
            }
            if not old_unresolved and not evidence.get("pan_unresolved_profile_group"):
                self._strip_reason(policy.review_reasons, "unresolved-security-profiles")

        # The references are now fully parsed and resolved, but no portable IR
        # field claims GTP/SCTP/AI Security semantic equivalence.  Keep this
        # distinction explicit for target-generation safety.
        if "source-specific-security-profile-family" not in policy.review_reasons:
            policy.review_reasons.append("source-specific-security-profile-family")
        policy.security_profile_semantics_review = True

        profile_groups = evidence.get("pan_profile_groups", [])
        if profile_groups and all_direct:
            policy.source_profile_type = "mixed"
            if "mixed-profile-assignment" not in policy.review_reasons:
                policy.review_reasons.append("mixed-profile-assignment")
        elif all_direct:
            policy.source_profile_type = "profiles"

        policy.requires_manual_review = True
        policy.migration_status = "PARTIALLY_NORMALIZED"

        item = self._inventory_item(
            extraction,
            "policies",
            scope,
            entry.get("name"),
        )
        if item is not None:
            item.source_attributes.update(evidence)
            item.status = ExtractionStatus.PARTIALLY_NORMALIZED
            item.requires_manual_review = True
            if not other_unknown_profile_content:
                item.notes = [
                    note
                    for note in item.notes
                    if "unknown-profile-fields" not in note
                ]
            note = (
                "PAN-OS GTP/SCTP/AI Security profile references are parsed and "
                "scope-resolved but remain source-specific for target migration."
            )
            if note not in item.notes:
                item.notes.append(note)

    def _augment_profile_groups(
        self,
        scope: PANScope,
        search_root: ET.Element,
        extraction,
    ) -> None:
        for entry in search_root.findall("./profile-group/entry"):
            name = entry.get("name")
            if not name:
                continue

            source_members = {
                family: member_texts(entry, f"./{family}/member")
                for family in ADDITIONAL_POLICY_SECURITY_PROFILE_FAMILIES
            }
            source_members = {
                family: values
                for family, values in source_members.items()
                if values
            }
            if not source_members:
                continue

            resolved_group = self.resolver.resolve_exact(
                name,
                "profile-group",
                scope,
            )
            if resolved_group is None or resolved_group.ir_object is None:
                continue
            group = resolved_group.ir_object

            canonical, unresolved, statuses = self._resolve_additional_profiles(
                scope,
                source_members,
            )
            evidence = group.source_attributes

            all_members = dict(evidence.get("pan_profile_members", {}))
            all_members.update(source_members)
            evidence["pan_profile_members"] = all_members
            evidence["pan_additional_profile_members"] = canonical
            evidence["pan_additional_profile_reference_statuses"] = statuses
            evidence["pan_source_only_profile_families"] = list(source_members)

            resolved_members = dict(evidence.get("pan_resolved_profile_members", {}))
            unresolved_members = dict(evidence.get("pan_unresolved_profile_members", {}))
            for family, canonical_values in canonical.items():
                unresolved_values = set(unresolved.get(family, []))
                resolved_values = [
                    canonical_value
                    for source_value, canonical_value in zip(
                        source_members[family],
                        canonical_values,
                    )
                    if source_value not in unresolved_values
                ]
                if resolved_values:
                    resolved_members[family] = resolved_values
            for family, values in unresolved.items():
                unresolved_members[family] = values
            if resolved_members:
                evidence["pan_resolved_profile_members"] = resolved_members
            if unresolved_members:
                evidence["pan_unresolved_profile_members"] = unresolved_members
            else:
                evidence.pop("pan_unresolved_profile_members", None)

            unknown = evidence.get("pan_unknown_fields")
            if isinstance(unknown, dict):
                for family in ADDITIONAL_POLICY_SECURITY_PROFILE_FAMILIES:
                    unknown.pop(family, None)
                if unknown:
                    evidence["pan_unknown_fields"] = unknown
                else:
                    evidence.pop("pan_unknown_fields", None)

            refs = dict(group.source_profile_references)
            for family, values in source_members.items():
                for index, value in enumerate(values):
                    refs[f"{family}[{index}]"] = value
            group.source_profile_references = refs
            group.source_attributes = evidence

            # Definitions and references are fully extracted.  These three
            # families remain source-only because IRSecurityProfileGroup has no
            # portable semantic fields for them.
            group.requires_manual_review = True
            group.migration_status = "PARTIALLY_NORMALIZED"

            item = self._inventory_item(
                extraction,
                "profile_groups",
                scope,
                name,
            )
            if item is not None:
                item.source_attributes.update(evidence)
                item.status = ExtractionStatus.PARTIALLY_NORMALIZED
                item.requires_manual_review = True
                item.notes = [
                    note
                    for note in item.notes
                    if "unknown-fields" not in note
                ]
                note = (
                    "GTP/SCTP/AI Security profile-group members are parsed and "
                    "scope-resolved but remain source-specific for target migration."
                )
                if unresolved:
                    note += " One or more profile references are unresolved."
                if note not in item.notes:
                    item.notes.append(note)

    def _augment_default_security_rule(
        self,
        scope: PANScope,
        entry: ET.Element,
        extraction,
    ) -> None:
        direct_profiles = self._additional_direct_profiles(entry)
        if not direct_profiles:
            return
        item = self._inventory_item(
            extraction,
            "default_security_rules",
            scope,
            entry.get("name"),
        )
        if item is None:
            return
        evidence = item.source_attributes
        all_direct = dict(evidence.get("pan_direct_profiles", {}))
        all_direct.update(direct_profiles)
        evidence["pan_direct_profiles"] = all_direct
        _canonical, unresolved, statuses = self._resolve_additional_profiles(
            scope,
            direct_profiles,
        )
        evidence["pan_additional_profile_reference_statuses"] = statuses
        if unresolved:
            evidence["pan_unresolved_additional_direct_profiles"] = unresolved

    def _parse_objects(self, scope: PANScope, search_root: ET.Element, extraction):
        # AI Security profile definitions are recognized by the shared
        # source-oriented profile extractor through the runtime family extension
        # above.  Run the normal parser first so all definitions are registered
        # before resolving profile-group members.
        super()._parse_objects(scope, search_root, extraction)
        self._augment_profile_groups(scope, search_root, extraction)

    def _parse_security_rule(
        self,
        scope: PANScope,
        entry: ET.Element,
        extraction,
        rulebase_position: str,
        source_rule_index: int,
        path_prefix: str,
    ):
        before = len(extraction.canonical_ir.policies)
        super()._parse_security_rule(
            scope,
            entry,
            extraction,
            rulebase_position,
            source_rule_index,
            path_prefix,
        )
        if len(extraction.canonical_ir.policies) == before:
            return
        self._augment_security_policy(
            scope,
            entry,
            extraction,
            extraction.canonical_ir.policies[-1],
        )

    def _parse_default_security_rule(
        self,
        scope: PANScope,
        entry: ET.Element,
        extraction,
        position: str,
        source_index: int,
        prefix: str,
    ) -> None:
        super()._parse_default_security_rule(
            scope,
            entry,
            extraction,
            position,
            source_index,
            prefix,
        )
        self._augment_default_security_rule(scope, entry, extraction)
