"""Safety propagation for policies using source-only PAN-OS profile families."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from fwmigrate.extraction.models import ExtractionStatus

from .source_model import PANScope
from .xml_utils import member_texts


class PANOSSecurityProfileGroupPolicySafetyMixin:
    """Mark policies when a referenced profile group has PAN-specific families.

    GTP, SCTP, and AI Security group members are now fully extracted and
    scope-resolved, but the portable profile-group IR has no equivalent typed
    semantic fields.  Propagate that source-only status to the consuming policy
    so target generation cannot mistake an apparently resolved group for a
    lossless portable bundle.
    """

    def _mark_source_only_profile_group_policy(
        self,
        scope: PANScope,
        entry: ET.Element,
        extraction,
        policy,
    ) -> None:
        group_names = member_texts(entry, "./profile-setting/group/member")
        if not group_names:
            return

        source_only_groups = {}
        for group_name in group_names:
            resolved = self.resolver.resolve(group_name, "profile-group", scope)
            if resolved is None or resolved.ir_object is None:
                continue
            families = resolved.ir_object.source_attributes.get(
                "pan_source_only_profile_families",
                [],
            )
            if families:
                source_only_groups[group_name] = list(families)

        if not source_only_groups:
            return

        policy.source_extra_settings[
            "pan_source_only_profile_group_families"
        ] = source_only_groups
        policy.security_profile_semantics_review = True
        if "source-specific-security-profile-group-family" not in policy.review_reasons:
            policy.review_reasons.append(
                "source-specific-security-profile-group-family"
            )
        policy.requires_manual_review = True
        policy.migration_status = "PARTIALLY_NORMALIZED"

        item = self._inventory_item(
            extraction,
            "policies",
            scope,
            entry.get("name"),
        )
        if item is not None:
            item.source_attributes.update(policy.source_extra_settings)
            item.status = ExtractionStatus.PARTIALLY_NORMALIZED
            item.requires_manual_review = True
            note = (
                "Referenced PAN-OS profile group contains GTP/SCTP/AI Security "
                "members that are parsed and resolved but remain source-specific "
                "for target migration."
            )
            if note not in item.notes:
                item.notes.append(note)

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
        self._mark_source_only_profile_group_policy(
            scope,
            entry,
            extraction,
            extraction.canonical_ir.policies[-1],
        )
