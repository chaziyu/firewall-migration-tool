"""PAN-OS extraction pipeline kept behind the public parser facade."""
from __future__ import annotations

from typing import Dict, Optional

from .completeness import PANOSSourceParser as _CompletenessPANOSSourceParser
from .ipv6_nat_compatibility import PANOSIPv6NATCompatibilityMixin
from .ipv6_nat_coverage import PANOSIPv6NATSemanticsCoverageMixin
from .ipv6_nat_interface_refinement import PANOSIPv6NATInterfaceRefinementMixin
from .panorama_stages import finalize_pan_extraction
from .transformer import PANToIRTransformer as _PANToIRTransformer
from .policy_nat_coverage import PANOSSourceParser as _CoveragePANOSSourceParser
from .safe_completeness import PANOSSourceParser as _SafePANOSSourceParser
from .nat_interface_address_coverage import PANOSNATInterfaceAddressCoverageMixin
from .security_profile_coverage import PANOSSecurityProfileCoverageMixin
from .security_profile_group_safety import PANOSSecurityProfileGroupPolicySafetyMixin


class PANOSecurityProfileProcessor:
    """Explicit processor for source-only PAN-OS profile families."""

    def __init__(self, parser):
        self.parser = parser
        self.resolver = parser.resolver

    _inventory_item = staticmethod(_CompletenessPANOSSourceParser._inventory_item)
    _additional_direct_profiles = staticmethod(
        PANOSSecurityProfileCoverageMixin._additional_direct_profiles
    )
    _remove_recognized_unknown_profile_types = staticmethod(
        PANOSSecurityProfileCoverageMixin._remove_recognized_unknown_profile_types
    )
    _strip_reason = staticmethod(PANOSSecurityProfileCoverageMixin._strip_reason)
    _resolve_additional_profiles = PANOSSecurityProfileCoverageMixin._resolve_additional_profiles

    def augment_security_policy(self, scope, entry, extraction, policy) -> None:
        PANOSSecurityProfileCoverageMixin._augment_security_policy(
            self, scope, entry, extraction, policy
        )

    def augment_profile_groups(self, scope, search_root, extraction) -> None:
        PANOSSecurityProfileCoverageMixin._augment_profile_groups(
            self, scope, search_root, extraction
        )

    def augment_default_security_rule(self, scope, entry, extraction) -> None:
        PANOSSecurityProfileCoverageMixin._augment_default_security_rule(
            self, scope, entry, extraction
        )

    def mark_source_only_profile_group_policy(self, scope, entry, extraction, policy) -> None:
        PANOSSecurityProfileGroupPolicySafetyMixin._mark_source_only_profile_group_policy(
            self, scope, entry, extraction, policy
        )


class PANOSExtractionPipeline(_PANToIRTransformer):
    """Run PAN-OS domain stages in a stable, explicit order.

    The older modules remain import-compatible, but their multiple-inheritance
    chain is not part of this runtime class. Each stage calls the existing
    domain implementation directly.
    """

    _inventory_item = staticmethod(_CompletenessPANOSSourceParser._inventory_item)
    _target_details = staticmethod(_CompletenessPANOSSourceParser._target_details)
    _zone_source_attributes = staticmethod(
        _CompletenessPANOSSourceParser._zone_source_attributes
    )
    _parse_interface_address = staticmethod(
        _CompletenessPANOSSourceParser._parse_interface_address
    )
    _unwrap_config = staticmethod(_CompletenessPANOSSourceParser._unwrap_config)
    _unwrap_source_config = staticmethod(_CoveragePANOSSourceParser._unwrap_source_config)
    _configured_zone_types = staticmethod(
        _CoveragePANOSSourceParser._configured_zone_types
    )
    _panorama_template_entries = staticmethod(
        _CoveragePANOSSourceParser._panorama_template_entries
    )
    _inventory_order_map = staticmethod(
        _CoveragePANOSSourceParser._inventory_order_map
    )
    _target_applicability = staticmethod(
        _CoveragePANOSSourceParser._target_applicability
    )
    _compat_nat_family = staticmethod(
        PANOSIPv6NATCompatibilityMixin._compat_nat_family
    )
    _legacy_marker_required = staticmethod(
        PANOSIPv6NATCompatibilityMixin._legacy_marker_required
    )
    _nat_family_value = staticmethod(
        PANOSIPv6NATSemanticsCoverageMixin._nat_family_value
    )
    _literal_address_family = staticmethod(
        PANOSIPv6NATSemanticsCoverageMixin._literal_address_family
    )
    _translation_values = staticmethod(
        PANOSIPv6NATSemanticsCoverageMixin._translation_values
    )
    _resolved_selector_values = PANOSIPv6NATSemanticsCoverageMixin._resolved_selector_values
    _selector_family_summary = staticmethod(
        PANOSIPv6NATSemanticsCoverageMixin._selector_family_summary
    )
    _nptv6_prefix_validation = staticmethod(
        PANOSIPv6NATSemanticsCoverageMixin._nptv6_prefix_validation
    )
    _nptv6_selector_validation = staticmethod(
        PANOSIPv6NATSemanticsCoverageMixin._nptv6_selector_validation
    )
    _has_invalid_records = staticmethod(
        PANOSIPv6NATSemanticsCoverageMixin._has_invalid_records
    )
    _remove_reason = staticmethod(PANOSIPv6NATSemanticsCoverageMixin._remove_reason)
    _interface_address_families = staticmethod(
        PANOSIPv6NATInterfaceRefinementMixin._interface_address_families
    )
    _interface_address_values = staticmethod(
        PANOSNATInterfaceAddressCoverageMixin._interface_address_values
    )
    _validate_interface_address_values = staticmethod(
        PANOSNATInterfaceAddressCoverageMixin._validate_interface_address_values
    )
    _remove_review_reason = staticmethod(
        PANOSNATInterfaceAddressCoverageMixin._remove_review_reason
    )
    _interface_address_review_reasons = (
        PANOSNATInterfaceAddressCoverageMixin._interface_address_review_reasons
    )
    _selection_from_details = staticmethod(
        PANOSNATInterfaceAddressCoverageMixin._selection_from_details
    )
    _sync_source_translation_semantics = (
        PANOSNATInterfaceAddressCoverageMixin._sync_source_translation_semantics
    )
    _parse_complete_interface_address = (
        PANOSNATInterfaceAddressCoverageMixin._parse_complete_interface_address
    )
    _resolve_tag_references = _CompletenessPANOSSourceParser._resolve_tag_references
    _resolve_interface_reference = _CompletenessPANOSSourceParser._resolve_interface_reference
    _nat64_semantics = PANOSIPv6NATInterfaceRefinementMixin._nat64_semantics
    _nptv6_semantics = PANOSIPv6NATInterfaceRefinementMixin._nptv6_semantics

    def _security_profile_processor(self) -> PANOSecurityProfileProcessor:
        processor = getattr(self, "_pan_security_profile_processor", None)
        if processor is None:
            processor = PANOSecurityProfileProcessor(self)
            self._pan_security_profile_processor = processor
        return processor

    def _parse_objects(self, scope, search_root, extraction):
        _CompletenessPANOSSourceParser._parse_objects(
            self, scope, search_root, extraction
        )
        self._security_profile_processor().augment_profile_groups(
            scope, search_root, extraction
        )

    def _parse_security_rule(
        self, scope, entry, extraction, rulebase_position, source_rule_index, path_prefix
    ):
        before = len(extraction.canonical_ir.policies)
        _CompletenessPANOSSourceParser._parse_security_rule(
            self,
            scope,
            entry,
            extraction,
            rulebase_position,
            source_rule_index,
            path_prefix,
        )
        if len(extraction.canonical_ir.policies) == before:
            return
        policy = extraction.canonical_ir.policies[-1]
        processor = self._security_profile_processor()
        processor.augment_security_policy(scope, entry, extraction, policy)
        processor.mark_source_only_profile_group_policy(
            scope, entry, extraction, policy
        )

    def _parse_default_security_rule(
        self, scope, entry, extraction, position, source_index, prefix
    ) -> None:
        _PANToIRTransformer._parse_default_security_rule(
            self, scope, entry, extraction, position, source_index, prefix
        )
        self._security_profile_processor().augment_default_security_rule(
            scope, entry, extraction
        )

    def _parse_schedules(self, scope, search_root, extraction):
        _SafePANOSSourceParser._parse_schedules(
            self, scope, search_root, extraction
        )

    def _parse_rules(self, scope, search_root, extraction):
        _CompletenessPANOSSourceParser._parse_rules(
            self, scope, search_root, extraction
        )

    def _enhance_security_policy(self, scope, entry, extraction, policy) -> None:
        _SafePANOSSourceParser._enhance_security_policy(
            self, scope, entry, extraction, policy
        )

    def _enhance_zones(self, scope, search_root, extraction, zones) -> None:
        _CoveragePANOSSourceParser._enhance_zones(
            self, scope, search_root, extraction, zones
        )

    def _enhance_profile_groups(self, scope, extraction, groups) -> None:
        _SafePANOSSourceParser._enhance_profile_groups(
            self, scope, extraction, groups
        )

    def _enhance_nat_rule(self, scope, entry, extraction, rule) -> None:
        PANOSIPv6NATCompatibilityMixin._enhance_nat_rule(
            self, scope, entry, extraction, rule
        )

    def _enhance_interfaces(self, extraction) -> None:
        _SafePANOSSourceParser._enhance_interfaces(self, extraction)

    def _extract_template_interfaces(self, content, extraction) -> None:
        _CoveragePANOSSourceParser._extract_template_interfaces(
            self, content, extraction
        )

    def _apply_target_applicability_base(self, extraction) -> None:
        _CoveragePANOSSourceParser._apply_target_applicability(self, extraction)

    def extract(self, content: str, zone_mapping: Optional[Dict[str, str]] = None):
        extraction = _PANToIRTransformer.transform(self, content, zone_mapping)
        self._extract_template_interfaces(content, extraction)
        self._enhance_interfaces(extraction)
        _CoveragePANOSSourceParser._extract_panorama_vsys_rule_views(
            self, content, extraction
        )
        return finalize_pan_extraction(self, extraction)
