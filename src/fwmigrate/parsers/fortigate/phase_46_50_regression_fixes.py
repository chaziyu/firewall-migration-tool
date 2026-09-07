"""Regression hardening for FortiGate phases 46-50.

These fixes preserve the Phase 46-50 extraction behavior while keeping
pre-existing context, dependency, coverage, and source-safety contracts intact.
"""

from __future__ import annotations

from typing import Any, List

from fwmigrate.parsers.fortigate.extraction import sanitize_source_attributes
from fwmigrate.parsers.fortigate.model import FGSSLSSHCertificate
from fwmigrate.parsers.fortigate.phase_41_security_profiles import (
    _effective_node_attributes,
)
from fwmigrate.parsers.fortigate.source_tree import FGSourceNode


_PROFILE_GROUP_NESTED_TARGETS = {
    "ssh-filter-profile": {
        "ssh-filter profile",
        "firewall profile-group ssh-filter",
    },
    "diameter-filter-profile": {
        "diameter-filter profile",
        "firewall profile-group diameter-filter",
    },
    "sctp-filter-profile": {
        "sctp-filter profile",
        "firewall profile-group sctp-filter",
    },
    "videofilter-profile": {
        "videofilter profile",
        "firewall profile-group videofilter",
    },
}

_SSL_CERTIFICATE_SPEC = {
    "scalar_fields": {"certificate", "status"},
}

_IPS_COVERAGE_PATHS = {
    "ips sensor",
    "ips sensor entries",
    "ips sensor entries exempt-ip",
}


def _install_dependency_target_compatibility(dependencies_module: Any) -> None:
    """Keep legacy nested profile-group targets valid alongside top-level ones."""

    for field, targets in _PROFILE_GROUP_NESTED_TARGETS.items():
        key = ("firewall profile-group", field)
        dependencies_module.REFERENCE_TARGET_SECTIONS[key] = set(targets)


def _install_parser_regressions(parser_module: Any) -> None:
    """Restore source context and exact certificate-section typing."""

    parser_cls = parser_module.FortiGateParser
    current = parser_cls._build_structured_typed_parents
    if getattr(current, "_phase_46_50_regression_wrapped", False):
        return

    def build_structured_typed_parents(
        self: Any,
        source_path: str,
        top_edits: List[FGSourceNode],
    ) -> None:
        ips_before = len(self.config.ips_sensors)
        ssl_before = len(self.config.ssl_ssh_profiles)
        current(self, source_path, top_edits)

        if source_path == "ips sensor":
            context = self.current_context or "root"
            for sensor in self.config.ips_sensors[ips_before:]:
                # FGIPSSensor is contextual.  Phase 46 must not collapse VDOM
                # identity to the model default of root.
                sensor.source_context = context

        if source_path != "firewall ssl-ssh-profile":
            return

        new_profiles = self.config.ssl_ssh_profiles[ssl_before:]
        for source, profile in zip(top_edits, new_profiles):
            # Phase 47 uses an exact hierarchy.  ``certificate`` is a known
            # legacy/documented child and must be typed explicitly; similarly
            # named future sections remain generic source evidence.
            certificate_nodes = [
                child
                for child in source.children
                if child.node_type == "config" and child.name.lower() == "certificate"
            ]
            if not certificate_nodes:
                continue

            profile.entries = [
                entry for entry in profile.entries if entry.name.lower() != "certificate"
            ]
            for certificate_node in certificate_nodes:
                for entry in certificate_node.children:
                    if entry.node_type != "edit":
                        continue
                    values, extra = _effective_node_attributes(
                        entry,
                        field_spec=_SSL_CERTIFICATE_SPEC,
                    )
                    profile.certificates.append(
                        FGSSLSSHCertificate(
                            name=entry.name,
                            certificate=values.get("certificate"),
                            status=values.get("status"),
                            extra_settings=sanitize_source_attributes(extra),
                        )
                    )

    build_structured_typed_parents._phase_46_50_regression_wrapped = True
    parser_cls._build_structured_typed_parents = build_structured_typed_parents


def _install_coverage_regressions(coverage_module: Any) -> None:
    """Keep IPS typed-extract-only classification after structured registration."""

    for path in _IPS_COVERAGE_PATHS:
        coverage_module.SEMANTIC_SUPPORT_LEVELS[path] = "TYPED_EXTRACT_ONLY"


def _install_extractor_regressions(extractor_module: Any) -> None:
    current = extractor_module.extract_fortigate_config
    if getattr(current, "_phase_46_50_regression_wrapped", False):
        return

    def extract_fortigate_config(*args: Any, **kwargs: Any) -> Any:
        result = current(*args, **kwargs)

        # Phase 46 is still typed extract-only.  Moving its parser to the
        # recursive source tree must not change public coverage accounting.
        # A successfully structured IPS object/entry is represented in the
        # Phase 46 typed projection one-for-one with the scanner's source
        # object count, even though it deliberately remains EXTRACT_ONLY.
        for section in result.source_sections:
            if section.path not in _IPS_COVERAGE_PATHS:
                continue
            section.parser_handler = "FortiGateParser.build_model"
            if section.object_count_source is not None:
                if section.object_count_parsed is None:
                    section.object_count_parsed = section.object_count_source
                if section.object_count_normalized is None:
                    section.object_count_normalized = section.object_count_source
            section.notes = [
                note
                for note in section.notes
                if not note.startswith("Semantic support level:")
            ]
            section.notes.append("Semantic support level: TYPED_EXTRACT_ONLY")

        # Phase 49 can classify a documented IPv6 subtree as fully typed for
        # extraction while the IR still correctly requires target-platform
        # review for source-specific nested behavior.  Retain the historical
        # generation blocker in that case instead of conflating extraction
        # coverage with portability.
        reviewed_nested_ipv6 = any(
            interface.requires_manual_review
            and any(node.name == "ipv6" for node in interface.nested_source_configs)
            for interface in result.canonical_ir.interfaces
        )
        nested_reason = (
            "FortiGate nested interface configuration contains source-specific "
            "IPv6 behavior requiring target-platform review"
        )
        if reviewed_nested_ipv6 and not any(
            "nested interface configuration" in reason
            for reason in result.blocking_reasons
        ):
            result.blocking_reasons.append(nested_reason)
            result.requires_manual_review = True
            result.migration_complete = False
            result.generation_safe = False
            result.canonical_ir.requires_manual_review = True
            result.canonical_ir.generation_safe = False
            if nested_reason not in result.canonical_ir.generation_blocking_reasons:
                result.canonical_ir.generation_blocking_reasons.append(nested_reason)

        return result

    extract_fortigate_config._phase_46_50_regression_wrapped = True
    extractor_module.extract_fortigate_config = extract_fortigate_config


def install_phase_46_50_regression_fixes(
    parser_module: Any,
    dependencies_module: Any,
    extractor_module: Any,
    coverage_module: Any,
) -> None:
    """Install regression fixes after the Phase 46-50 and Phase 48 wrappers."""

    _install_dependency_target_compatibility(dependencies_module)
    _install_parser_regressions(parser_module)
    _install_coverage_regressions(coverage_module)
    _install_extractor_regressions(extractor_module)
