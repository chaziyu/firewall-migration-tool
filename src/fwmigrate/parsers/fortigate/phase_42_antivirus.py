"""Phase 42 FortiGate antivirus profile typing.

This module extends the Phase 41 operation-aware profile evaluator with
FortiOS 7.4.6 antivirus-specific field declarations and typed projections.
The recursive FGSourceNode tree remains authoritative and unchanged.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fwmigrate.parsers.fortigate import phase_41_security_profiles as phase41
from fwmigrate.parsers.fortigate.model import (
    FGAntivirusProfile as _FGAntivirusProfile,
    FGAntivirusProfileConfig as _FGAntivirusProfileConfig,
    FGAntivirusProtocol as _FGAntivirusProtocol,
)
from fwmigrate.parsers.fortigate.source_tree import FGSourceNode


class FGAntivirusProfileConfig746(_FGAntivirusProfileConfig):
    """Typed non-protocol AV child config, including CDR and NAC quarantine."""

    cover_page: Optional[str] = None
    detect_only: Optional[str] = None
    error_action: Optional[str] = None
    office_action: Optional[str] = None
    office_dde: Optional[str] = None
    office_embed: Optional[str] = None
    office_hylink: Optional[str] = None
    office_linked: Optional[str] = None
    office_macro: Optional[str] = None
    original_file_destination: Optional[str] = None
    pdf_act_form: Optional[str] = None
    pdf_act_gotor: Optional[str] = None
    pdf_act_java: Optional[str] = None
    pdf_act_launch: Optional[str] = None
    pdf_act_movie: Optional[str] = None
    pdf_act_sound: Optional[str] = None
    pdf_embedfile: Optional[str] = None
    pdf_hyperlink: Optional[str] = None
    pdf_javacode: Optional[str] = None
    expiry: Optional[str] = None
    infected: Optional[str] = None


class FGAntivirusProtocol746(_FGAntivirusProtocol):
    """FortiOS 7.4.6 protocol-specific antivirus scan semantics."""

    archive_block: List[str] = []
    archive_log: List[str] = []
    av_scan: Optional[str] = None
    content_disarm: Optional[str] = None
    emulator: Optional[str] = None
    executables: Optional[str] = None
    external_blocklist: Optional[str] = None
    fortindr: Optional[str] = None
    fortisandbox: Optional[str] = None
    outbreak_prevention: Optional[str] = None
    quarantine: Optional[str] = None
    configs: List[FGAntivirusProfileConfig746] = []


class FGAntivirusProfile746(_FGAntivirusProfile):
    """FortiOS 7.4.6 antivirus profile-level typed semantics."""

    analytics_accept_filetype: Optional[int] = None
    analytics_db: Optional[str] = None
    analytics_ignore_filetype: Optional[int] = None
    av_virus_log: Optional[str] = None
    ems_threat_feed: Optional[str] = None
    extended_log: Optional[str] = None
    external_blocklist: List[str] = []
    external_blocklist_enable_all: Optional[str] = None
    feature_set: Optional[str] = None
    fortindr_error_action: Optional[str] = None
    fortindr_timeout_action: Optional[str] = None
    fortisandbox_error_action: Optional[str] = None
    fortisandbox_max_upload: Optional[int] = None
    fortisandbox_mode: Optional[str] = None
    fortisandbox_timeout_action: Optional[str] = None
    mobile_malware_db: Optional[str] = None
    outbreak_prevention_archive_scan: Optional[str] = None
    replacemsg_group: Optional[str] = None
    scan_mode: Optional[str] = None
    protocols: List[FGAntivirusProtocol746] = []
    configs: List[FGAntivirusProfileConfig746] = []


_AV_PROTOCOLS = {
    "cifs",
    "ftp",
    "http",
    "imap",
    "mapi",
    "nntp",
    "pop3",
    "smtp",
    "ssh",
}

_AV_PROFILE_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {
        "comment",
        "status",
        "inspection_mode",
        "analytics_db",
        "av_virus_log",
        "ems_threat_feed",
        "extended_log",
        "external_blocklist_enable_all",
        "feature_set",
        "fortindr_error_action",
        "fortindr_timeout_action",
        "fortisandbox_error_action",
        "fortisandbox_mode",
        "fortisandbox_timeout_action",
        "mobile_malware_db",
        "outbreak_prevention_archive_scan",
        "replacemsg_group",
        "scan_mode",
    },
    "list_fields": {"external_blocklist"},
    "integer_fields": {
        "analytics_accept_filetype",
        "analytics_ignore_filetype",
        "fortisandbox_max_upload",
    },
}

_AV_PROTOCOL_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {
        "status",
        "action",
        "scan",
        "comment",
        "av_scan",
        "content_disarm",
        "emulator",
        "executables",
        "external_blocklist",
        "fortindr",
        "fortisandbox",
        "outbreak_prevention",
        "quarantine",
    },
    "list_fields": {"archive_block", "archive_log"},
}

_AV_CONFIG_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {
        "status",
        "action",
        "scan",
        "log",
        "comment",
        "cover_page",
        "detect_only",
        "error_action",
        "office_action",
        "office_dde",
        "office_embed",
        "office_hylink",
        "office_linked",
        "office_macro",
        "original_file_destination",
        "pdf_act_form",
        "pdf_act_gotor",
        "pdf_act_java",
        "pdf_act_launch",
        "pdf_act_movie",
        "pdf_act_sound",
        "pdf_embedfile",
        "pdf_hyperlink",
        "pdf_javacode",
        "expiry",
        "infected",
    },
}


def _build_antivirus_profiles(
    parser: Any,
    collection_name: str,
    top_edits: List[FGSourceNode],
) -> None:
    for node in top_edits:
        profile_settings, profile_extra = phase41._effective_profile_settings(
            node,
            FGAntivirusProfile746,
        )
        profile = FGAntivirusProfile746(
            name=node.name,
            **phase41._typed_values(profile_settings, FGAntivirusProfile746),
        )
        profile.extra_settings = profile_extra

        for child in node.children:
            child_name = child.name.lower().replace("-", "_")
            child_entries = [
                entry for entry in child.children if entry.node_type == "edit"
            ]

            if child_name in _AV_PROTOCOLS:
                settings, extra_settings = phase41._effective_profile_settings(
                    child,
                    FGAntivirusProtocol746,
                )
                protocol = FGAntivirusProtocol746(
                    name=child.name,
                    settings=settings,
                    entries=[phase41._typed_profile_node(entry) for entry in child_entries],
                    extra_settings=extra_settings,
                    **phase41._typed_values(settings, FGAntivirusProtocol746),
                )
                for nested in child.children:
                    if nested.node_type != "config":
                        continue
                    for projection in phase41._effective_nested_profile_edits(
                        nested,
                        FGAntivirusProfileConfig746,
                    ):
                        protocol.configs.append(
                            FGAntivirusProfileConfig746(
                                name=projection["name"],
                                settings=projection["settings"],
                                extra_settings=projection["extra_settings"],
                                **projection["values"],
                            )
                        )
                profile.protocols.append(protocol)
                continue

            settings, extra_settings = phase41._effective_profile_settings(
                child,
                FGAntivirusProfileConfig746,
            )
            profile.configs.append(
                FGAntivirusProfileConfig746(
                    name=child.name,
                    settings=settings,
                    extra_settings=extra_settings,
                    **phase41._typed_values(settings, FGAntivirusProfileConfig746),
                )
            )

        getattr(parser.config, collection_name).append(profile)


def install_phase_42_antivirus_support(parser_module: Any) -> None:
    """Install Phase 42 AV typing on top of the Phase 41 shared evaluator."""

    phase41.PROFILE_FIELD_SPECS[FGAntivirusProfile746] = _AV_PROFILE_SPEC
    phase41.PROFILE_FIELD_SPECS[FGAntivirusProtocol746] = _AV_PROTOCOL_SPEC
    phase41.PROFILE_FIELD_SPECS[FGAntivirusProfileConfig746] = _AV_CONFIG_SPEC

    phase41.FGAntivirusProfile = FGAntivirusProfile746
    phase41.FGAntivirusProtocol = FGAntivirusProtocol746
    phase41.FGAntivirusProfileConfig = FGAntivirusProfileConfig746
    phase41._PROFILE_PATHS["antivirus profile"] = (
        "antivirus_profiles",
        FGAntivirusProfile746,
    )

    original_builder = phase41._build_antivirus_or_webfilter
    if not getattr(original_builder, "_phase_42_wrapped", False):
        def build_antivirus_or_webfilter(
            parser: Any,
            source_path: str,
            collection_name: str,
            model: Any,
            top_edits: List[FGSourceNode],
        ) -> None:
            if model is FGAntivirusProfile746:
                _build_antivirus_profiles(parser, collection_name, top_edits)
                return
            original_builder(
                parser,
                source_path,
                collection_name,
                model,
                top_edits,
            )

        build_antivirus_or_webfilter._phase_42_wrapped = True
        phase41._build_antivirus_or_webfilter = build_antivirus_or_webfilter

    # Keep parser-module public names aligned with the active typed models.
    parser_module.FGAntivirusProfile = FGAntivirusProfile746
    parser_module.FGAntivirusProtocol = FGAntivirusProtocol746
    parser_module.FGAntivirusProfileConfig = FGAntivirusProfileConfig746
    parser_module.PROFILE_FIELD_SPECS = phase41.PROFILE_FIELD_SPECS
