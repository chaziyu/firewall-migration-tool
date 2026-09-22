"""Cisco FTD vendor-native source extraction and reporting entry point."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem, SourceSectionResult
from fwmigrate.extraction.sanitize import sanitize_raw_text

from .derived import FTDDerivedViews, build_ftd_derived_views
from .model import CiscoFTDConfig, CiscoFTDInterfaceSource, CiscoFTDRoute
from .cli.parser import CiscoFTDParser
from .validation import FTDValidationResult, validate_ftd_config


def _sanitize(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_raw_text(value)
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize(item) for key, item in value.items()}
    fields = getattr(type(value), "model_fields", None)
    if fields is not None:
        for name in fields:
            setattr(value, name, _sanitize(getattr(value, name)))
    return value


@dataclass(frozen=True)
class FTDSourceResult:
    config: CiscoFTDConfig
    source_sections: list[Any]
    inventory_items: list[Any]
    unsupported_items: list[Any]
    derived: FTDDerivedViews
    validation: FTDValidationResult


def _text_source(text: str, zone_mapping: dict[str, str] | None) -> CiscoFTDConfig:
    config = CiscoFTDParser(text, zone_mapping=zone_mapping).parse_raw()
    config.input_source_type = config.source_plane = "ftd-text-evidence"
    config.source_metadata = {"authoritative": "device CLI/text evidence"}
    config.source_interfaces = [CiscoFTDInterfaceSource(
        name=item.name, source_plane="ftd-text-evidence", raw={"raw_lines": item.raw_lines},
        interface_type=item.interface_type, address=item.ip, zone=zone_mapping.get(item.nameif, zone_mapping.get(item.name))
        if zone_mapping else None,
    ) for item in config.interfaces]
    config.routes = [CiscoFTDRoute(
        name=item.name, source_plane="ftd-text-evidence", raw={"raw_line": item.raw_line},
        interface=item.interface, destination=item.destination, gateway=item.gateway,
    ) for item in config.static_routes]
    return config


def _inventory(config: CiscoFTDConfig) -> list[SourceInventoryItem]:
    collections = (
        ("managed_objects", "objects"), ("object_groups", "object-groups"),
        ("services", "services"), ("security_zones", "security-zones"),
        ("source_interfaces", "interfaces"), ("routes", "routes"),
        ("acp_rules", "acp"), ("nat_policies", "nat"),
    )
    items = []
    for attribute, path in collections:
        for index, record in enumerate(getattr(config, attribute), 1):
            items.append(SourceInventoryItem(
                domain="cisco_ftd", source_path=f"{config.source_plane}/{path}",
                source_id=str(record.source_id or index), name=record.name,
                source_type=attribute[:-1], source_context=record.source_context,
                source_attributes={"source_plane": config.source_plane, **record.source_attributes},
                status=ExtractionStatus.SOURCE_ONLY if config.source_plane == "ftd-text-evidence" else ExtractionStatus.EXTRACTED,
                requires_manual_review=any(item.get("source_name") == record.name for item in config.unsupported_evidence),
            ))
    return items


def extract_cisco_ftd_source(text: str, zone_mapping: dict[str, str] | None = None) -> FTDSourceResult:
    from .fdm.fdm_adapter import CiscoFDMBundleParser, is_fdm_bundle
    from .fmc.fmc_adapter import CiscoFMCBundleParser, is_fmc_bundle

    if is_fmc_bundle(text):
        config = CiscoFMCBundleParser(text).parse_source()
        sections = [SourceSectionResult(path="fmc/source", source_context=config.source_metadata.get("domain_name"),
                                         status=ExtractionStatus.EXTRACTED,
                                         object_count_source=len(config.managed_objects) + len(config.object_groups) + len(config.services),
                                         object_count_parsed=len(config.managed_objects) + len(config.object_groups) + len(config.services),
                                         object_count_extracted=len(config.managed_objects) + len(config.object_groups) + len(config.services))]
    elif is_fdm_bundle(text):
        config = CiscoFDMBundleParser(text).parse_source()
        sections = [SourceSectionResult(path="fdm/source", source_context=config.source_metadata.get("domain_name"),
                                         status=ExtractionStatus.EXTRACTED,
                                         object_count_source=len(config.managed_objects) + len(config.object_groups) + len(config.services),
                                         object_count_parsed=len(config.managed_objects) + len(config.object_groups) + len(config.services),
                                         object_count_extracted=len(config.managed_objects) + len(config.object_groups) + len(config.services))]
    else:
        config = _text_source(text, zone_mapping)
        sections = [SourceSectionResult(path="ftd-cli/source", status=ExtractionStatus.SOURCE_ONLY,
                                         object_count_source=len(config.interfaces) + len(config.static_routes),
                                         object_count_parsed=len(config.interfaces) + len(config.static_routes),
                                         object_count_extracted=0)]
    config = _sanitize(deepcopy(config))
    derived = build_ftd_derived_views(config)
    validation = validate_ftd_config(config, derived)
    return FTDSourceResult(config, sections, _inventory(config), config.unsupported_evidence, derived, validation)


class CiscoFTDSourceReporter:
    vendor_id = "cisco_ftd"
    display_name = "Cisco Firepower Threat Defense"
    supported_extensions = (".cfg", ".txt", ".conf", ".json")

    def analyze_source(self, source: str, **options: Any) -> FTDSourceResult:
        return extract_cisco_ftd_source(source, zone_mapping=options.get("zone_mapping"))

    def build_preview(self, analysis: FTDSourceResult, **options: Any) -> dict[str, Any]:
        from .web_report import build_ftd_preview
        return build_ftd_preview(analysis)

    def export_excel(self, analysis: FTDSourceResult, output: Any, **options: Any) -> Any:
        from .export.excel import export_ftd_excel
        return export_ftd_excel(analysis, output)


__all__ = ["CiscoFTDSourceReporter", "FTDSourceResult", "extract_cisco_ftd_source"]
