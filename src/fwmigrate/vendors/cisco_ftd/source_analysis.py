"""Cisco FTD source plane selection and report analysis."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from .derived import FTDDerivedViews, build_ftd_derived_views
from .model import CiscoFTDConfig
from .cli.parser import CiscoFTDParser
from .source_accounting import account_cli_sections, project_collection_completeness, source_count
from .source_inventory import build_ftd_source_inventory
from .validation import FTDValidationResult, validate_ftd_config
from fwmigrate.extraction.models import ExtractionStatus, SourceSectionResult
from fwmigrate.extraction.sanitize import sanitize_raw_text


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


def _text_source(text: str) -> CiscoFTDConfig:
    config = CiscoFTDParser(text).parse_raw()
    config.input_source_type = config.source_plane = "ftd-text-evidence"
    config.source_metadata = {"authoritative": "device CLI/text evidence"}
    return config


def extract_cisco_ftd_source(text: str) -> FTDSourceResult:
    from .fdm.fdm_adapter import CiscoFDMBundleParser, is_fdm_bundle
    from .fmc.fmc_adapter import CiscoFMCBundleParser, is_fmc_bundle

    if is_fmc_bundle(text):
        config = CiscoFMCBundleParser(text).parse_source()
        collection_status = config.collection_metadata.status
        sections = [SourceSectionResult(path="fmc/source", source_context=config.source_metadata.get("domain_name"),
                                         status=(ExtractionStatus.UNKNOWN if collection_status == "UNKNOWN" else
                                                 ExtractionStatus.PARTIAL if collection_status in {"PARTIAL", "FAILED"} else
                                                 ExtractionStatus.EXTRACTED),
                                         object_count_source=source_count(config), object_count_parsed=source_count(config),
                                         object_count_extracted=source_count(config))]
    elif is_fdm_bundle(text):
        config = CiscoFDMBundleParser(text).parse_source()
        sections = [SourceSectionResult(path="fdm/source", source_context=config.source_metadata.get("domain_name"),
                                         status=ExtractionStatus.EXTRACTED,
                                         object_count_source=source_count(config), object_count_parsed=source_count(config),
                                         object_count_extracted=source_count(config))]
    else:
        config = _text_source(text)
        sections = account_cli_sections(text, config)
    config = _sanitize(deepcopy(config))
    project_collection_completeness(config, sections)
    derived = build_ftd_derived_views(config)
    validation = validate_ftd_config(config, derived)
    return FTDSourceResult(config, sections, build_ftd_source_inventory(config), config.unsupported_evidence, derived, validation)


