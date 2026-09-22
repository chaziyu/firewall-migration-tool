"""Vendor-native FortiGate source extraction and reporting."""

from .derived import DerivedViews, build_derived_views
from .extraction.extractor import extract_fortigate_config
from .extraction.result import ExtractionResult
from .export import export_excel
from .model.source import FGConfig
from .parser import parse_fortigate_config
from .validation.validator import validate_config

__all__ = [
    "DerivedViews",
    "ExtractionResult",
    "FGConfig",
    "build_derived_views",
    "export_excel",
    "extract_fortigate_config",
    "parse_fortigate_config",
    "validate_config",
]
