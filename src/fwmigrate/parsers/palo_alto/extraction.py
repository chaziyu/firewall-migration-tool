from typing import Dict, Any, Optional, List
from fwmigrate.extraction.models import ExtractionResult, SourceSectionResult, SourceInventoryItem, ExtractionStatus
from fwmigrate.extraction.sanitize import sanitize_source_attributes
from fwmigrate.parsers.palo_alto.source_model import PANScope

def add_source_section(
    extraction: ExtractionResult,
    path: str,
    status: ExtractionStatus,
    source_count: Optional[int] = None,
    parsed_count: Optional[int] = None,
    normalized_count: Optional[int] = None,
    handler: Optional[str] = None
):
    extraction.source_sections.append(
        SourceSectionResult(
            path=path,
            status=status,
            object_count_source=source_count,
            object_count_parsed=parsed_count,
            object_count_normalized=normalized_count,
            parser_handler=handler
        )
    )

def _generate_source_record_id(scope: Optional[PANScope], domain: str, source_path: str, name: Optional[str]) -> str:
    scope_kind = scope.kind if scope else "unknown"
    scope_name = scope.name if scope else "unknown"
    obj_name = name if name else "anonymous"
    return f"palo_alto|{scope_kind}|{scope_name}|{domain}|{source_path}|{obj_name}"

def _record_item(
    extraction: ExtractionResult,
    status: ExtractionStatus,
    domain: str,
    source_path: str,
    scope: Optional[PANScope] = None,
    name: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
    requires_manual_review: bool = False,
    notes: Optional[List[str]] = None
):
    safe_attrs = sanitize_source_attributes(attributes) if attributes else {}
    if scope:
        safe_attrs["scope_kind"] = scope.kind
        safe_attrs["scope_name"] = scope.name
        if scope.device_name: safe_attrs["scope_device_name"] = scope.device_name
        if scope.vsys: safe_attrs["scope_vsys"] = scope.vsys
        if scope.device_group: safe_attrs["scope_device_group"] = scope.device_group

    record_id = _generate_source_record_id(scope, domain, source_path, name)

    extraction.inventory_items.append(
        SourceInventoryItem(
            domain=domain,
            source_path=source_path,
            name=name,
            source_record_id=record_id,
            source_attributes=safe_attrs,
            status=status,
            requires_manual_review=requires_manual_review,
            notes=notes or []
        )
    )

def record_normalized(extraction: ExtractionResult, domain: str, source_path: str, scope: Optional[PANScope] = None, name: Optional[str] = None, attributes: Optional[Dict[str, Any]] = None):
    _record_item(extraction, ExtractionStatus.NORMALIZED, domain, source_path, scope, name, attributes)

def record_partial(extraction: ExtractionResult, domain: str, source_path: str, scope: Optional[PANScope] = None, name: Optional[str] = None, attributes: Optional[Dict[str, Any]] = None, notes: Optional[List[str]] = None):
    _record_item(extraction, ExtractionStatus.PARTIALLY_NORMALIZED, domain, source_path, scope, name, attributes, requires_manual_review=True, notes=notes)

def record_extract_only(extraction: ExtractionResult, domain: str, source_path: str, scope: Optional[PANScope] = None, name: Optional[str] = None, attributes: Optional[Dict[str, Any]] = None):
    _record_item(extraction, ExtractionStatus.EXTRACT_ONLY, domain, source_path, scope, name, attributes)

def record_unsupported(extraction: ExtractionResult, domain: str, source_path: str, scope: Optional[PANScope] = None, name: Optional[str] = None, attributes: Optional[Dict[str, Any]] = None, notes: Optional[List[str]] = None):
    _record_item(extraction, ExtractionStatus.UNSUPPORTED, domain, source_path, scope, name, attributes, requires_manual_review=True, notes=notes)

def record_parse_error(extraction: ExtractionResult, domain: str, source_path: str, scope: Optional[PANScope] = None, name: Optional[str] = None, attributes: Optional[Dict[str, Any]] = None, notes: Optional[List[str]] = None):
    _record_item(extraction, ExtractionStatus.PARSE_ERROR, domain, source_path, scope, name, attributes, requires_manual_review=True, notes=notes)

def record_vendor_extension(extraction: ExtractionResult, domain: str, source_path: str, scope: Optional[PANScope] = None, name: Optional[str] = None, attributes: Optional[Dict[str, Any]] = None):
    _record_item(extraction, ExtractionStatus.VENDOR_EXTENSION, domain, source_path, scope, name, attributes)

def classify_partial(has_unsupported_fields: bool) -> ExtractionStatus:
    return ExtractionStatus.PARTIALLY_NORMALIZED if has_unsupported_fields else ExtractionStatus.NORMALIZED
