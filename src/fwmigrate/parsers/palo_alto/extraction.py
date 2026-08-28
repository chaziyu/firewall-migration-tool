from typing import Dict, Any, Optional
from fwmigrate.extraction.models import ExtractionResult, SourceSectionResult, SourceInventoryItem, ExtractionStatus
from fwmigrate.extraction.sanitize import sanitize_source_attributes

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

def add_inventory_item(
    extraction: ExtractionResult,
    domain: str,
    source_path: str,
    name: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
    status: ExtractionStatus = ExtractionStatus.EXTRACT_ONLY,
    requires_manual_review: bool = False
):
    safe_attrs = sanitize_source_attributes(attributes) if attributes else {}
    extraction.inventory_items.append(
        SourceInventoryItem(
            domain=domain,
            source_path=source_path,
            name=name,
            source_attributes=safe_attrs,
            status=status,
            requires_manual_review=requires_manual_review
        )
    )

def classify_partial(has_unsupported_fields: bool) -> ExtractionStatus:
    return ExtractionStatus.PARTIALLY_NORMALIZED if has_unsupported_fields else ExtractionStatus.NORMALIZED
