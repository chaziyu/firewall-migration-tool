from __future__ import annotations

from typing import Any

from ..loader import build_rulebase_safety_map, group_response_pages
from ..models import (
    CheckPointCollectionDiagnostic, CheckPointExportBundle, CheckPointResponse,
    CollectionStatus, ScopeSelectionResult, collection_status_is_success,
)
from ..model.source import CheckPointConfig
from .common import source_plane
from .gaia import extract_gaia_records
from .objects import extract_object_records
from .policy import (
    extract_access_rulebase, extract_https_rulebase, extract_nat_rulebase,
    extract_threat_rulebase,
)
from .result import ExtractionResult
from .source_metadata import capture_source_metadata


_POLICY_EXTRACTORS = {
    "show-access-rulebase": extract_access_rulebase,
    "show-nat-rulebase": extract_nat_rulebase,
    "show-threat-rulebase": extract_threat_rulebase,
    "show-threat-rule-exception-rulebase": extract_threat_rulebase,
    "show-https-rulebase": extract_https_rulebase,
    "show-https-inspection-rulebase": extract_https_rulebase,
}


def extract_checkpoint_config(
    bundle: CheckPointExportBundle,
    scope: ScopeSelectionResult | None = None,
) -> ExtractionResult:
    config = CheckPointConfig()
    collection: list[CheckPointCollectionDiagnostic] = []
    source_objects = []
    groups = group_response_pages(bundle)
    safety = build_rulebase_safety_map(bundle)

    for key, pages in groups.items():
        response = _merge_pages(pages)
        state = safety[key]
        collection.append(CheckPointCollectionDiagnostic(
            command=response.command,
            source_plane=source_plane(response),
            domain=response.domain,
            package=response.package,
            layer=response.layer,
            gateway=response.gateway,
            status=_group_status(pages),
            complete=state.complete and all(collection_status_is_success(page.collection_status) for page in pages),
            error=next((page.error for page in pages if page.error), None),
            error_code=next((page.collection_error_code for page in pages if page.collection_error_code), None),
            from_index=min((page.from_index for page in pages if page.from_index is not None), default=None),
            to_index=max((page.to_index for page in pages if page.to_index is not None), default=None),
            total=max((page.total for page in pages if page.total is not None), default=None),
        ))
        if response.command.startswith("gaia/") and "cli_text" in response.data:
            records = extract_gaia_records(response)
        elif response.command.lower() in _POLICY_EXTRACTORS:
            records = _POLICY_EXTRACTORS[response.command.lower()](response)
        else:
            records = extract_object_records(response)
        for bucket, item in records:
            destination = getattr(config, bucket, None)
            if destination is None:
                source_objects.append(item)
            else:
                destination.append(item)

    return ExtractionResult(
        config=config,
        collection=tuple(collection),
        source_objects=tuple(source_objects),
        source_metadata=capture_source_metadata(bundle),
        scope=scope or ScopeSelectionResult(),
    )


def _merge_pages(pages: list[CheckPointResponse]) -> CheckPointResponse:
    merged = pages[0].model_copy(deep=True)
    data = dict(merged.data)
    for key in ("objects", "rulebase", "rules", "items", "interfaces", "routes"):
        values = [page.data.get(key) for page in pages if key in page.data]
        if not values:
            continue
        if all(isinstance(value, list) for value in values):
            data[key] = [item for value in values for item in value]
        elif all(isinstance(value, dict) for value in values):
            combined: dict[str, Any] = {}
            for value in values:
                combined.update(value)
            data[key] = combined
    merged.data = data
    return merged


def _group_status(pages: list[CheckPointResponse]) -> CollectionStatus:
    return next((page.collection_status for page in pages if not collection_status_is_success(page.collection_status)), pages[0].collection_status)
