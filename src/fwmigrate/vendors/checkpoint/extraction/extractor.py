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
from ..policy_context import CPPolicyContextRecord
from .result import ExtractionResult
from .source_metadata import capture_source_metadata
from .reconcile import reconcile_append


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
    policy_context: list[CPPolicyContextRecord] = []
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
        if response.command.startswith("gaia/"):
            records = extract_gaia_records(response)
        elif response.command.lower() in _POLICY_EXTRACTORS:
            records = _POLICY_EXTRACTORS[response.command.lower()](response)
        else:
            records = extract_object_records(response)
        for bucket, item in records:
            if bucket == "policy_context":
                policy_context.append(item)
                continue
            destination = getattr(config, bucket, None)
            if destination is None:
                source_objects.append(item)
            else:
                reconcile_append(destination, item)

    represented = {(item.command, item.domain, item.package, item.layer, item.gateway) for item in collection}
    for item in bundle.collection_completeness.values():
        command = item.command
        identity = (command, item.domain_name or item.domain, item.package_name or item.package,
                    item.layer_name or item.layer, item.gateway)
        if identity not in represented:
            collection.append(CheckPointCollectionDiagnostic(
                command=command, source_plane="management", domain=item.domain_name or item.domain,
                domain_uid=item.domain_uid, domain_name=item.domain_name,
                package=item.package_name or item.package, package_uid=item.package_uid,
                package_name=item.package_name, layer=item.layer_name or item.layer,
                layer_uid=item.layer_uid, layer_name=item.layer_name, gateway=item.gateway,
                status=item.status, complete=item.complete, error=item.error_message,
                error_code=item.error_code,
            ))
    if not bundle.collection_completeness:
        collection.append(CheckPointCollectionDiagnostic(
            command="collection-coverage", source_plane="management", status=CollectionStatus.UNKNOWN,
            complete=False, error="Offline collection coverage manifest is unavailable.",
        ))

    return ExtractionResult(
        config=config,
        collection=tuple(collection),
        source_objects=tuple(source_objects),
        source_metadata=capture_source_metadata(bundle),
        policy_context=tuple(policy_context),
        scope=scope or ScopeSelectionResult(),
    )


def _merge_pages(pages: list[CheckPointResponse]) -> CheckPointResponse:
    if all(page.from_index is not None and page.to_index is not None for page in pages):
        pages = sorted(pages, key=lambda page: page.from_index or 0)
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
