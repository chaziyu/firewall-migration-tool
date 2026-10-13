"""Reporting and collection context for Check Point extraction."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import CheckPointExportBundle


@dataclass(frozen=True, slots=True)
class CheckPointSourceMetadata:
    api_version: str | None = None
    management_server: str | None = None
    selected_scope: dict[str, Any] = field(default_factory=dict)
    collection_scope: str | None = None
    collector_version: str | None = None
    collection_timestamp: str | None = None
    successful_command_count: int | None = None
    failed_command_count: int | None = None
    unsupported_command_count: int | None = None
    permission_denied_count: int | None = None


def capture_source_metadata(bundle: CheckPointExportBundle) -> CheckPointSourceMetadata:
    selected_scope = {
        key: value
        for key, value in {
            "domain": bundle.selected_domain or bundle.domain,
            "domain_uid": bundle.selected_domain_uid or bundle.domain_uid,
            "package": bundle.selected_package,
            "access_layer": bundle.selected_access_layer,
            "access_layer_uid": bundle.selected_access_layer_uid,
            "gateway": bundle.selected_gateway or bundle.gateway,
            "requested": bundle.requested_scope,
        }.items()
        if value is not None
    }
    return CheckPointSourceMetadata(
        api_version=bundle.api_version,
        management_server=bundle.management_server,
        selected_scope=selected_scope,
        collection_scope=bundle.collection_scope,
        collector_version=bundle.collector_version,
        collection_timestamp=bundle.collection_timestamp,
        successful_command_count=bundle.successful_command_count,
        failed_command_count=bundle.failed_command_count,
        unsupported_command_count=bundle.unsupported_command_count,
        permission_denied_count=bundle.permission_denied_count,
    )


__all__ = ["CheckPointSourceMetadata", "capture_source_metadata"]
