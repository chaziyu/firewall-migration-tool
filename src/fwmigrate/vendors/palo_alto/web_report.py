from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any

from .source_report import PaloAltoSourceResult


def _jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if is_dataclass(value):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def build_panos_preview(analysis: PaloAltoSourceResult) -> dict[str, Any]:
    config = analysis.config
    records = config.source_inventory
    return {
        "vendor": "palo_alto",
        "hostname": config.hostname,
        "source_version": config.source_version,
        "summary": {
            "scopes": len(config.scopes),
            "records": len(records),
            "interfaces": len(config.interfaces),
            "addresses": len(config.addresses) + len(config.address_groups),
            "services": len(config.services) + len(config.service_groups),
            "schedules": len(config.schedules),
            "policies": len(config.security_rules),
            "default_security_rules": len(config.default_security_rules),
            "nat_rules": len(config.nat_rules),
            "routes": len(config.static_routes),
            "virtual_routers": len(config.virtual_routers),
            "logical_routers": len(config.logical_routers),
            "unresolved_references": len(analysis.derived.unresolved_references),
            "relationship_issues": len(analysis.derived.relationship_issues),
            "validation_errors": len(analysis.validation.errors),
            "validation_warnings": len(analysis.validation.warnings),
        },
        "scopes": [scope.model_dump() for scope in config.scopes],
        "scope_hierarchy": {
            "parents": list(analysis.derived.scope_hierarchy.parents),
            "ancestors": list(analysis.derived.scope_hierarchy.ancestors),
        },
        "records": [
            {
                "kind": record.kind,
                "source_path": record.source_path,
                "name": record.name,
                "scope": record.scope.model_dump() if record.scope else None,
                "source_order": record.source_order,
                "values": record.values,
            }
            for record in records[:200]
        ],
        "unresolved_references": [_jsonable(item) for item in analysis.derived.reference_resolutions if item.status != "RESOLVED"],
        "validation": [_jsonable(issue) for issue in analysis.validation.issues],
    }
