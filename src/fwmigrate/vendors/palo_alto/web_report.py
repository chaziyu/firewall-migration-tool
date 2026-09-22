from __future__ import annotations

from typing import Any

from .source_report import PaloAltoSourceResult


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
        },
        "scopes": [scope.model_dump() for scope in config.scopes],
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
        "validation": [issue.__dict__ for issue in analysis.validation.issues],
    }
