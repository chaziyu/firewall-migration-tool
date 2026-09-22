from __future__ import annotations

from typing import Any

from .source_report import PaloAltoSourceResult


def build_panos_preview(analysis: PaloAltoSourceResult) -> dict[str, Any]:
    config = analysis.config
    records = config.records
    return {
        "vendor": "palo_alto",
        "hostname": config.hostname,
        "source_version": config.source_version,
        "summary": {
            "scopes": len(config.scopes),
            "records": len(records),
            "interfaces": sum(record.kind == "interface" for record in records),
            "addresses": sum(record.kind == "address" for record in records),
            "policies": sum("rule" in record.source_path for record in records),
            "nat_rules": sum("nat" in record.source_path for record in records),
            "routes": sum("route" in record.source_path for record in records),
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
