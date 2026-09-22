from __future__ import annotations

from typing import Any

from .source_report import FTDSourceResult


def build_ftd_preview(result: FTDSourceResult) -> dict[str, Any]:
    config = result.config
    return {
        "vendor": "cisco_ftd",
        "input_source_type": config.input_source_type,
        "source_plane": config.source_plane,
        "summary": {
            "managed_objects": len(config.managed_objects),
            "object_groups": len(config.object_groups),
            "services": len(config.services),
            "security_zones": len(config.security_zones),
            "interfaces": len(config.source_interfaces) or len(config.interfaces),
            "routes": len(config.routes) or len(config.static_routes),
            "acp_rules": len(config.acp_rules),
            "nat_rules": len(config.nat_policies),
        },
        "source_metadata": config.source_metadata,
        "source_plane_completeness": result.derived.source_plane_completeness,
        "unresolved_references": [item.__dict__ for item in result.derived.unresolved_references],
        "unsupported": config.unsupported_evidence,
        "validation": [issue.__dict__ for issue in result.validation.issues],
    }


__all__ = ["build_ftd_preview"]
