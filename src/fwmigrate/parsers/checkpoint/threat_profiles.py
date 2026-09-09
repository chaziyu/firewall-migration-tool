"""Source-only Check Point Threat Prevention profile extraction."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem
from fwmigrate.ir.core import IRCheckpointThreatPreventionProfile
from fwmigrate.parsers.checkpoint.models import CheckPointResponse


def extract_threat_profiles(responses: List[CheckPointResponse]) -> Tuple[List[IRCheckpointThreatPreventionProfile], List[SourceInventoryItem]]:
    profiles: List[IRCheckpointThreatPreventionProfile] = []
    inventory: List[SourceInventoryItem] = []
    commands = {"show-threat-profiles", "show-threat-prevention-profiles", "show-ips-profiles", "show-antibot-profiles", "show-antivirus-profiles", "show-threat-emulation-profiles", "show-threat-extraction-profiles"}
    for response in responses:
        if response.command.lower() not in commands:
            continue
        objects = response.data.get("objects", [])
        if isinstance(objects, dict):
            objects = list(objects.values())
        for obj in objects if isinstance(objects, list) else []:
            if not isinstance(obj, dict):
                continue
            family = str(obj.get("family") or obj.get("profile-type") or response.command.removeprefix("show-").removesuffix("-profiles"))
            profile = IRCheckpointThreatPreventionProfile(
                name=str(obj.get("name") or obj.get("uid") or family), source_uuid=obj.get("uid"),
                source_context=response.domain, family=family,
                activation=obj.get("activation") or obj.get("active") or {},
                actions=obj.get("actions") or {k: obj[k] for k in ("action", "default-action") if k in obj},
                confidence_severity_filters=obj.get("confidence-severity-filters") or obj.get("filters") or {},
                exceptions=obj.get("exceptions") or [], update_options=obj.get("update-options") or {},
                source_attributes=dict(obj),
            )
            profiles.append(profile)
            inventory.append(SourceInventoryItem(
                domain=response.domain or "global", source_path=f"checkpoint/{response.command}", name=profile.name,
                source_id=profile.source_uuid, source_type="threat-prevention-profile", source_attributes=dict(obj),
                status=ExtractionStatus.EXTRACT_ONLY, requires_manual_review=True,
            ))
    return profiles, inventory
