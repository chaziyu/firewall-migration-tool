"""Extract explicitly configured SecureXL/CoreXL settings only."""

from __future__ import annotations

import re
from typing import List, Tuple

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem
from fwmigrate.ir.core import IRCheckpointPerformanceSettings


def extract_performance_settings(text: str) -> Tuple[List[IRCheckpointPerformanceSettings], List[SourceInventoryItem]]:
    settings: List[IRCheckpointPerformanceSettings] = []
    inventory: List[SourceInventoryItem] = []
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        match = re.match(r"(?:set|add)\s+(securexl|fwaccel|corexl|multi-core)\s+(.+)$", line, re.I)
        if not match: continue
        feature, tail = match.groups()
        lowered = tail.lower()
        enabled = True if re.search(r"\b(on|enable|enabled)\b", lowered) else False if re.search(r"\b(off|disable|disabled)\b", lowered) else None
        count_match = re.search(r"\b(?:instances?|instance-count|num)\s+(\d+)", tail, re.I)
        attrs = {"raw_command": line}
        item = IRCheckpointPerformanceSettings(name=f"{feature}_{line_number}", feature=feature.lower(), enabled=enabled,
            instance_count=int(count_match.group(1)) if count_match else None, settings=attrs, source_attributes=attrs)
        settings.append(item)
        inventory.append(SourceInventoryItem(domain="gaia", source_path="gaia/show-configuration/performance",
            name=item.name, source_type=f"gaia-{feature.lower()}", source_attributes=attrs,
            status=ExtractionStatus.EXTRACT_ONLY, requires_manual_review=True,
            notes=["persistent setting only; runtime statistics excluded"]))
    return settings, inventory
