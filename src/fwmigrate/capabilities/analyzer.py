from __future__ import annotations

from typing import Any, Iterable, List, Optional

from fwmigrate.capabilities.schema import FeatureSupport, VendorCapabilityProfile
from fwmigrate.ir.core import IRConfig
from fwmigrate.jobs.models import MigrationIssue


def _issue(
    *,
    severity: str,
    category: str,
    source_object: str,
    message: str,
    blocking: bool,
    target_vendor: Optional[str] = None,
) -> MigrationIssue:
    issue = MigrationIssue(
        severity=severity,
        category=category,
        source_object=source_object,
        target_object=f"Target:{target_vendor}" if target_vendor else None,
        message=message,
        blocking=blocking,
    )
    return issue


class CapabilityAnalyzer:
    """Analyze canonical ``IRConfig`` against an optional target profile."""

    def __init__(self, target_profile: Optional[VendorCapabilityProfile] = None):
        self.target_profile = target_profile

    def _capability(self, name: str) -> Any:
        if not self.target_profile:
            return None
        aliases = {
            "SecurityRule": ("SecurityRule", "rules", "policies"),
            "Address": ("Address", "addresses"),
            "Service": ("Service", "services"),
            "Zone": ("Zone", "zones"),
            "NATRule": ("NATRule", "nat_rules", "nat"),
        }
        for candidate in aliases.get(name, (name,)):
            if candidate in self.target_profile.objects:
                return self.target_profile.objects[candidate]
        return None

    @staticmethod
    def _items(ir_config: IRConfig, name: str) -> Iterable[Any]:
        return {
            "SecurityRule": ir_config.policies,
            "Address": ir_config.addresses,
            "Service": ir_config.services,
            "Zone": ir_config.zones,
            "NATRule": ir_config.nat_rules,
        }[name]

    def analyze(
        self,
        ir_config: IRConfig,
        target_vendor: Optional[str] = None,
    ) -> List[MigrationIssue]:
        """Return evidence only; this method never changes ``ir_config``."""
        issues: List[MigrationIssue] = []
        if not isinstance(ir_config, IRConfig):
            raise TypeError("CapabilityAnalyzer expects IRConfig")

        vendor = target_vendor or (self.target_profile.vendor_id if self.target_profile else None)
        for object_name in ("SecurityRule", "Address", "Service", "Zone", "NATRule"):
            capability = self._capability(object_name)
            if capability is None:
                continue
            for item in self._items(ir_config, object_name):
                object_id = f"{object_name}:{getattr(item, 'name', object_name)}"
                if capability.support == FeatureSupport.UNSUPPORTED:
                    display_name = {
                        "SecurityRule": "Security Rules",
                        "NATRule": "NAT Rules",
                    }.get(object_name, f"{object_name} objects")
                    issues.append(_issue(
                        severity="CRITICAL",
                        category="CAPABILITY_MISMATCH",
                        source_object=object_id,
                        message=f"Target platform does not support {display_name}.",
                        blocking=True,
                        target_vendor=vendor,
                    ))
                    continue

                for field_name, field_capability in capability.fields.items():
                    value = getattr(item, field_name, None)
                    if value and field_capability.support == FeatureSupport.UNSUPPORTED:
                        issues.append(_issue(
                            severity="HIGH",
                            category="DATA_LOSS",
                            source_object=f"{object_id}.{field_name}",
                            message=f"Target platform does not support '{field_name}'. Value requires manual review.",
                            blocking=False,
                            target_vendor=vendor,
                        ))

                if getattr(item, "requires_manual_review", False):
                    issues.append(_issue(
                        severity="HIGH",
                        category="MANUAL_REVIEW",
                        source_object=object_id,
                        message="Source object is marked for manual review.",
                        blocking=False,
                        target_vendor=vendor,
                    ))

        return issues
