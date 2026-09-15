from typing import Any, Iterable, Optional

from fwmigrate.capabilities.schema import (
    CapabilityAnalysisResult,
    CapabilityIssue,
    CapabilityStatus,
    FeatureSupport,
    VendorCapabilityProfile,
)
from fwmigrate.ir import IRConfig

class CapabilityAnalyzer:
    """
    Analyzes an IR against a target capability profile to determine translation viability,
    flagging structural loss as structured capability issues.
    """
    
    _OBJECT_FIELDS = {
        "securityrule": "policies",
        "securityrules": "policies",
        "rules": "policies",
        "policy": "policies",
        "service": "services",
        "services": "services",
        "address": "addresses",
        "addresses": "addresses",
        "zone": "zones",
        "zones": "zones",
        "nat": "nat_rules",
        "natrule": "nat_rules",
        "route": "routes",
        "routes": "routes",
    }

    def __init__(self, target_profile: Optional[VendorCapabilityProfile] = None):
        self.target_profile = target_profile

    @staticmethod
    def _field_value(obj: Any, name: str) -> Any:
        value = getattr(obj, name, None)
        return value if value is not None else getattr(obj, "model_dump", lambda: {})().get(name)

    def _entries(self, ir_config: IRConfig, object_name: str) -> Iterable[Any]:
        key = "".join(ch for ch in object_name.casefold() if ch.isalnum())
        field_name = self._OBJECT_FIELDS.get(key, object_name)
        value = getattr(ir_config, field_name, [])
        return value if isinstance(value, list) else [value] if value else []

    def analyze(
        self,
        ir_config: IRConfig,
        target_vendor: Optional[str] = None,
    ) -> CapabilityAnalysisResult:
        """Analyze canonical IR without modifying it or generating output."""
        profile = self.target_profile
        vendor = target_vendor or (profile.vendor_id if profile else "")
        issues: list[CapabilityIssue] = []

        for key in getattr(ir_config, "global_unknown_fields", {}):
            issues.append(CapabilityIssue(
                feature=key,
                status=CapabilityStatus.MANUAL_REVIEW,
                reason=f"Global configuration field '{key}' could not be parsed.",
                object_type="GlobalConfig",
                target_vendor=vendor,
            ))

        if not profile:
            return CapabilityAnalysisResult(issues)

        for object_name, object_cap in profile.objects.items():
            for obj in self._entries(ir_config, object_name):
                object_id = getattr(obj, "name", None) or getattr(obj, "id", None)
                if object_cap.support == FeatureSupport.UNSUPPORTED:
                    label = {"SecurityRule": "Security Rules"}.get(object_name, object_name)
                    issues.append(CapabilityIssue(
                        feature=object_name,
                        status=CapabilityStatus.UNSUPPORTED,
                        reason=f"Target platform does not support {label}.",
                        object_type=object_name,
                        object_id=str(object_id) if object_id is not None else None,
                        target_vendor=vendor,
                        blocks_generation=True,
                    ))
                    continue
                if object_cap.support == FeatureSupport.PARTIAL:
                    issues.append(CapabilityIssue(
                        feature=object_name,
                        status=CapabilityStatus.PARTIAL,
                        reason=f"Target platform only partially supports {object_name}.",
                        object_type=object_name,
                        object_id=str(object_id) if object_id is not None else None,
                        target_vendor=vendor,
                    ))

                for field_name, field_cap in object_cap.fields.items():
                    if self._field_value(obj, field_name) and field_cap.support == FeatureSupport.UNSUPPORTED:
                        issues.append(CapabilityIssue(
                            feature=field_name,
                            status=CapabilityStatus.UNSUPPORTED,
                            reason=f"Target platform does not support '{field_name}'. Value will be dropped.",
                            object_type=object_name,
                            object_id=str(object_id) if object_id is not None else None,
                            target_vendor=vendor,
                        ))

                unknown_fields = getattr(getattr(obj, "provenance", None), "unknown_fields", {})
                if unknown_fields:
                    issues.append(CapabilityIssue(
                        feature="provenance",
                        status=CapabilityStatus.MANUAL_REVIEW,
                        reason=f"Native structural data requires review: {list(unknown_fields)}",
                        object_type=object_name,
                        object_id=str(object_id) if object_id is not None else None,
                        target_vendor=vendor,
                    ))

        return CapabilityAnalysisResult(issues)
