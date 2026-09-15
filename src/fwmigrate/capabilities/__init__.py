# init
from fwmigrate.capabilities.analyzer import CapabilityAnalyzer
from fwmigrate.capabilities.schema import (
    CapabilityAnalysisResult,
    CapabilityIssue,
    CapabilityStatus,
    FeatureSupport,
    VendorCapabilityProfile,
)
from fwmigrate.capabilities.fortigate_nat_remediation import (
    install_fortigate_nat_capability_remediation,
)

install_fortigate_nat_capability_remediation(
    __import__("fwmigrate.capabilities.analyzer", fromlist=["CapabilityAnalyzer"])
)

__all__ = [
    "CapabilityAnalyzer",
    "CapabilityAnalysisResult",
    "CapabilityIssue",
    "CapabilityStatus",
    "FeatureSupport",
    "VendorCapabilityProfile",
]
