from fwmigrate.ir.version import IR_SCHEMA_VERSION
from fwmigrate.ir.core import (
    IRAddress,
    IRAddressGroup,
    IRConfig,
    IRMetadata,
    IRNATRule,
    IRPolicy,
    IRRoute,
    IRService,
    IRServiceGroup,
    IRVPNTunnel,
    IRZone,
)
from fwmigrate.ir.semantics import (
    AddressUniversalFamily,
    classify_universal_address_reference,
    is_zone_safe_for_target_generation,
    unsafe_zone_names,
    policy_references_unsafe_zone,
)

__all__ = [
    "IR_SCHEMA_VERSION",
    "IRConfig",
    "IRMetadata",
    "IRZone",
    "IRAddress",
    "IRAddressGroup",
    "IRService",
    "IRServiceGroup",
    "IRPolicy",
    "IRNATRule",
    "IRRoute",
    "IRVPNTunnel",
    "AddressUniversalFamily",
    "classify_universal_address_reference",
    "is_zone_safe_for_target_generation",
    "unsafe_zone_names",
    "policy_references_unsafe_zone",
]
