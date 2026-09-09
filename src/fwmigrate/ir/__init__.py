from fwmigrate.ir.version import IR_SCHEMA_VERSION
from fwmigrate.ir.semantics import (
    AddressUniversalFamily,
    classify_universal_address_reference,
    is_zone_safe_for_target_generation,
    unsafe_zone_names,
    policy_references_unsafe_zone,
)

__all__ = [
    "IR_SCHEMA_VERSION",
    "AddressUniversalFamily",
    "classify_universal_address_reference",
    "is_zone_safe_for_target_generation",
    "unsafe_zone_names",
    "policy_references_unsafe_zone",
]
