"""Universal IR Stub / Placeholder Factory for Unsupported Firewall Objects.

Provides deterministic RFC 2544 dummy IP stubs (198.18.0.1/32 - 198.19.255.254/32) to preserve
referential integrity in parent address groups, security rules, and NAT policies
across any vendor migration path without triggering IP collisions, FIPS violations,
target DNS queries, or CLI syntax rejections.
"""

import hashlib
import ipaddress
from typing import Optional, List
from fwmigrate.ir.core import IRAddress
from fwmigrate.ir.enums import AddressType

DEFAULT_STUB_IP = "198.19.255.254/32"
DEFAULT_STUB_TAG = "MANUAL_REVIEW_REQUIRED"

def generate_deterministic_dummy_ip(original_value: str) -> str:
    """Allocates a deterministic, repeatable dummy IP for an unsupported object

    using the RFC 2544 benchmark subnet (198.18.0.0/15, providing 131,070 usable host IPs).
    Uses FIPS-compliant SHA-256 hashing.
    """
    if not original_value:
        return DEFAULT_STUB_IP

    # Step 1: FIPS-compliant SHA-256 hash
    hash_object = hashlib.sha256(original_value.encode("utf-8"))
    hash_int = int(hash_object.hexdigest(), 16)

    # Step 2: Modulo against usable hosts in 198.18.0.0/15, reserving the final IP (.254)
    # Max offset becomes 131069, mapping to 198.19.255.253
    host_offset = (hash_int % 131069) + 1

    # Step 3: Add offset to base network integer
    base_ip_int = int(ipaddress.IPv4Address("198.18.0.0"))
    unique_ip = ipaddress.IPv4Address(base_ip_int + host_offset)

    return f"{unique_ip}/32"

def create_unsupported_stub(
    name: str,
    original_type: str,
    original_value: str,
    description: Optional[str] = None,
    stub_ip: Optional[str] = None,
    extra_tags: Optional[List[str]] = None
) -> IRAddress:
    """Generates a universal IR stub object to preserve referential integrity

    in parent address groups and security rules across all vendors.
    """
    allocated_ip = stub_ip or generate_deterministic_dummy_ip(original_value or name)
    clean_type = "".join(c for c in original_type if c.isalnum() or c in "_-").upper()
    tags = [DEFAULT_STUB_TAG, f"UNSUPPORTED_{clean_type}"]
    if extra_tags:
        for t in extra_tags:
            if t not in tags:
                tags.append(t)

    audit_note = (
        f"Unsupported source object type '{original_type}' ({original_value}). "
        f"Created RFC 2544 placeholder stub ({allocated_ip}) to prevent empty group and rule degradation."
    )

    desc = description or audit_note

    return IRAddress(
        name=name,
        type=AddressType.STUB_UNSUPPORTED,
        subnet=allocated_ip,
        stub_value=allocated_ip,
        original_type=original_type,
        original_value=original_value,
        description=desc,
        tags=tags,
        requires_manual_review=True,
        audit_note=audit_note
    )
