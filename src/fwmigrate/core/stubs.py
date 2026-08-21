"""Universal IR Stub / Placeholder Factory for Unsupported Firewall Objects.

Provides standard RFC 5737 dummy IP stubs (192.0.2.254/32) to preserve
referential integrity in parent address groups, security rules, and NAT policies
across any vendor migration path without triggering target DNS queries or CLI rejections.
"""

from typing import Optional, List
from fwmigrate.ir.core import IRAddress, IRAuditEntry
from fwmigrate.ir.enums import AddressType, MigrationConfidence

# Reserved non-routable IP from RFC 5737 TEST-NET-1
DEFAULT_STUB_IP = "192.0.2.254/32"
DEFAULT_STUB_TAG = "MANUAL_REVIEW_REQUIRED"

def create_unsupported_stub(
    name: str,
    original_type: str,
    original_value: str,
    description: Optional[str] = None,
    stub_ip: str = DEFAULT_STUB_IP,
    extra_tags: Optional[List[str]] = None
) -> IRAddress:
    """Generates a universal IR stub object to preserve referential integrity

    in parent address groups and security rules across all vendors.
    """
    clean_type = "".join(c for c in original_type if c.isalnum() or c in "_-").upper()
    tags = [DEFAULT_STUB_TAG, f"UNSUPPORTED_{clean_type}"]
    if extra_tags:
        for t in extra_tags:
            if t not in tags:
                tags.append(t)

    audit_note = (
        f"Unsupported source object type '{original_type}' ({original_value}). "
        f"Created RFC 5737 placeholder stub ({stub_ip}) to prevent empty group and rule degradation."
    )

    desc = description or audit_note

    return IRAddress(
        name=name,
        type=AddressType.STUB_UNSUPPORTED,
        subnet=stub_ip,
        stub_value=stub_ip,
        original_type=original_type,
        original_value=original_value,
        description=desc,
        tags=tags,
        requires_manual_review=True,
        audit_note=audit_note
    )
