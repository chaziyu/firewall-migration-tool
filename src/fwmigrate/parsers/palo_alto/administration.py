"""PAN-OS firewall administrator inventory."""

from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET

from fwmigrate.extraction.sanitize import sanitize_source_attributes
from fwmigrate.ir.core import IRAdminProfile, IRAdminProfilePermissionBlock, IRAdministrator
from .extraction import record_extract_only, record_parse_error
from .source_model import PANScope, PANSourceObject
from .xml_utils import collect_unknown_children, structured_xml_capture, text_or_none


def _permitted_ips(entry: ET.Element) -> tuple[list[str], list[str]]:
    values = [node.get("name") for node in entry.findall("./permitted-ip/entry") if node.get("name")]
    values.extend(member.text.strip() for member in entry.findall("./permitted-ip/member")
                  if member.text and member.text.strip())
    scalar = text_or_none(entry, "./permitted-ip")
    if scalar:
        values.append(scalar)
    valid, invalid = [], []
    for value in values:
        try:
            ipaddress.ip_network(value, strict=False)
            valid.append(value)
        except ValueError:
            invalid.append(value)
    return valid, invalid


def _yes_no(value: str | None) -> bool | None:
    if value in {"yes", "no"}:
        return value == "yes"
    return None


def extract_administrators(root: ET.Element, extraction, resolver=None) -> None:
    shared_scope = PANScope(kind="shared", name="shared")
    role_profile_names = set()
    for container in (root.find("./mgt-config/profiles"), root.find("./mgt-config/admin-role"), root.find("./mgt-config/role")):
        if container is None:
            continue
        for entry in container.findall("./entry"):
            name = entry.get("name")
            if not name:
                record_parse_error(extraction, "admin_role_profiles", f"{container.tag}/entry", None,
                                   attributes=structured_xml_capture(entry), notes=["Missing administrator role-profile name."])
                continue
            profile = IRAdminProfile(
                name=name,
                permission_blocks=[IRAdminProfilePermissionBlock(name=child.tag, settings=structured_xml_capture(child) or {})
                                   for child in entry],
                source_attributes=sanitize_source_attributes({
                    "pan_source_entry": structured_xml_capture(entry),
                    "pan_scope_kind": "shared", "pan_scope_name": "shared",
                }),
            )
            role_profile_names.add(name)
            extraction.canonical_ir.admin_profiles.append(profile)
            if resolver is not None:
                resolver.register_object(PANSourceObject(
                    name=name, kind="admin-role-profile", domain="admin_role_profiles",
                    source_path=f"{container.tag}/entry", scope=shared_scope,
                    attributes=profile.source_attributes, ir_object=profile,
                ), "admin-role-profile")
            record_extract_only(extraction, "admin_role_profiles", f"{container.tag}/entry", None, name,
                                profile.source_attributes, ["PAN-OS administrator role-profile is source-only."], True)
    for entry in root.findall("./mgt-config/users/entry"):
        name, path = entry.get("name"), "mgt-config/users/entry"
        attrs = sanitize_source_attributes({"pan_source_entry": structured_xml_capture(entry)})
        if not name:
            record_parse_error(extraction, "administrators", path, None, attributes=attrs, notes=["Missing administrator name."])
            continue
        role = None
        role_based = entry.find("./permissions/role-based")
        if role_based is not None:
            for child in role_based:
                if (child.text or "").strip().lower() == "yes":
                    role = child.tag
                    break
        profile = text_or_none(entry, "./permissions/role-based/profile")
        auth = text_or_none(entry, "./authentication-profile")
        sequence = text_or_none(entry, "./authentication-sequence")
        valid_ips, invalid_ips = _permitted_ips(entry)
        cert_required = text_or_none(entry, "./certificate-authentication/required")
        if cert_required is None:
            cert_required = text_or_none(entry, "./require-certificate-authentication")
        certificate_profile = (
            text_or_none(entry, "./certificate-authentication/certificate-profile")
            or text_or_none(entry, "./certificate-profile")
        )
        disabled_value = text_or_none(entry, "./disabled")
        reasons = [] if role or profile else ["unknown-permissions"]
        reasons.extend(f"malformed-permitted-ip:{value}" for value in invalid_ips)
        if cert_required is not None and cert_required not in {"yes", "no"}:
            reasons.append(f"malformed-certificate-authentication-required:{cert_required}")
        if disabled_value is not None and disabled_value not in {"yes", "no"}:
            reasons.append(f"malformed-disabled:{disabled_value}")
        source = {
            **attrs,
            "pan_unknown_fields": collect_unknown_children(entry, [
                "permissions", "phash", "authentication-profile", "authentication-sequence",
                "permitted-ip", "certificate-authentication", "certificate-profile",
                "require-certificate-authentication", "disabled",
            ]),
            "pan_permitted_ips": [*valid_ips, *invalid_ips],
            "pan_invalid_permitted_ips": invalid_ips,
            "pan_certificate_authentication_required": cert_required,
            "pan_certificate_authentication_profile": certificate_profile,
            "pan_disabled": disabled_value,
        }
        item = IRAdministrator(
            name=name, source_context="shared:shared", access_profile=profile or role,
            credential_configured=entry.find("./phash") is not None,
            authentication_profile=auth, authentication_sequence=sequence,
            permitted_ips=valid_ips, invalid_permitted_ips=invalid_ips,
            certificate_authentication_required=_yes_no(cert_required),
            certificate_profile=certificate_profile, disabled=_yes_no(disabled_value),
            remote_auth=auth,
            source_attributes=sanitize_source_attributes({
                **source, "pan_role_name": role, "pan_role_profile_reference": profile,
            }),
            requires_manual_review=True,
        )
        if profile:
            item.access_profile_resolved = profile in role_profile_names
            if not item.access_profile_resolved:
                item.unresolved_references.append(profile)
        extraction.canonical_ir.administrators.append(item)
        record_extract_only(extraction, "administrators", path, None, name, item.source_attributes,
                            ["PAN-OS administrator is source-only inventory.", *reasons], requires_manual_review=True)
