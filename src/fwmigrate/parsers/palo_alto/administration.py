"""PAN-OS firewall administrator inventory."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from fwmigrate.extraction.sanitize import sanitize_source_attributes
from fwmigrate.ir.core import IRAdminProfile, IRAdminProfilePermissionBlock, IRAdministrator
from .extraction import record_extract_only, record_parse_error
from .xml_utils import collect_unknown_children, structured_xml_capture, text_or_none


def extract_administrators(root: ET.Element, extraction) -> None:
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
            blocks = [IRAdminProfilePermissionBlock(name=child.tag, settings=structured_xml_capture(child) or {})
                      for child in entry]
            profile = IRAdminProfile(name=name, permission_blocks=blocks,
                                     source_attributes=sanitize_source_attributes({"pan_source_entry": structured_xml_capture(entry)}))
            role_profile_names.add(name)
            extraction.canonical_ir.admin_profiles.append(profile)
            record_extract_only(extraction, "admin_role_profiles", f"{container.tag}/entry", None, name,
                                profile.source_attributes, ["PAN-OS administrator role-profile is source-only."], True)
    users = root.findall("./mgt-config/users/entry")
    for entry in users:
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
        reasons = [] if role or profile else ["unknown-permissions"]
        source = {**attrs, "pan_unknown_fields": collect_unknown_children(entry, ["permissions", "phash", "authentication-profile", "authentication-sequence"])}
        item = IRAdministrator(name=name, access_profile=profile or role,
            credential_configured=entry.find("./phash") is not None,
            authentication_profile=auth, authentication_sequence=sequence,
            remote_auth=auth, source_attributes=sanitize_source_attributes({**source, "pan_role_name": role,
                                                                              "pan_role_profile_reference": profile}),
            requires_manual_review=True)
        if profile:
            item.access_profile_resolved = profile in role_profile_names
            if not item.access_profile_resolved:
                item.unresolved_references.append(profile)
        extraction.canonical_ir.administrators.append(item)
        record_extract_only(extraction, "administrators", path, None, name, item.source_attributes,
                            ["PAN-OS administrator is source-only inventory.", *reasons], requires_manual_review=True)
