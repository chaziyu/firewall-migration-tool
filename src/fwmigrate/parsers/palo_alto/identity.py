"""PAN-OS identity definitions and deferred reference correlation."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Optional

from fwmigrate.extraction.sanitize import sanitize_source_attributes
from fwmigrate.ir.core import (
    IRAuthenticationScheme, IRAuthenticationSequence, IRIdentityServerEndpoint,
    IRLocalUser, IRUserLDAP, IRUserRADIUS, IRUserSAML, IRUserTACACS,
)
from .extraction import record_extract_only, record_parse_error
from .source_model import PANScope, PANSourceObject
from .xml_utils import collect_unknown_children, member_texts, structured_xml_capture, text_or_none


def _capture(node: ET.Element) -> dict:
    return sanitize_source_attributes({"pan_source_entry": structured_xml_capture(node)})


def _scope_attrs(scope: PANScope) -> dict:
    return {"pan_scope_kind": scope.kind, "pan_scope_name": scope.name,
            "pan_device_serial": scope.device_serial, "pan_device_name": scope.device_name,
            "pan_vsys": scope.vsys, "pan_device_group": scope.device_group}


def _record_profiles(scope: PANScope, root: ET.Element, extraction, resolver, families: tuple[tuple[str, str, tuple[str, ...]], ...]) -> None:
    for xml_name, domain, fields in families:
        for entry in root.findall(f"./server-profile/{xml_name}/entry"):
            name = entry.get("name")
            path = f"server-profile/{xml_name}/entry"
            attrs = {"pan_source_entry": structured_xml_capture(entry), **_scope_attrs(scope),
                     "pan_fields": {field: structured_xml_capture(entry.find(f"./{field}"))
                                    for field in fields if entry.find(f"./{field}") is not None}}
            if xml_name == "kerberos":
                attrs["pan_server_entries"] = [
                    {"name": server.get("name"), "host": text_or_none(server, "./host") or text_or_none(server, "./address"),
                     "port": text_or_none(server, "./port"), "source": structured_xml_capture(server)}
                    for server in entry.findall("./server/entry")
                ]
            if xml_name == "saml-idp":
                attrs["pan_saml"] = {key: text_or_none(entry, path) for key, path in {
                    "entity_id": "./entity-id", "idp_entity_id": "./idp-entity-id",
                    "certificate": "./certificate", "idp_certificate": "./idp-certificate",
                    "sso_url": "./sso-url", "slo_url": "./slo-url",
                    "sso_binding": "./sso-binding", "slo_binding": "./slo-binding",
                    "validate_identity_provider_certificate": "./validate-idp-certificate",
                }.items() if entry.find(path) is not None}
            if not name:
                record_parse_error(extraction, domain, path, scope, attributes=attrs, notes=["Missing profile name."])
                continue
            attrs = sanitize_source_attributes(attrs)
            if xml_name == "saml-idp":
                saml = attrs.get("pan_saml", {})
                ir_item = IRUserSAML(name=name, entity_id=saml.get("entity_id"), idp_entity_id=saml.get("idp_entity_id"),
                                     single_sign_on_url=saml.get("sso_url"), single_logout_url=saml.get("slo_url"),
                                     idp_single_sign_on_url=saml.get("sso_url"), idp_single_logout_url=saml.get("slo_url"),
                                     idp_cert=saml.get("idp_certificate"), cert=saml.get("certificate"),
                                     source_attributes=attrs)
                extraction.canonical_ir.user_saml_servers.append(ir_item)
            resolver.register_object(PANSourceObject(name=name, kind=domain, domain="identity", source_path=path,
                                                     scope=scope, attributes=attrs, ir_object=ir_item if xml_name == "saml-idp" else None), domain)
            record_extract_only(extraction, domain, path, scope, name, attrs,
                                 [f"PAN-OS {xml_name} profile is retained as source-only inventory."],
                                 requires_manual_review=True)


def _record_user_id(scope: PANScope, root: ET.Element, extraction) -> None:
    for xml_name in ("user-identification", "user-id", "userid"):
        node = root.find(f"./{xml_name}")
        if node is None:
            continue
        attrs = sanitize_source_attributes({"pan_source_entry": structured_xml_capture(node),
                                            "pan_scope_kind": scope.kind, "pan_scope_name": scope.name,
                                            "pan_redistribution": structured_xml_capture(node.find("./redistribution")),
                                            "pan_members": [structured_xml_capture(child) for child in node.findall("./*/member")]})
        record_extract_only(extraction, "user_id_settings", xml_name, scope, None, attrs,
                            ["PAN-OS User-ID settings are retained as source-only inventory."], requires_manual_review=True)


def _item_scope(item) -> PANScope:
    attrs = item.source_attributes
    return PANScope(kind=attrs.get("pan_scope_kind") or "shared", name=attrs.get("pan_scope_name") or "shared",
                    device_serial=attrs.get("pan_device_serial"), device_name=attrs.get("pan_device_name"),
                    vsys=attrs.get("pan_vsys"), device_group=attrs.get("pan_device_group"))


def _port(node: ET.Element, path: str, attrs: dict, reasons: list[str]) -> Optional[int]:
    value = text_or_none(node, path)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        attrs.setdefault("pan_malformed_fields", {})[path] = value
        reasons.append(f"malformed-port:{value}")
        return None


def _endpoints(entry: ET.Element, secret_tags: tuple[str, ...], address_tag: str) -> tuple[list[IRIdentityServerEndpoint], list[str]]:
    result, reasons = [], []
    for server in entry.findall("./server/entry"):
        address = text_or_none(server, f"./{address_tag}")
        attrs = {"pan_source_entry": structured_xml_capture(server)}
        has_secret = any(server.find(f"./{tag}") is not None for tag in secret_tags)
        if not address:
            reasons.append("missing-endpoint-address")
        port = None
        raw_port = text_or_none(server, "./port")
        if raw_port:
            try:
                port = int(raw_port)
            except ValueError:
                reasons.append(f"malformed-port:{raw_port}")
                attrs["pan_malformed_port"] = raw_port
        result.append(IRIdentityServerEndpoint(
            name=server.get("name"), address=address, port=port,
            has_secret=has_secret, source_attributes=sanitize_source_attributes(attrs),
        ))
    return result, reasons


def _register(resolver, name, kind, path, scope, item):
    if name:
        resolver.register_object(PANSourceObject(
            name=name, kind=kind, domain="identity", source_path=path,
            scope=scope, ir_object=item,
        ), kind)


def extract_identity(scope: PANScope, root: ET.Element, extraction, resolver) -> None:
    ir = extraction.canonical_ir
    _record_profiles(scope, root, extraction, resolver, (
        ("kerberos", "kerberos-server-profile", ("server",)),
        ("saml-idp", "saml-idp-server-profile", ("idp-entity-id", "idp-certificate", "sso-url", "slo-url", "sso-bindings", "slo-bindings")),
        ("mfa", "mfa-server-profile", ("vendor", "certificate", "config")),
        ("multi-factor-authentication", "mfa-server-profile", ("vendor", "certificate", "config")),
        ("group-mapping", "group-mapping-profile", ("group-include-list", "group-exclude-list", "custom-group")),
    ))
    _record_user_id(scope, root, extraction)
    for family, cls, kind, secret_tags, address_tag in (
        ("tacplus", IRUserTACACS, "tacacs-server-profile", ("shared-secret", "secret"), "address"),
        ("radius", IRUserRADIUS, "radius-server-profile", ("shared-secret", "secret"), "ip-address"),
        ("ldap", IRUserLDAP, "ldap-server-profile", ("bind-password", "password"), "address"),
    ):
        for entry in root.findall(f"./server-profile/{family}/entry"):
            name, path = entry.get("name"), f"server-profile/{family}/entry"
            attrs = _capture(entry)
            reasons: list[str] = []
            endpoints, endpoint_reasons = _endpoints(entry, secret_tags, address_tag)
            reasons.extend(endpoint_reasons)
            if not name:
                record_parse_error(extraction, kind, path, scope, attributes=attrs, notes=["Missing profile name."])
                continue
            values = {"name": name, "source_context": f"{scope.kind}:{scope.name}", "server_entries": endpoints,
                      "server": endpoints[0].address if endpoints else None,
                      "secondary_server": endpoints[1].address if len(endpoints) > 1 else None,
                      "tertiary_server": endpoints[2].address if len(endpoints) > 2 else None,
                      "port": endpoints[0].port if endpoints else None}
            if family == "ldap":
                values.update(
                              source_type=text_or_none(entry, "./ldap-type"),
                              username=text_or_none(entry, "./bind-dn"),
                              has_password=entry.find("./bind-password") is not None,
                              secure=text_or_none(entry, "./ssl"), dn=text_or_none(entry, "./base"))
            elif family == "radius":
                protocols = [child.tag for child in entry.findall("./protocol/*")]
                values.update(
                              auth_type=protocols[0] if len(protocols) == 1 else None,
                              has_secret=any(e.has_secret for e in endpoints))
                if len(protocols) != 1: reasons.append("ambiguous-protocol" if protocols else "missing-protocol")
            else:
                values.update(server=endpoints[0].address if endpoints else None,
                              port=endpoints[0].port if endpoints else None,
                              authentication_type=text_or_none(entry, "./protocol"),
                              has_secret=any(e.has_secret for e in endpoints))
            known = ["server", "protocol", "ldap-type", "bind-dn", "bind-password", "ssl", "base"]
            attrs["pan_unknown_fields"] = collect_unknown_children(entry, known)
            attrs = sanitize_source_attributes(attrs)
            item = cls(**values, source_attributes=attrs)
            getattr(ir, {"ldap": "user_ldap_servers", "radius": "user_radius_servers", "tacplus": "user_tacacs_servers"}[family]).append(item)
            _register(resolver, name, kind, path, scope, item)
            note = ["PAN-OS identity server profile is retained as source-only inventory."] + reasons
            record_extract_only(extraction, kind, path, scope, name, attrs, note, requires_manual_review=True)

    for entry in root.findall("./authentication-profile/entry"):
        name, path = entry.get("name"), "authentication-profile/entry"
        attrs = _capture(entry)
        method_root = entry.find("./method")
        methods = [(child.tag, text_or_none(child, "./server-profile")) for child in method_root or [] if child.tag in {"local-database", "ldap", "radius", "tacplus", "saml"}]
        all_methods = [child.tag for child in method_root or []]
        reasons = []
        if not name:
            record_parse_error(extraction, "authentication_profiles", path, scope, attributes=attrs, notes=["Missing profile name."])
            continue
        method = methods[0][0] if len(methods) == 1 else None
        if len(methods) != 1: reasons.append("multiple-or-missing-method")
        unsupported = [tag for tag in all_methods if tag not in {"local-database", "ldap", "radius", "tacplus", "saml"}]
        reasons.extend(f"unsupported-method:{tag}" for tag in unsupported)
        token = methods[0][1] if methods and method != "local-database" else ("local-database" if method == "local-database" else None)
        if method == "local-database": token = "local-database"
        item = IRAuthenticationScheme(name=name, method=method, user_database=token,
                                      source_attributes=sanitize_source_attributes({**attrs, **_scope_attrs(scope), "pan_method": structured_xml_capture(method_root), "pan_unknown_fields": collect_unknown_children(entry, ["method"])}))
        ir.authentication_schemes.append(item)
        _register(resolver, name, "authentication-profile", path, scope, item)
        record_extract_only(extraction, "authentication_profiles", path, scope, name, item.source_attributes, ["PAN-OS authentication profile is source-only inventory.", *reasons], requires_manual_review=True)

    for entry in root.findall("./authentication-sequence/entry"):
        name, path = entry.get("name"), "authentication-sequence/entry"
        attrs = _capture(entry)
        if not name:
            record_parse_error(extraction, "authentication_sequences", path, scope, attributes=attrs, notes=["Missing sequence name."])
            continue
        item = IRAuthenticationSequence(name=name, source_context=f"{scope.kind}:{scope.name}",
            authentication_profiles=member_texts(entry, "./authentication-profiles/member"),
            source_attributes={**attrs, **_scope_attrs(scope)})
        ir.authentication_sequences.append(item)
        _register(resolver, name, "authentication-sequence", path, scope, item)
        record_extract_only(extraction, "authentication_sequences", path, scope, name, attrs, ["Authentication sequence order is preserved as source-only inventory."], requires_manual_review=True)

    for entry in root.findall("./local-user-database/user/entry"):
        name, path = entry.get("name"), "local-user-database/user/entry"
        attrs = _capture(entry)
        if not name:
            record_parse_error(extraction, "local_users", path, scope, attributes=attrs, notes=["Missing username."])
            continue
        disabled = text_or_none(entry, "./disabled")
        status = {"yes": "disabled", "no": "enabled"}.get(disabled.lower()) if disabled else None
        reasons = [] if disabled is None or disabled.lower() in {"yes", "no"} else ["malformed-disabled"]
        item = IRLocalUser(name=name, status=status, source_type="pan-local-user-database",
                           has_password=entry.find("./phash") is not None, source_attributes=attrs,
                           requires_manual_review=True)
        ir.local_users.append(item)
        record_extract_only(extraction, "local_users", path, scope, name, attrs, ["PAN-OS local user is source-only inventory.", *reasons], requires_manual_review=True)


def finalize_identity_references(extraction, resolver) -> None:
    ir = extraction.canonical_ir
    shared_scope = PANScope(kind="shared", name="shared")
    types = {"ldap": "ldap-server-profile", "radius": "radius-server-profile", "tacplus": "tacacs-server-profile", "saml": "saml-idp-server-profile"}
    for item in ir.authentication_schemes:
        if item.method in types and item.user_database:
            obj = resolver.resolve(item.user_database, types[item.method], _item_scope(item))
            if obj: item.resolved_user_databases = [obj.canonical_name or item.user_database]
            else: item.unresolved_user_databases = [item.user_database]
    for item in ir.authentication_sequences:
        for name in item.authentication_profiles:
            obj = resolver.resolve(name, "authentication-profile", _item_scope(item))
            (item.resolved_authentication_profiles if obj else item.unresolved_authentication_profiles).append(obj.canonical_name if obj and obj.canonical_name else name)
    if ir.user_authentication_settings and ir.user_authentication_settings.management_authentication_profile:
        name = ir.user_authentication_settings.management_authentication_profile
        obj = resolver.resolve(name, "authentication-profile", shared_scope)
        ir.user_authentication_settings.management_authentication_profile_resolved = obj is not None
        if obj is None:
            ir.user_authentication_settings.unresolved_management_authentication_profile = name
    for item in ir.administrators:
        if item.authentication_profile:
            item.authentication_profile_resolved = resolver.resolve(item.authentication_profile, "authentication-profile", shared_scope) is not None
        if item.authentication_sequence:
            item.authentication_sequence_resolved = resolver.resolve(item.authentication_sequence, "authentication-sequence", shared_scope) is not None
