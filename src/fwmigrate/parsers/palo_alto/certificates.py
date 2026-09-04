"""PAN-OS certificates and certificate-consuming TLS profiles."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from fwmigrate.extraction.sanitize import sanitize_source_attributes
from fwmigrate.ir.core import IRCertificate, IRSSLTLSServiceProfile
from .extraction import record_extract_only, record_parse_error
from .source_model import PANScope, PANSourceObject
from .xml_utils import collect_unknown_children, structured_xml_capture, text_or_none


def _attrs(entry):
    return sanitize_source_attributes({"pan_source_entry": structured_xml_capture(entry)})


def extract_certificates(scope: PANScope, root: ET.Element, extraction, resolver) -> None:
    ir = extraction.canonical_ir
    for entry in root.findall("./certificate/entry"):
        name, path = entry.get("name"), "certificate/entry"
        attrs = _attrs(entry)
        if not name:
            record_parse_error(extraction, "certificates", path, scope, attributes=attrs, notes=["Missing certificate name."])
            continue
        cert_node = entry.find("./certificate")
        item = IRCertificate(
            name=name, certificate_type="pan-os",
            public_certificate_pem=(cert_node.text.strip() if cert_node is not None and cert_node.text else None),
            subject=text_or_none(entry, "./subject"), issuer=text_or_none(entry, "./issuer"),
            serial_number=text_or_none(entry, "./serial-number"),
            public_key_algorithm=text_or_none(entry, "./public-key-algorithm"),
            has_certificate=cert_node is not None,
            has_private_key=entry.find("./private-key") is not None,
            source_attributes=sanitize_source_attributes({**attrs, "pan_unknown_fields": collect_unknown_children(entry, ["certificate", "private-key", "subject", "issuer", "serial-number", "public-key-algorithm"])}),
        )
        ir.certificates.append(item)
        resolver.register_object(PANSourceObject(name=name, kind="certificate", domain="certificates", source_path=path, scope=scope, ir_object=item), "certificate")
        record_extract_only(extraction, "certificates", path, scope, name, item.source_attributes, ["PAN-OS certificate metadata is source-only inventory."], requires_manual_review=True)

    for node in root.iter():
        if node.tag.lower() in {"trusted-root-ca", "trusted-root-certificate", "trusted-root"}:
            reference = (node.text or "").strip()
            if reference:
                for item in ir.certificates:
                    if item.name == reference:
                        item.source_attributes.setdefault("pan_trusted_root_references", []).append(reference)

    for entry in root.findall("./ssl-tls-service-profile/entry"):
        name, path = entry.get("name"), "ssl-tls-service-profile/entry"
        attrs = _attrs(entry)
        if not name:
            record_parse_error(extraction, "ssl_tls_service_profiles", path, scope, attributes=attrs, notes=["Missing TLS service profile name."])
            continue
        cert = text_or_none(entry, "./certificate") or text_or_none(entry, "./certificate-profile")
        item = IRSSLTLSServiceProfile(name=name, source_context=f"{scope.kind}:{scope.name}", certificate=cert,
            minimum_tls_version=text_or_none(entry, "./min-version"), maximum_tls_version=text_or_none(entry, "./max-version"), source_attributes=attrs)
        ir.ssl_tls_service_profiles.append(item)
        resolver.register_object(PANSourceObject(name=name, kind="ssl-tls-service-profile", domain="certificates", source_path=path, scope=scope, ir_object=item), "ssl-tls-service-profile")
        record_extract_only(extraction, "ssl_tls_service_profiles", path, scope, name, attrs, ["PAN-OS SSL/TLS service profile is source-only inventory."], requires_manual_review=True)


def finalize_certificate_references(extraction, resolver) -> None:
    for item in extraction.canonical_ir.ssl_tls_service_profiles:
        if item.certificate:
            obj = resolver.resolve(item.certificate, "certificate", None)
            item.certificate_resolved = obj is not None
            if obj is None: item.review_reasons.append("unresolved-certificate-reference")
