"""Authoritative, secret-safe Check Point certificate metadata extraction."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, List, Tuple

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem
from fwmigrate.extraction.sanitize import sanitize_raw_text
from fwmigrate.ir.core import IRCertificate

_CERT_KEYS = {"subject", "issuer", "serial", "serial-number", "fingerprint", "certificate-uid"}
_SECRET_KEYS = {
    "private-key", "private_key", "private-key-data", "private_key_data", "key-data", "key_data",
    "password", "passphrase", "shared-secret", "shared_secret", "activation-key", "activation_key",
    "sic-password", "sic_password", "sic-password-hash", "sic_password_hash", "one-time-password",
    "one_time_password", "otp", "pkcs12-password", "pkcs12_password",
}
_SAFE_KEY_METADATA = {"key-usage", "public-key-algorithm", "public-key-size", "fingerprint-algorithm"}
_PURPOSE_KEYS = {
    "sic": "SIC", "sic-certificate": "SIC", "sic-certificate-uid": "SIC",
    "ike": "IKE", "ike-certificate": "IKE", "ike-certificate-uid": "IKE",
    "https-inspection": "HTTPS_INSPECTION_CA", "ca-certificate": "HTTPS_INSPECTION_CA",
}


def _command(response: Any) -> str:
    return str(getattr(response, "command", "")).lower().replace("_", "-")


def _objects(response: Any) -> Iterable[Dict[str, Any]]:
    objects = getattr(response, "data", {}).get("objects", [])
    if isinstance(objects, dict):
        objects = list(objects.values())
    return (item for item in objects if isinstance(item, dict))


def _is_certificate_object(obj: Dict[str, Any], source_family: str) -> bool:
    kind = str(obj.get("type") or obj.get("object-type") or "").lower()
    if "cert" in kind:
        return True
    return source_family == "server-certificates" and bool(_CERT_KEYS & set(obj))


def _is_certificate_reference(value: Any) -> bool:
    if isinstance(value, dict):
        return bool(value.get("uid") or value.get("name") or value.get("certificate-uid") or value.get("certificate_uid"))
    return isinstance(value, (str, int)) and bool(str(value).strip())


def _certificate_source_family(response: Any) -> str:
    command = _command(response)
    if command == "show-server-certificates":
        return "server-certificates"
    if command in {"show-gateways-and-servers", "show-simple-gateways", "show-simple-clusters"}:
        return "gateway"
    if "vpn" in command:
        return "vpn"
    if "https" in command or "inspection" in command:
        return "https-inspection"
    return "unknown"


def _date(value: Any) -> tuple[datetime | None, str | None]:
    if value in (None, ""):
        return None, None
    if isinstance(value, datetime):
        return value, None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")), None
    except (TypeError, ValueError):
        return None, str(value)


def _uid(obj: Dict[str, Any]) -> str | None:
    value = obj.get("uid") or obj.get("certificate-uid") or obj.get("certificate_uid")
    return str(value) if value not in (None, "") else None


def _safe_attributes(value: Any) -> Any:
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            normalized = str(key).lower().replace("_", "-")
            if normalized in {item.replace("_", "-") for item in _SECRET_KEYS}:
                continue
            result[key] = _safe_attributes(child)
        return result
    if isinstance(value, list):
        return [_safe_attributes(item) for item in value]
    if isinstance(value, str):
        return sanitize_raw_text(value)
    return value


def _identity(domain: str, domain_uid: str | None, domain_name: str | None,
              obj: Dict[str, Any], cert: IRCertificate) -> tuple[str, ...]:
    scope = (domain_uid or domain, domain_name or domain)
    if cert.source_uid:
        return *scope, "uid", cert.source_uid
    if cert.sha256_fingerprint:
        return *scope, "fingerprint", cert.sha256_fingerprint.lower()
    if cert.issuer and cert.serial_number:
        return *scope, "issuer-serial", cert.issuer, cert.serial_number
    return *scope, "subject-validity", cert.subject or "", str(cert.valid_from), str(cert.valid_until)


def _reference(value: Any) -> tuple[str | None, str | None]:
    if isinstance(value, dict):
        return (str(value.get("uid") or value.get("certificate-uid") or value.get("certificate_uid") or "") or None,
                str(value.get("name") or "") or None)
    return str(value), None


def _global_reference_flags(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        key.replace("-", "_"): value[key]
        for key in ("global-assignment", "global_assignment", "global-provenance", "global_provenance")
        if value.get(key)
    }


def _usage_from_object(obj: Dict[str, Any], consumer_type: str, consumer_uid: Any, consumer_name: Any,
                       path: str, domain_uid: str | None, domain_name: str) -> List[dict]:
    uses = []
    for key, value in obj.items():
        if str(key).lower().replace("_", "-") == "sic" and isinstance(value, dict):
            cert_value = value.get("certificate") or value.get("certificate-reference")
            if _is_certificate_reference(cert_value):
                uid, name = _reference(cert_value)
                uses.append({"certificate_uid": uid, "certificate_name": name, **_global_reference_flags(cert_value), "domain_uid": domain_uid,
                             "domain_name": domain_name, "consumer_type": consumer_type,
                             "consumer_uid": consumer_uid, "consumer_name": consumer_name, "usage": "SIC",
                             "source_path": path})
            continue
        purpose = _PURPOSE_KEYS.get(str(key).lower().replace("_", "-"))
        if not purpose and key not in {"certificate", "certificate-reference", "certificate-references", "ca-certificate"}:
            continue
        values = value if isinstance(value, list) else [value]
        for item in values:
            if not _is_certificate_reference(item):
                continue
            uid, name = _reference(item)
            uses.append({"certificate_uid": uid, "certificate_name": name, **_global_reference_flags(item), "domain_uid": domain_uid,
                         "domain_name": domain_name, "consumer_type": consumer_type,
                         "consumer_uid": consumer_uid, "consumer_name": consumer_name, "usage": purpose or "UNKNOWN",
                         "source_path": path})
    return uses


def extract_certificates(responses: Iterable[Any], usage_sources: Iterable[Any] = ()) -> Tuple[List[IRCertificate], List[SourceInventoryItem]]:
    result: List[IRCertificate] = []
    inventory: List[SourceInventoryItem] = []
    by_identity: Dict[tuple[str, ...], IRCertificate] = {}
    all_usage: List[dict] = []

    for response in responses:
        family = _certificate_source_family(response)
        domain = str(getattr(response, "domain", None) or "global")
        domain_uid = getattr(response, "domain_uid", None)
        domain_name = str(getattr(response, "domain_name", None) or domain)
        for index, obj in enumerate(_objects(response)):
            path = f"checkpoint/{_command(response)}/objects/{index}"
            if family == "gateway":
                all_usage.extend(_usage_from_object(obj, "gateway", obj.get("uid"), obj.get("name"), path, domain_uid, domain_name))
            if not _is_certificate_object(obj, family):
                if family == "unknown" and _CERT_KEYS & set(obj):
                    inventory.append(SourceInventoryItem(domain=domain, source_path=path, name=str(obj.get("name") or obj.get("uid") or "<unknown-certificate>"),
                        source_id=_uid(obj), source_type="checkpoint-certificate", source_attributes=_safe_attributes(obj),
                        status=ExtractionStatus.EXTRACT_ONLY, requires_manual_review=True, notes=["unknown certificate-looking structure retained as evidence"]))
                continue
            uid = _uid(obj)
            name = str(obj.get("name") or uid or f"certificate-{len(result) + 1}")
            valid_from, invalid_from = _date(obj.get("valid-from") if "valid-from" in obj else obj.get("valid_from"))
            valid_until, invalid_until = _date(obj.get("valid-until") if "valid-until" in obj else obj.get("valid_until"))
            review_reasons = []
            if invalid_from is not None: review_reasons.append("invalid-certificate-valid-from")
            if invalid_until is not None: review_reasons.append("invalid-certificate-valid-until")
            fingerprint = obj.get("sha256-fingerprint") or obj.get("fingerprint")
            kind = _PURPOSE_KEYS.get(str(obj.get("purpose") or obj.get("kind") or "").lower(), "UNKNOWN")
            cert = IRCertificate(name=name, certificate_type=str(obj.get("type") or "checkpoint"), source_uid=uid,
                source_context=getattr(response, "gateway", None) or domain, kind=kind,
                status=str(obj.get("status") or "unknown"), fingerprint_algorithm=obj.get("fingerprint-algorithm") or ("SHA-256" if fingerprint else None),
                subject=obj.get("subject"), issuer=obj.get("issuer"), serial_number=obj.get("serial-number") or obj.get("serial"),
                sha256_fingerprint=fingerprint, valid_from=valid_from, valid_until=valid_until,
                ca_reference=obj.get("ca-reference") or obj.get("ca_reference") or obj.get("ca"),
                is_ca=obj.get("is-ca") if isinstance(obj.get("is-ca"), bool) else None,
                has_certificate=bool(obj.get("certificate") or obj.get("public-certificate") or _CERT_KEYS & set(obj)),
                has_private_key=any(str(key).lower().replace("_", "-") in {"private-key", "private-key-data"} for key in obj),
                migration_status=ExtractionStatus.PARTIALLY_NORMALIZED.value if review_reasons else ExtractionStatus.NORMALIZED.value,
                requires_manual_review=bool(review_reasons), review_reasons=review_reasons,
                source_attributes={**_safe_attributes(obj), "domain_uid": domain_uid, "domain_name": domain_name,
                                   "source_command": getattr(response, "command", None), "source_path": path})
            identity = _identity(domain, domain_uid, domain_name, obj, cert)
            existing = by_identity.get(identity)
            if existing is None:
                by_identity[identity] = cert
                result.append(cert)
                existing = cert
            all_usage.extend(_usage_from_object(obj, "certificate", uid, name, path, domain_uid, domain_name))
            inventory.append(SourceInventoryItem(domain=domain, source_path=path, name=name, source_id=uid,
                source_context=cert.source_context, source_type="checkpoint-certificate", source_attributes=cert.source_attributes,
                status=ExtractionStatus.PARTIALLY_NORMALIZED if review_reasons else ExtractionStatus.NORMALIZED,
                requires_manual_review=bool(review_reasons), notes=review_reasons or ["certificate metadata only; secret material excluded"]))

    for source in usage_sources:
        if not isinstance(source, (list, tuple)):
            continue
        for record in source:
            attrs = record.model_dump() if hasattr(record, "model_dump") else record
            refs = attrs.get("certificate_references") or ([attrs.get("certificate_reference")] if attrs.get("certificate_reference") else [])
            for reference in refs:
                uid, name = _reference(reference)
                all_usage.append({"certificate_uid": uid, "certificate_name": name, **_global_reference_flags(reference),
                    "domain_uid": attrs.get("domain_uid"), "domain_name": attrs.get("domain_name") or attrs.get("domain") or "global",
                    "consumer_type": "vpn",
                    "consumer_uid": attrs.get("uid"), "consumer_name": attrs.get("name"), "usage": "IKE",
                    "source_path": "checkpoint/vpn"})
    for use in all_usage:
        use_domain_uid = use.get("domain_uid")
        use_domain_name = use.get("domain_name") or "global"
        def same_scope(cert: IRCertificate) -> bool:
            attrs = cert.source_attributes
            return ((use_domain_uid and attrs.get("domain_uid") == use_domain_uid)
                    or (not use_domain_uid and attrs.get("domain_name", "global") == use_domain_name))
        matches = [cert for cert in result if same_scope(cert) and use.get("certificate_uid")
                   and cert.source_uid == use["certificate_uid"]]
        if not matches and use.get("certificate_name"):
            matches = [cert for cert in result if same_scope(cert) and cert.name == use["certificate_name"]]
        if not matches and (use.get("global_assignment") or use.get("global_provenance")):
            matches = [cert for cert in result if (use.get("certificate_uid") and cert.source_uid == use["certificate_uid"])
                       or (use.get("certificate_name") and cert.name == use["certificate_name"])]
        for cert in matches:
            if use not in cert.usage_references:
                cert.usage_references.append(use)
            if cert.kind == "UNKNOWN" and use.get("usage") in {"SIC", "IKE", "HTTPS_INSPECTION_CA"}:
                cert.kind = use["usage"]
        if not matches:
            inventory.append(SourceInventoryItem(
                domain=use_domain_name, domain_uid=use_domain_uid, domain_name=use_domain_name,
                source_path=str(use.get("source_path") or "checkpoint/certificate-reference"),
                name=use.get("certificate_name") or use.get("certificate_uid"),
                source_id=use.get("certificate_uid"), source_type="checkpoint-certificate-reference",
                source_attributes=_safe_attributes(use), status=ExtractionStatus.PARTIALLY_NORMALIZED,
                requires_manual_review=True, notes=["unresolved-certificate-reference"],
            ))
    return result, inventory


def attach_certificate_usages(certificates: List[IRCertificate], sources: Iterable[Any]) -> None:
    """Attach already-parsed HTTPS/VPN references without creating definitions."""
    for source in sources:
        if not isinstance(source, (list, tuple)):
            continue
        for record in source:
            attrs = record.model_dump() if hasattr(record, "model_dump") else record
            reference = attrs.get("certificate") or attrs.get("certificate_reference")
            if not reference:
                continue
            uid, name = _reference(reference)
            use_domain_uid = attrs.get("domain_uid")
            use_domain_name = attrs.get("domain_name") or attrs.get("domain") or "global"
            def same_scope(item: IRCertificate) -> bool:
                item_attrs = item.source_attributes
                return ((use_domain_uid and item_attrs.get("domain_uid") == use_domain_uid)
                        or (not use_domain_uid and item_attrs.get("domain_name", "global") == use_domain_name))
            matches = [item for item in certificates if same_scope(item) and uid and item.source_uid == uid]
            if not matches and name:
                matches = [item for item in certificates if same_scope(item) and item.name == name]
            usage = "HTTPS_INSPECTION_CA" if "certificate" in attrs and "source_uuid" in attrs else "IKE"
            relation = {"certificate_uid": uid, "certificate_name": name, "domain_uid": use_domain_uid,
                "domain_name": use_domain_name, "consumer_type": "https-inspection" if usage.startswith("HTTPS") else "vpn",
                "consumer_uid": attrs.get("source_uuid") or attrs.get("uid"), "consumer_name": attrs.get("name"), "usage": usage,
                "source_path": "checkpoint/https-inspection" if usage.startswith("HTTPS") else "checkpoint/vpn"}
            for item in matches:
                if relation not in item.usage_references:
                    item.usage_references.append(relation)
                if item.kind == "UNKNOWN":
                    item.kind = usage
