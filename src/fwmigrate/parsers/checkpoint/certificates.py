"""Secret-safe extraction of certificate metadata from Check Point objects."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple
from datetime import datetime

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem
from fwmigrate.ir.core import IRCertificate


def _walk(value: Any, path: str = "") -> Iterable[Tuple[Dict[str, Any], str]]:
    if isinstance(value, dict):
        if any(key in value for key in ("subject", "issuer", "serial", "serial-number", "fingerprint", "certificate-uid")):
            yield value, path
        for key, child in value.items(): yield from _walk(child, f"{path}/{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value): yield from _walk(child, f"{path}/{index}")


def _date(value: Any) -> Any:
    if not value: return None
    if isinstance(value, datetime): return value
    try: return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError: return None


def extract_certificates(responses: Iterable[Any]) -> Tuple[List[IRCertificate], List[SourceInventoryItem]]:
    result: List[IRCertificate] = []
    inventory: List[SourceInventoryItem] = []
    seen = set()
    for response in responses:
        for obj, path in _walk(response.data):
            uid = obj.get("uid") or obj.get("certificate-uid") or obj.get("certificate_uid")
            name = str(obj.get("name") or uid or f"certificate-{len(result) + 1}")
            key = (str(uid or name), path)
            if key in seen: continue
            seen.add(key)
            attrs = {k: v for k, v in obj.items() if not any(secret in str(k).lower() for secret in ("private", "password", "passphrase", "secret", "key"))}
            cert = IRCertificate(name=name, certificate_type=str(obj.get("type") or "checkpoint"), subject=obj.get("subject"), issuer=obj.get("issuer"),
                serial_number=obj.get("serial-number") or obj.get("serial"), sha256_fingerprint=obj.get("sha256-fingerprint") or obj.get("fingerprint"),
                valid_from=_date(obj.get("valid-from") or obj.get("valid_from")), valid_until=_date(obj.get("valid-until") or obj.get("valid_until")),
                ca_reference=obj.get("ca-reference") or obj.get("ca_reference") or obj.get("ca"), usage=path,
                source_attributes={**attrs, "usage": path}, has_certificate=True)
            result.append(cert)
            inventory.append(SourceInventoryItem(domain=response.domain or "global", source_path=f"checkpoint/certificates{path}", name=name,
                source_id=uid, source_type="certificate", source_attributes=cert.source_attributes,
                status=ExtractionStatus.EXTRACT_ONLY, requires_manual_review=True, notes=["certificate metadata only; secret material excluded"]))
    return result, inventory
