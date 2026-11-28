"""Public-only X.509 certificate inspection helpers for source reporting."""

from __future__ import annotations

from datetime import datetime, timezone
from re import DOTALL, compile as re_compile
from typing import Any

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

_PEM_CERT_RE = re_compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    DOTALL,
)
_EXPIRING_SOON_DAYS = 30


def extract_pem_block(text: str | None) -> str | None:
    """Return the first public X.509 PEM certificate block if present (never private keys)."""
    if not text:
        return None
    match = _PEM_CERT_RE.search(text)
    return match.group(0) if match else None


def classify_expiry(expires_at: datetime, now: datetime | None = None) -> tuple[int, str]:
    """Return (days_left, status) for a UTC expiration timestamp."""
    now_dt = now or datetime.now(timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    days_left = (expires_at - now_dt).days
    if days_left < 0:
        return days_left, "Expired"
    if days_left < _EXPIRING_SOON_DAYS:
        return days_left, "Expiring Soon"
    return days_left, "Valid"


def parse_panos_cert_time(value: str | None) -> datetime | None:
    """Parse PAN-OS XML not-valid-before / not-valid-after timestamps."""
    text = str(value or "").strip()
    if not text or text == "-":
        return None
    for fmt in ("%b %d %H:%M:%S %Y GMT", "%b  %d %H:%M:%S %Y GMT", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _attr_value(name: x509.Name, oid: x509.ObjectIdentifier) -> str:
    attrs = name.get_attributes_for_oid(oid)
    return str(attrs[0].value) if attrs else "-"


def _cert_dates(cert: x509.Certificate) -> tuple[datetime, datetime]:
    not_before = getattr(cert, "not_valid_before_utc", None)
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_before is None:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
    if not_after is None:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return not_before, not_after


def parse_pem_certificate(pem_text: str, now: datetime | None = None) -> dict[str, Any] | None:
    """Parse a public X.509 PEM certificate into display metadata."""
    pem_block = extract_pem_block(pem_text)
    if not pem_block:
        return None
    try:
        cert = x509.load_pem_x509_certificate(pem_block.encode("utf-8", errors="ignore"))
    except Exception:
        return None

    not_before, not_after = _cert_dates(cert)
    days_left, status = classify_expiry(not_after, now=now)

    cn = _attr_value(cert.subject, NameOID.COMMON_NAME)
    issuer_cn = _attr_value(cert.issuer, NameOID.COMMON_NAME)
    if issuer_cn == "-":
        issuer_cn = _attr_value(cert.issuer, NameOID.ORGANIZATION_NAME)

    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        for dns in san_ext.get_values_for_type(x509.DNSName):
            sans.append(str(dns))
        for ip in san_ext.get_values_for_type(x509.IPAddress):
            sans.append(str(ip))
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass

    san_display = ", ".join(sans[:6]) + ("..." if len(sans) > 6 else "") if sans else "-"
    return {
        "common_name": cn,
        "san": san_display,
        "issuer": issuer_cn,
        "not_before": not_before.strftime("%Y-%m-%d"),
        "expires": not_after.strftime("%Y-%m-%d"),
        "days_left": days_left,
        "status": status,
    }


def summarize_certificates(rows: list[dict[str, Any]]) -> dict[str, int]:
    """Count certificate rows by expiry classification."""
    return {
        "total": len(rows),
        "expired": sum(1 for row in rows if row.get("status") == "Expired"),
        "expiring_soon": sum(1 for row in rows if row.get("status") == "Expiring Soon"),
        "valid": sum(1 for row in rows if row.get("status") == "Valid"),
        "no_pem": sum(1 for row in rows if row.get("status") == "No PEM"),
    }
