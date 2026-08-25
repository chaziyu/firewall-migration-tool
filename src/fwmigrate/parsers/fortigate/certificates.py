"""Safe X.509 metadata extraction for FortiGate certificate inventory."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, TypedDict

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed25519,
    ed448,
    padding,
    rsa,
)


class CertificateMetadata(TypedDict):
    subject: Optional[str]
    issuer: Optional[str]
    serial_number: Optional[str]
    valid_from: Optional[datetime]
    valid_until: Optional[datetime]
    public_key_algorithm: Optional[str]
    public_key_size: Optional[int]
    signature_algorithm: Optional[str]
    sha256_fingerprint: Optional[str]
    is_self_signed: Optional[bool]
    is_ca: Optional[bool]
    parse_error: Optional[str]


def _empty_metadata(parse_error: str | None = None) -> CertificateMetadata:
    return {
        "subject": None,
        "issuer": None,
        "serial_number": None,
        "valid_from": None,
        "valid_until": None,
        "public_key_algorithm": None,
        "public_key_size": None,
        "signature_algorithm": None,
        "sha256_fingerprint": None,
        "is_self_signed": None,
        "is_ca": None,
        "parse_error": parse_error,
    }


def _utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _public_key_details(public_key: object) -> tuple[str, int | None]:
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "EC", public_key.key_size
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", None
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", None
    return type(public_key).__name__, getattr(public_key, "key_size", None)


def _is_self_signed(certificate: x509.Certificate) -> bool:
    if certificate.subject != certificate.issuer:
        return False

    verify_directly_issued_by = getattr(
        certificate,
        "verify_directly_issued_by",
        None,
    )
    if verify_directly_issued_by is not None:
        try:
            verify_directly_issued_by(certificate)
            return True
        except Exception:
            return False

    public_key = certificate.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(certificate.signature_hash_algorithm),
            )
        elif isinstance(public_key, dsa.DSAPublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                certificate.signature_hash_algorithm,
            )
        elif isinstance(
            public_key,
            (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey),
        ):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
            )
        else:
            return False
    except Exception:
        return False
    return True


def parse_certificate_metadata(pem: str) -> CertificateMetadata:
    """Return non-secret X.509 metadata without exposing malformed input."""
    try:
        certificate = x509.load_pem_x509_certificate(pem.encode("utf-8"))
        public_key = certificate.public_key()
        key_algorithm, key_size = _public_key_details(public_key)

        try:
            basic_constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
            is_ca: bool | None = basic_constraints.ca
        except x509.ExtensionNotFound:
            is_ca = None

        signature_algorithm = (
            certificate.signature_algorithm_oid._name
            or certificate.signature_algorithm_oid.dotted_string
        )
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex().upper()
        valid_from = getattr(certificate, "not_valid_before_utc", None)
        valid_until = getattr(certificate, "not_valid_after_utc", None)
        if valid_from is None:  # pragma: no cover - older cryptography
            valid_from = certificate.not_valid_before
        if valid_until is None:  # pragma: no cover - older cryptography
            valid_until = certificate.not_valid_after

        return {
            "subject": certificate.subject.rfc4514_string(),
            "issuer": certificate.issuer.rfc4514_string(),
            "serial_number": format(certificate.serial_number, "X"),
            "valid_from": _utc_datetime(valid_from),
            "valid_until": _utc_datetime(valid_until),
            "public_key_algorithm": key_algorithm,
            "public_key_size": key_size,
            "signature_algorithm": signature_algorithm,
            "sha256_fingerprint": ":".join(
                fingerprint[index:index + 2]
                for index in range(0, len(fingerprint), 2)
            ),
            "is_self_signed": _is_self_signed(certificate),
            "is_ca": is_ca,
            "parse_error": None,
        }
    except Exception:
        # Do not include the exception text: some parser errors may echo input.
        return _empty_metadata("Unable to parse X.509 certificate metadata.")
