"""Redact PAN-OS credential leaves without removing IPsec configuration."""

import xml.etree.ElementTree as ET
from typing import Any

from ...extraction.sanitize import is_sensitive_key, sanitize_raw_text, sanitize_source_value


def is_panos_metadata(key: str, value: Any) -> bool:
    """PAN-OS 11.1 labels, public certificates and options are not credentials."""
    if not isinstance(value, str):
        return False
    key = key.lower().replace("_", "-")
    if key in {"password-label", "public-key"}:
        return True
    options = {
        "auto-retrieve-passcode": {"", "yes", "no"},
        "user-credential-or-client-cert-required": {"", "yes", "no"},
        "save-user-credentials": {"", "0", "1", "2", "3"},
        "domain-credentials": {""},
    }
    return key in options and value.strip() in options[key]


def sanitize_panos_value(key: str, value: Any) -> Any:
    if is_panos_metadata(key, value):
        return value
    if not is_sensitive_key(key):
        if isinstance(value, dict):
            return sanitize_panos_attributes(value)
        if isinstance(value, list):
            return [sanitize_panos_value(key, child) for child in value]
    return sanitize_source_value(key, value)


def sanitize_panos_attributes(value: Any) -> Any:
    """Keep the PAN-OS distinction when sanitized XML becomes nested evidence."""
    if not isinstance(value, dict):
        return value
    return {key: sanitize_panos_value(str(key), child) for key, child in value.items()}


def sanitize_panos_element(root: ET.Element) -> None:
    # These are configuration containers; their descendant key leaves stay sensitive.
    containers = {
        child for ipsec in root.iter("ipsec") for entry in ipsec.findall("entry")
        for child in entry if child.tag in {"auto-key", "manual-key"}
        and not (child.text or "").strip()
    }
    # CLI hierarchy: global-protect client-auth/options, URL mode, certificate public-key.
    metadata_paths = (
        ".//global-protect-portal/entry/portal-config/client-auth/entry/password-label",
        ".//global-protect-portal/entry/portal-config/client-auth/entry/auto-retrieve-passcode",
        ".//global-protect-portal/entry/portal-config/client-auth/entry/user-credential-or-client-cert-required",
        ".//global-protect-gateway/entry/client-auth/entry/password-label",
        ".//global-protect-gateway/entry/client-auth/entry/auto-retrieve-passcode",
        ".//global-protect-gateway/entry/client-auth/entry/user-credential-or-client-cert-required",
        ".//global-protect-portal/entry/client-config/configs/entry/save-user-credentials",
        ".//url-filtering/entry/credential-enforcement/mode/domain-credentials",
        ".//certificate/entry/public-key",
    )
    metadata = {node for path in metadata_paths for node in root.findall(path)
                if not len(node) and is_panos_metadata(node.tag, node.text or "")}
    for element in root.iter():
        if is_sensitive_key(element.tag) and element not in containers and element not in metadata:
            element.clear()
            element.text = "[REDACTED]"
        else:
            for key in element.attrib:
                if is_sensitive_key(key):
                    element.set(key, "[REDACTED]")
            if element.text and element not in metadata:
                element.text = sanitize_raw_text(element.text)
        if element.tail:
            element.tail = sanitize_raw_text(element.tail)
