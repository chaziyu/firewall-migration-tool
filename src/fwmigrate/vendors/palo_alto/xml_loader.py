"""PAN-OS XML input loading and validation."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from .source_model import PANSourceDocument


def reject_unsafe_xml_declarations(content: str) -> None:
    """Reject DTD/entity declarations before handing customer XML to ElementTree."""
    lowered = content.casefold()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise ValueError("PAN-OS XML DTD/entity declarations are not supported.")


def load_pan_source(content: str) -> PANSourceDocument:
    """Load a PAN-OS XML export without entering source traversal."""
    reject_unsafe_xml_declarations(content)
    try:
        root = ET.fromstring(content)
    except ET.ParseError as error:
        cleaned = content.strip()
        if not cleaned:
            raise ValueError("Empty configuration input.") from error
        try:
            root = ET.fromstring(cleaned)
        except ET.ParseError:
            if cleaned.startswith("set "):
                raise ValueError(
                    "PAN-OS CLI 'set' format is not supported. Please provide XML configuration."
                ) from error
            raise ValueError(f"Malformed XML input: {error}") from error

    if root.tag == "response":
        wrapped = root.find("./result/config")
        if wrapped is None:
            raise ValueError(
                "Unsupported PAN-OS XML response: missing response/result/config."
            )
        root = wrapped
    if root.tag != "config":
        raise ValueError(
            f"Unsupported XML format: expected root element '<config>', found '<{root.tag}>'."
        )

    device_entries = root.findall("./devices/entry")
    hostname = None
    if len(device_entries) == 1:
        host_elem = device_entries[0].find("./deviceconfig/system/hostname")
        if host_elem is not None and host_elem.text and host_elem.text.strip():
            hostname = host_elem.text.strip()
    elif not device_entries:
        hostname_candidates = [
            element
            for xpath in ("./deviceconfig/system/hostname", "./system/hostname")
            for element in root.findall(xpath)
            if element.text and element.text.strip()
        ]
        if len(hostname_candidates) == 1:
            hostname = hostname_candidates[0].text.strip()
    return PANSourceDocument(
        root=root,
        hostname=hostname,
        source_version=root.get("version"),
    )
