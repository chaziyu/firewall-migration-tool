"""PAN-OS XML input loading and validation."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from .source_model import PANSourceDocument


def load_pan_source(content: str) -> PANSourceDocument:
    """Load a PAN-OS XML export without entering source traversal."""
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

    host_elem = root.find(".//system/hostname")
    if host_elem is None:
        host_elem = root.find(".//deviceconfig/system/hostname")
    hostname = host_elem.text.strip() if host_elem is not None and host_elem.text else None
    return PANSourceDocument(
        root=root,
        raw_content=content,
        hostname=hostname,
        source_version=root.get("version"),
    )
