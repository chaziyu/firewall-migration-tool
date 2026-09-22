from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from fwmigrate.extraction.sanitize import sanitize_source_attributes


def text_or_none(element: ET.Element | None) -> str | None:
    if element is None:
        return None
    return (element.text or "").strip()


def member_texts(element: ET.Element | None) -> list[str] | None:
    if element is None:
        return None
    return [(child.text or child.get("name") or "").strip() for child in element if child.tag == "member"]


def child_present(element: ET.Element, tag: str) -> bool:
    return element.find(tag) is not None


def entry_name(element: ET.Element) -> str | None:
    return element.get("name")


def structured_xml_capture(element: ET.Element) -> object:
    children: dict[str, object] = {}
    for child in element:
        value = structured_xml_capture(child)
        if child.tag in children:
            current = children[child.tag]
            children[child.tag] = [*(current if isinstance(current, list) else [current]), value]
        else:
            children[child.tag] = value
    text = (element.text or "").strip()
    if children:
        if text:
            children["#text"] = text
        if element.attrib:
            children["@attributes"] = dict(element.attrib)
        return children
    if element.attrib:
        result: dict[str, object] = {"@attributes": dict(element.attrib)}
        if text:
            result["#text"] = text
        return result
    return text


def capture_unknown_children(element: ET.Element, handled: set[str]) -> dict[str, Any]:
    result = {child.tag: structured_xml_capture(child) for child in element if child.tag not in handled}
    return sanitize_source_attributes(result)


def capture_unknown_attributes(element: ET.Element, handled: set[str] = {"name"}) -> dict[str, Any]:
    return sanitize_source_attributes({key: value for key, value in element.attrib.items() if key not in handled})
