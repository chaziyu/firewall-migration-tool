import xml.etree.ElementTree as ET
from typing import Optional, List, Dict, Any

def text_or_none(element: Optional[ET.Element], path: str) -> Optional[str]:
    if element is None:
        return None
    child = element.find(path)
    if child is not None and child.text:
        return child.text.strip()
    return None

def entry_name(element: ET.Element) -> Optional[str]:
    return element.get("name")

def member_texts(element: Optional[ET.Element], path: str) -> List[str]:
    if element is None:
        return []
    return [m.text for m in element.findall(path) if m.text]

def yes_no_or_none(element: Optional[ET.Element], path: str) -> Optional[bool]:
    text = text_or_none(element, path)
    if text:
        return text.lower() == "yes"
    return None

def int_or_none(element: Optional[ET.Element], path: str) -> Optional[int]:
    text = text_or_none(element, path)
    if text:
        try:
            return int(text)
        except ValueError:
            return None
    return None

def safe_xml_capture(element: Optional[ET.Element], max_bytes: int = 2000) -> Optional[str]:
    """Capture raw XML with a size bound."""
    if element is None:
        return None
    raw = ET.tostring(element, encoding="unicode")
    if len(raw) > max_bytes:
        return raw[:max_bytes] + "... [TRUNCATED]"
    return raw

def child_names(element: Optional[ET.Element]) -> List[str]:
    if element is None:
        return []
    return [child.tag for child in element]

def collect_unknown_children(element: ET.Element, known_children: List[str]) -> Dict[str, Any]:
    unknown = {}
    for child in element:
        if child.tag not in known_children:
            val = child.text.strip() if child.text else None
            if val:
                unknown[child.tag] = val
            elif len(child) > 0:
                unknown[child.tag] = "[Complex subtree]"
            else:
                unknown[child.tag] = True
    return unknown
