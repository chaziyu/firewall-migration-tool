"""Comparable fingerprints of sanitized PAN-OS destination evidence."""
import hashlib
import xml.etree.ElementTree as ET

from .collection_source import PANOSCollectedSourceSanitizer
from .xml_loader import reject_unsafe_xml_declarations


BASELINE_FORMAT = "panos-sanitized-xml-v1"


def destination_fingerprint(source_text):
    """Ignore XML formatting, retaining scope, ordering and non-secret leaf values."""
    try:
        reject_unsafe_xml_declarations(source_text)
        root = ET.fromstring(source_text)
        if root.tag == "response":
            root = root.find("./result/config")
        if root is None or root.tag != "config" or not len(root):
            raise ValueError
        safe_xml = PANOSCollectedSourceSanitizer().sanitize(ET.tostring(root, encoding="unicode"))
        root = ET.fromstring(safe_xml)
        for element in root.iter():
            if len(element) and element.text is not None and not element.text.strip():
                element.text = None
            if element.tail is not None and not element.tail.strip():
                element.tail = None
        canonical = ET.canonicalize(ET.tostring(root, encoding="unicode"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    except (ValueError, TypeError, ET.ParseError):
        raise ValueError("Cannot fingerprint complete PAN-OS destination evidence") from None
