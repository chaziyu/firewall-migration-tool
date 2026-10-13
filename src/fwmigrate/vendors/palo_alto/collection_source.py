"""Sanitize portable PAN-OS XML evidence using the existing secret-key policy."""
import xml.etree.ElementTree as ET
from fwmigrate.extraction.sanitize import is_sensitive_key, sanitize_raw_text
from .xml_loader import reject_unsafe_xml_declarations


class PANOSCollectedSourceSanitizer:
    vendor_id = 'palo_alto'

    def sanitize(self, source_text):
        reject_unsafe_xml_declarations(source_text)
        try:
            root = ET.fromstring(source_text)
        except ET.ParseError as exc:
            raise ValueError('Invalid PAN-OS XML source') from exc
        original_xml = ET.tostring(root, encoding='unicode')
        for element in root.iter():
            if is_sensitive_key(element.tag):
                element.clear()
                element.text = '[REDACTED]'
            else:
                for key in element.attrib:
                    if is_sensitive_key(key):
                        element.set(key, '[REDACTED]')
                if element.text:
                    element.text = sanitize_raw_text(element.text)
            if element.tail:
                element.tail = sanitize_raw_text(element.tail)
        # Redact XML values before serialization so CLI patterns cannot corrupt markup.
        sanitized_xml = ET.tostring(root, encoding='unicode')
        return source_text if sanitized_xml == original_xml else sanitized_xml
