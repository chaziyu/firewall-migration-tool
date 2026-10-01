"""Sanitize portable PAN-OS XML evidence using the existing secret-key policy."""
import xml.etree.ElementTree as ET
from fwmigrate.extraction.sanitize import is_sensitive_key, sanitize_raw_text


class PANOSCollectedSourceSanitizer:
    vendor_id = 'palo_alto'

    def sanitize(self, source_text):
        try:
            root = ET.fromstring(source_text)
        except ET.ParseError as exc:
            raise ValueError('Invalid PAN-OS XML source') from exc
        changed = False
        for element in root.iter():
            if is_sensitive_key(element.tag):
                changed = changed or element.text != '[REDACTED]' or bool(list(element)) or bool(element.attrib)
                element.clear()
                element.text = '[REDACTED]'
            else:
                for key in element.attrib:
                    if is_sensitive_key(key):
                        changed = changed or element.get(key) != '[REDACTED]'
                        element.set(key, '[REDACTED]')
        return ET.tostring(root, encoding='unicode') if changed else sanitize_raw_text(source_text)
