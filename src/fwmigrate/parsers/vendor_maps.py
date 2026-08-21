from fwmigrate.core.constants import IR_KEYWORD_ANY, IR_KEYWORD_DYNAMIC, IR_KEYWORD_NONE

SOURCE_KEYWORD_MAP = {
    "fortigate": {
        "all": IR_KEYWORD_ANY,
        "any": IR_KEYWORD_ANY,
        "none": IR_KEYWORD_NONE
    },
    "panos": {
        "any": IR_KEYWORD_ANY,
        "dynamic": IR_KEYWORD_DYNAMIC
    },
    "cisco": {
        "any": IR_KEYWORD_ANY
    }
}

def normalize_to_ir(source_vendor, parsed_keyword):
    """Translates a vendor's native keyword to the Universal IR."""
    if not isinstance(parsed_keyword, str):
        return parsed_keyword
    vendor_map = SOURCE_KEYWORD_MAP.get(source_vendor, {})
    # Return the IR constant if matched, otherwise return the custom object name
    return vendor_map.get(parsed_keyword.lower(), parsed_keyword)
