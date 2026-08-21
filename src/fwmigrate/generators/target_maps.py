from fwmigrate.core.constants import IR_KEYWORD_ANY, IR_KEYWORD_DYNAMIC, IR_KEYWORD_NONE

TARGET_KEYWORD_MAP = {
    "fortigate": {
        IR_KEYWORD_ANY: "all",
        IR_KEYWORD_NONE: "none"
    },
    "panos": {
        IR_KEYWORD_ANY: "any",
        IR_KEYWORD_DYNAMIC: "dynamic"
    },
    "cisco": {
        IR_KEYWORD_ANY: "any"
    }
}

def translate_to_target(target_vendor, ir_object):
    """Translates the Universal IR back to the target vendor's syntax."""
    if not isinstance(ir_object, str):
        return ir_object
    vendor_map = TARGET_KEYWORD_MAP.get(target_vendor, {})
    # Return the vendor keyword if it's an IR constant, otherwise return the custom name
    return vendor_map.get(ir_object, ir_object)
