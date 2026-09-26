"""Fail-closed sanitizer for data sent to the external model."""

import json
import ipaddress
import re

from fwmigrate.ai.errors import AIInvalidResponseError

_SENSITIVE_KEY = re.compile(r"password|passwd|secret|psk|private.?key|api.?key|token|authorization|credential|community|authentication", re.I)
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I)
_IP_ADDRESS = re.compile(r"(?<![A-Za-z0-9])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![A-Za-z0-9])")
_IPV6_ADDRESS = re.compile(r"(?<![A-Za-z0-9])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f:.]{0,39}(?:/\d{1,3})?(?![A-Za-z0-9])", re.I)


def sanitize_ai_context(value, *, max_bytes=16000, max_depth=8, max_string=256, max_list=64):
    def clean(item, depth=0):
        if depth > max_depth:
            raise AIInvalidResponseError("AI context exceeded the allowed nesting depth")
        if isinstance(item, dict):
            result = {}
            for key, child in item.items():
                if not isinstance(key, str) or _SENSITIVE_KEY.search(key):
                    raise AIInvalidResponseError("AI context contains a sensitive field")
                result[key] = clean(child, depth + 1)
            return result
        if isinstance(item, (list, tuple)):
            if len(item) > max_list:
                raise AIInvalidResponseError("AI context contains too many list items")
            return [clean(child, depth + 1) for child in item]
        if isinstance(item, str):
            if _PRIVATE_KEY.search(item):
                raise AIInvalidResponseError("AI context contains private-key material")
            if len(item) > max_string:
                raise AIInvalidResponseError("AI context contains an oversized string")
            item = _IP_ADDRESS.sub("[address evidence]", item)
            return _IPV6_ADDRESS.sub(_replace_ipv6, item)
        if item is None or isinstance(item, (bool, int, float)):
            return item
        raise AIInvalidResponseError("AI context contains an unsupported value")

    result = clean(value)
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > max_bytes:
        raise AIInvalidResponseError("AI context exceeded the configured size limit")
    return result


def _replace_ipv6(match):
    value = match.group(0)
    try:
        ipaddress.ip_interface(value)
    except ValueError:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return value
    return "[address evidence]"
