"""PAN-OS zone naming constraints shared by draft and plan validation."""
import re


def zone_name_issue(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 31:
        return "Zone name must contain 1 to 31 characters"
    if not re.fullmatch(r"[A-Za-z0-9_. -]+", value):
        return "Zone name may contain only letters, numbers, spaces, hyphens, periods and underscores"
    return None
