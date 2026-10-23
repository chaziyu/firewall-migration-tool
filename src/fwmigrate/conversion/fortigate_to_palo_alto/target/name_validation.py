"""PAN-OS object text constraints shared by planning and validation."""
import re


def zone_name_issue(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 31:
        return "Zone name must contain 1 to 31 characters"
    if not re.fullmatch(r"[A-Za-z0-9_. -]+", value):
        return "Zone name may contain only letters, numbers, spaces, hyphens, periods and underscores"
    return None


def object_description_issue(value):
    if value is not None and (
        not isinstance(value, str) or len(value) > 1023 or any(
            (ord(char) < 32 and char != "\n") or 127 <= ord(char) <= 159
            or char in "\u2028\u2029" for char in value)
    ):
        return "target description must be at most 1,023 characters without unsafe CLI controls"
    return None
