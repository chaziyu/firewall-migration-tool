"""Centralized secret sanitization for configuration evidence and extraction metadata."""

from __future__ import annotations

import re
from typing import Any, Dict

SENSITIVE_KEY_PREFIXES = (
    "password",
    "passphrase",
    "password-hash",
    "password_hash",
    "phash",
    "api-key",
    "api_key",
    "apikey",
    "sid",
    "token",
    "set-cookie",
    "x-chkp-sid",
    "shared-secret",
    "shared_secret",
    "challenge-response",
    "challenge_response",
    "secret",
    "private-key",
    "private_key",
    "privatekey",
    "psk",
    "pre-shared-key",
    "preshared-key",
    "community",
    "sic-name",
    "sic_name",
    "sic-password",
    "sic_password",
    "sic-key",
    "sic_key",
    "one-time-password",
    "one_time_password",
    "passcode",
    "ddns-key",
    "ddns_key",
    "agent-user-override-key",
    "agent_user_override_key",
    "newpass",
    "new-pass",
    "new-password",
    "key",
)

SENSITIVE_EXACT_KEYS = {
    "authpwd", "privpwd",  # PAN-OS SNMPv3 authentication/privacy credentials.
    "credential", "credentials", "connection-string", "conn-string",
    "authorization",
    "cookie",
    "private-key-data", "private_key_data", "key-data", "key_data",
    "activation-key", "activation_key", "sic-password-hash", "sic_password_hash",
    "otp", "pkcs12-password", "pkcs12_password", "one-time-password",
    "one_time_password",
}

REDACTED_PLACEHOLDER = "[REDACTED]"


def is_sensitive_key(key: str) -> bool:
    """Check if a dictionary key name matches sensitive prefixes/names."""
    k = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "-", key.strip()).lower().replace("_", "-")
    if k in {"community-type", "vpn-community", "vpn-community-type", "key-length"}:
        return False
    if k in {item.replace("_", "-") for item in SENSITIVE_EXACT_KEYS}:
        return True
    if k.endswith(("-credential", "-credentials", "-credential-value", "-credentials-value",
                   "-connection-string", "-conn-string")):
        return True
    if k.startswith("private-key-") or k.startswith("sic-password-"):
        return True
    for prefix in SENSITIVE_KEY_PREFIXES:
        p = prefix.replace("_", "-")
        if k == p or k.startswith(f"{p}-") or k.startswith(f"{p}_") or k.endswith(f"-{p}") or k.endswith(f"_{p}"):
            return True
    return False


def sanitize_source_value(key: str, value: Any) -> Any:
    """Sanitize a value if its key is sensitive, or recursively sanitize dicts and lists."""
    normalized_key = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "-", key.strip()).lower().replace("_", "-")
    if isinstance(value, bool) and normalized_key.endswith(("configured", "present")):
        return value
    if is_sensitive_key(key):
        return REDACTED_PLACEHOLDER

    if isinstance(value, dict):
        return sanitize_source_attributes(value)
    if isinstance(value, list):
        return [sanitize_source_value(key, item) for item in value]
    if isinstance(value, str) and key.strip().lower().replace("_", "-") in {
        "raw", "raw-command", "cli-text", "error", "command-output"
    }:
        return sanitize_raw_text(value)
    return value


def sanitize_source_attributes(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively sanitize a dictionary of source attributes."""
    if not isinstance(attrs, dict):
        return attrs

    has_generator_id = "gid" in attrs  # Snort GID/SID pairs identify configured signatures.
    return {key: value if has_generator_id and str(key).lower() == "sid" and type(value) is int
            else sanitize_source_value(str(key), value) for key, value in attrs.items()}


def sanitize_raw_text(text: str) -> str:
    """Sanitize secrets in raw command output, Gaia lines, or config text."""
    if not text:
        return text

    # ASA NTP authentication keys place the secret after a key ID and
    # algorithm. Redact the secret-bearing tail before the generic "key"
    # sanitizer can mistake the non-secret key ID for the credential.
    text = re.sub(
        r"(?im)^([ \t]*ntp[ \t]+authentication-key[ \t]+\S+[ \t]+\S+)[ \t]+[^ \t\r\n][^\r\n]*$",
        rf"\1 {REDACTED_PLACEHOLDER}", text,
    )

    # ASA SNMPv3 credentials follow algorithm names rather than secret keys.
    token = r'(?:"[^"]*"|\'[^\']*\'|[^\s\r\n]+)'
    text = re.sub(
        rf"(?im)^(\s*snmp-server\s+user\s+[^\r\n]*?\bauth\s+(?:md5|sha(?:-?\d+)?)\s+)({token})",
        rf"\1{REDACTED_PLACEHOLDER}", text,
    )
    text = re.sub(
        rf"(?im)^(\s*snmp-server\s+user\s+[^\r\n]*?\bpriv\s+(?:des|3des|aes(?:\s+(?:128|192|256))?)\s+)({token})",
        rf"\1{REDACTED_PLACEHOLDER}", text,
    )

    text = re.sub(r"(?im)^(\s*(?:authorization|cookie|set-cookie|x-chkp-sid)\s*:\s*).+$",
                  rf"\1{REDACTED_PLACEHOLDER}", text)

    # Mask password hashes or cleartext in known CLI patterns (e.g. set user admin password-hash ...)
    key_pattern = (
        r"password(?:-hash)?|phash|authpwd|privpwd|one-time-password|passcode|shared-secret|sic-name|sic-password|"
        r"secret|(?<!-)key|password|login-password|common-password|bind-password|new-?pass(?:word)?|pre-?shared-key|preshared-key|private-key|api-key|token|psk|community|ddns-key|ddns_key|agent-user-override-key|agent_user_override_key"
    )
    # Cisco-style credentials may place an encryption type between the key
    # and the secret (for example, ``password 0 value``).
    sanitized = re.sub(
        rf"((?:password|secret|pre-?shared-key|preshared-key))(\s+)(?:0|7)(\s+)(?:\"[^\"]*\"|'[^']*'|[^\s\r\n]+)",
        rf"\1\2[REDACTED]",
        text,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        rf"({key_pattern})(\s+)((?:ascii|plain-text|cleartext|hex|encrypted|0|7)\s+)?(?:\"[^\"]*\"|'[^']*'|[^\s\r\n]+)",
        lambda match: f"{match.group(1)}{match.group(2)}{match.group(3) or ''}{REDACTED_PLACEHOLDER}",
        sanitized,
        flags=re.IGNORECASE,
    )
    # Also cover serialized Python/JSON dictionaries used in diagnostic raw_capture.
    sanitized = re.sub(
        rf"([\"'](?:{key_pattern})[\"']\s*:\s*)(?:\"[^\"]*\"|'[^']*'|[^,}}\r\n]+)",
        rf"\1'{REDACTED_PLACEHOLDER}'",
        sanitized,
        flags=re.IGNORECASE,
    )
    return _sanitize_xml_secret_text(sanitized)


def _sanitize_xml_secret_text(text: str) -> str:
    """Redact XML element text with a single pass, preserving other evidence."""
    output = []
    stack = []
    position = 0
    secret_start = None
    secret_open_end = None
    while True:
        start = text.find("<", position)
        if start < 0:
            if stack and any(secret for _, secret, _, _ in stack):
                output.append(REDACTED_PLACEHOLDER if text[position:].strip() else text[position:])
            else:
                output.append(text[position:])
            break
        end = text.find(">", start + 1)
        if end < 0:
            remainder = text[start + 1:].lstrip("?!/")
            parts = remainder.split()
            candidate = parts[0].rstrip("/") if parts else ""
            sensitive_attribute = any(is_sensitive_key(part.split("=", 1)[0].strip("\"'")) for part in parts[1:])
            if secret_start is not None:
                return text[:secret_start] + text[secret_start:secret_open_end] + REDACTED_PLACEHOLDER
            if candidate and (is_sensitive_key(candidate) or sensitive_attribute):
                return text[:start] + f"<{candidate}>{REDACTED_PLACEHOLDER}"
            output.append(text[position:])
            break

        raw_tag = text[start + 1:end]
        tag = raw_tag.strip()
        closing = tag.startswith("/")
        self_closing = tag.endswith("/")
        name = (tag[1:].lstrip().split(None, 1)[0] if closing else
                tag.split(None, 1)[0].rstrip("/") if tag else "")
        if not name or tag.startswith(("?", "!")):
            if secret_start is not None:
                return text[:secret_start] + text[secret_start:secret_open_end] + REDACTED_PLACEHOLDER
            output.append(text[position:end + 1])
            position = end + 1
            continue

        in_secret = any(secret for _, secret, _, _ in stack)
        segment = text[position:start]
        output.append(REDACTED_PLACEHOLDER if in_secret and segment.strip() else segment)
        if closing:
            if not stack or stack[-1][0].casefold() != name.casefold():
                if secret_start is not None:
                    return text[:secret_start] + text[secret_start:secret_open_end] + REDACTED_PLACEHOLDER
                output.append(text[start:end + 1])
            else:
                _, was_secret, _, _ = stack.pop()
                output.append(text[start:end + 1])
                if was_secret and not any(secret for _, secret, _, _ in stack):
                    secret_start = None
                    secret_open_end = None
        else:
            safe_tag, sensitive_attribute = _redact_xml_attributes(raw_tag)
            sensitive = (is_sensitive_key(name) or name.casefold() in {"bind-password", "authentication-key"}
                         or sensitive_attribute)
            output.append(f"<{safe_tag}>")
            if not self_closing:
                stack.append((name, sensitive, start, end + 1))
                if sensitive:
                    if secret_start is None:
                        secret_start, secret_open_end = start, end + 1
        position = end + 1

    if stack and secret_start is not None:
        return text[:secret_start] + text[secret_start:secret_open_end] + REDACTED_PLACEHOLDER
    return "".join(output)


def _redact_xml_attributes(tag: str) -> tuple[str, bool]:
    """Mask sensitive XML attribute values without changing other attributes."""
    replacements = []
    sensitive = False
    position = 0
    length = len(tag)
    while position < length and not tag[position].isspace() and tag[position] not in "/>?":
        position += 1
    while position < length:
        while position < length and (tag[position].isspace() or tag[position] in "/?"):
            position += 1
        start = position
        while position < length and not tag[position].isspace() and tag[position] not in "=/>?":
            position += 1
        if position == start:
            position += 1
            continue
        name = tag[start:position]
        while position < length and tag[position].isspace():
            position += 1
        if position >= length or tag[position] != "=":
            continue
        position += 1
        while position < length and tag[position].isspace():
            position += 1
        quote = tag[position] if position < length and tag[position] in "\"'" else ""
        if quote:
            value_start = position + 1
            value_end = tag.find(quote, value_start)
            if value_end < 0:
                break
            position = value_end + 1
            if is_sensitive_key(name):
                replacements.append((value_start, value_end))
                sensitive = True
        else:
            value_start = position
            while position < length and not tag[position].isspace() and tag[position] not in "/>?":
                position += 1
            if is_sensitive_key(name):
                replacements.append((value_start, position))
                sensitive = True
    for start, end in reversed(replacements):
        tag = tag[:start] + REDACTED_PLACEHOLDER + tag[end:]
    return tag, sensitive


