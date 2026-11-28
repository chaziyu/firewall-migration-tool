"""Sanitize portable FortiGate CLI evidence without changing non-secret commands."""
import re
from itertools import groupby

from .tokenizer import FortiGateTokenizer
from .security.extraction import sanitize_source_value


_ENC_TOKEN_RE = re.compile(r"^[A-Za-z0-9+/=]{16,}$")
_ENC_LINE_RE = re.compile(r"\bENC\s+[A-Za-z0-9+/=]{16,}")


def _contains_fortios_enc(values: list[str]) -> bool:
    for idx in range(2, len(values) - 1):
        if values[idx] == "ENC" and _ENC_TOKEN_RE.match(values[idx + 1]):
            return True
    return any(_ENC_LINE_RE.search(item) for item in values[2:])


class FortiGateCollectedSourceSanitizer:
    vendor_id = 'fortigate'

    def sanitize(self, source_text):
        lines = source_text.splitlines(keepends=True)
        groups = [(number, list(tokens)) for number, tokens in groupby(
            FortiGateTokenizer(source_text).tokenize(), key=lambda item: item.line_number)]
        for index, (number, tokens) in enumerate(groups):
            values = [item.value for item in tokens]
            match = re.match(r'\s*(?:set|append)\s+(\S+)', values[0], re.IGNORECASE)
            key = values[1] if len(values) > 1 and values[0].lower() in {'set', 'append'} else match[1] if match else None
            is_sensitive = bool(key and sanitize_source_value(key, 'workspace-secret-probe') == '[REDACTED]')
            if not is_sensitive and key and _contains_fortios_enc(values):
                is_sensitive = True
            if is_sensitive:
                end = groups[index + 1][0] - 1 if index + 1 < len(groups) else len(lines)
                operation = values[0] if len(values) > 1 else values[0].strip().split()[0]
                indent = re.match(r'\s*', lines[number - 1])[0].replace('\n', '')
                lines[number - 1] = f'{indent}{operation} {key} "[REDACTED]"\n'
                for offset in range(number, end):
                    lines[offset] = '\n'
        return ''.join(lines)
