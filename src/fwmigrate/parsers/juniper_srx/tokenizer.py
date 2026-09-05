"""Tokenizer and activation state management for Juniper JunOS 'set' configuration format."""

from __future__ import annotations

from enum import Enum
import re
import shlex
from typing import List, Optional, Sequence

from pydantic import BaseModel, Field

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import (
    has_access_denied_token,
    sanitize_junos_command,
    sanitize_tokens,
)


class JunosOperation(str, Enum):
    SET = "set"
    ACTIVATE = "activate"
    DEACTIVATE = "deactivate"
    UNKNOWN = "unknown"


class JunosCommand(BaseModel):
    operation: JunosOperation
    tokens: List[str] = Field(default_factory=list)
    raw_sanitized: str
    line_number: int
    consumed: bool = False
    handler: Optional[str] = None
    parse_error: Optional[str] = None
    extraction_status: Optional[ExtractionStatus] = None
    requires_manual_review: bool = False
    access_denied: bool = False
    consumed_tokens: Optional[int] = None
    remaining_tokens: List[str] = Field(default_factory=list)
    source_group: Optional[str] = None
    synthetic: bool = False

    def to_sanitized_copy(self) -> JunosCommand:
        """Return a copy of JunosCommand with tokens sanitized."""
        return JunosCommand(
            operation=self.operation,
            tokens=sanitize_tokens(self.tokens),
            raw_sanitized=self.raw_sanitized,
            line_number=self.line_number,
            consumed=self.consumed,
            handler=self.handler,
            parse_error=self.parse_error,
            extraction_status=self.extraction_status,
            requires_manual_review=self.requires_manual_review,
            access_denied=self.access_denied,
            consumed_tokens=self.consumed_tokens,
            remaining_tokens=sanitize_tokens(self.remaining_tokens),
            source_group=self.source_group,
            synthetic=self.synthetic,
        )


def extract_value_list(tokens: Sequence[str]) -> List[str]:
    """
    Extract values from tokens that might be enclosed in JunOS bracket list syntax: [ v1 v2 ... ]
    or single values.
    """
    if not tokens:
        return []
    toks = list(tokens)
    if toks[0] == "[" and toks[-1] == "]":
        return toks[1:-1]
    if toks[0].startswith("[") and toks[0] != "[":
        toks[0] = toks[0][1:]
    if toks[-1].endswith("]") and toks[-1] != "]":
        toks[-1] = toks[-1][:-1]
    # Filter any stray '[' or ']'
    return [t for t in toks if t not in ("[", "]")]


# High-confidence subordinate hierarchy tokens that indicate relative display-set output
_KNOWN_SUBORDINATE_TOKENS = {
    "unit",
    "policy",
    "address",
    "address-set",
    "application",
    "application-set",
    "rule",
    "rule-set",
    "security-zone",
    "term",
    "family",
    "then",
    "match",
    "from-zone",
    "to-zone",
}


def validate_input_mode(commands: Sequence[JunosCommand]) -> None:
    """
    Validate that the input represents root-level 'show configuration | display set'
    rather than relative display-set output (e.g. 'set unit 0 ...' from 'edit interfaces ge-0/0/0').
    Conservative: only high-confidence subordinate starting tokens trigger rejection.
    """
    for cmd in commands:
        if cmd.operation in (JunosOperation.SET, JunosOperation.ACTIVATE, JunosOperation.DEACTIVATE):
            if len(cmd.tokens) >= 2:
                first_sub = cmd.tokens[1].lower()
                if first_sub in _KNOWN_SUBORDINATE_TOKENS:
                    raise ValueError(
                        "Juniper SRX parser requires root-level 'show configuration | display set' "
                        f"output; relative display-set input detected starting with '{cmd.tokens[0]} {first_sub}'."
                    )


class JunosActivationState:
    """Tracks deactivate/activate path state to determine if a configuration path is inactive."""

    def __init__(self) -> None:
        self.inactive_paths: List[List[str]] = []

    def apply(self, commands: Sequence[JunosCommand]) -> None:
        """Process deactivate and activate commands."""
        for cmd in commands:
            if cmd.operation == JunosOperation.DEACTIVATE:
                if len(cmd.tokens) > 1:
                    path = [t.lower() for t in cmd.tokens[1:]]
                    if path not in self.inactive_paths:
                        self.inactive_paths.append(path)
                cmd.consumed = True
                cmd.extraction_status = ExtractionStatus.NORMALIZED
            elif cmd.operation == JunosOperation.ACTIVATE:
                if len(cmd.tokens) > 1:
                    path = [t.lower() for t in cmd.tokens[1:]]
                    # Remove exact match or prefix
                    self.inactive_paths = [
                        p for p in self.inactive_paths if p != path
                    ]
                cmd.consumed = True
                cmd.extraction_status = ExtractionStatus.NORMALIZED

    def is_inactive(self, path: Sequence[str]) -> bool:
        """
        Check if path or any parent prefix path is deactivated.
        Supports subtree inheritance.
        """
        if not path or not self.inactive_paths:
            return False
        normalized_path = [t.lower() for t in path]
        for inact in self.inactive_paths:
            if len(normalized_path) >= len(inact):
                if normalized_path[:len(inact)] == inact:
                    return True
        return False

    def is_exactly_inactive(self, path: Sequence[str]) -> bool:
        normalized_path = [t.lower() for t in path]
        return normalized_path in self.inactive_paths


class JuniperSetTokenizer:
    """Tokenizes JunOS display-set configuration text into sanitized JunosCommand objects."""

    def tokenize(self, content: str) -> List[JunosCommand]:
        commands: List[JunosCommand] = []
        in_block_comment = False

        for line_idx, raw_line in enumerate(content.splitlines(), 1):
            stripped = raw_line.strip()
            if not stripped:
                continue

            # Handle block comments /* ... */
            if in_block_comment:
                if "*/" in stripped:
                    in_block_comment = False
                    # Extract any trailing code after */
                    stripped = stripped[stripped.index("*/") + 2:].strip()
                    if not stripped:
                        continue
                else:
                    continue

            if "/*" in stripped:
                if "*/" in stripped:
                    # Single line block comment: remove it
                    stripped = re.sub(r'/\*.*?\*/', '', stripped).strip()
                    if not stripped:
                        continue
                else:
                    in_block_comment = True
                    stripped = stripped[:stripped.index("/*")].strip()
                    if not stripped:
                        continue

            # Skip single-line line comments #
            if stripped.startswith("#"):
                continue

            # Lexical tokenization using shlex
            try:
                # Pre-split brackets if attached to text so [host1 host2] becomes [ host1 host2 ]
                # but preserve brackets in quotes
                normalized_line = self._normalize_brackets(stripped)
                lexer = shlex.shlex(normalized_line, posix=True)
                lexer.whitespace_split = True
                lexer.commenters = "#"
                tokens = list(lexer)
            except Exception as ex:
                # Malformed quoting
                tokens = stripped.split()
                sanitized_raw = sanitize_junos_command(tokens)
                commands.append(
                    JunosCommand(
                        operation=JunosOperation.UNKNOWN,
                        tokens=tokens,
                        raw_sanitized=sanitized_raw,
                        line_number=line_idx,
                        parse_error=f"Lexical error: {ex}",
                        extraction_status=ExtractionStatus.PARSE_ERROR,
                        requires_manual_review=True,
                    )
                )
                continue

            if not tokens:
                continue

            # Token-aware secret sanitization
            sanitized_raw = sanitize_junos_command(tokens)
            access_denied = has_access_denied_token(tokens)

            op_str = tokens[0].lower()
            if op_str == "set":
                op = JunosOperation.SET
            elif op_str == "activate":
                op = JunosOperation.ACTIVATE
            elif op_str == "deactivate":
                op = JunosOperation.DEACTIVATE
            else:
                op = JunosOperation.UNKNOWN

            cmd = JunosCommand(
                operation=op,
                tokens=tokens,
                raw_sanitized=sanitized_raw,
                line_number=line_idx,
                access_denied=access_denied,
                requires_manual_review=access_denied,
            )

            if op == JunosOperation.UNKNOWN:
                cmd.parse_error = f"Unrecognized Junos operation: {tokens[0]}"
                cmd.extraction_status = ExtractionStatus.PARSE_ERROR
                cmd.requires_manual_review = True
            elif access_denied:
                cmd.extraction_status = ExtractionStatus.UNSUPPORTED

            commands.append(cmd)

        return commands

    def _normalize_brackets(self, line: str) -> str:
        """Ensure spaces around [ and ] when not inside quoted strings."""
        result: List[str] = []
        in_quote = False
        quote_char = ''
        for char in line:
            if char in ('"', "'"):
                if not in_quote:
                    in_quote = True
                    quote_char = char
                elif quote_char == char:
                    in_quote = False
                    quote_char = ''
                result.append(char)
            elif in_quote:
                result.append(char)
            elif char == '[':
                result.append(' [ ')
            elif char == ']':
                result.append(' ] ')
            else:
                result.append(char)
        return "".join(result)
