import dataclasses
import enum
import io
import shlex
from typing import Iterator


class TokenType(enum.Enum):
    CONFIG = "config"
    EDIT = "edit"
    SET = "set"
    UNSET = "unset"
    APPEND = "append"
    NEXT = "next"
    END = "end"

    # Recognized but normally not expected in exported configuration.

    STRING = "string"
    COMMENT = "comment"
    UNKNOWN = "unknown"


class TokenizerError(Exception):
    """Raised when FortiGate CLI syntax cannot be tokenized."""


@dataclasses.dataclass(frozen=True, slots=True)
class Token:
    type: TokenType
    value: str
    line_number: int



class FortiGateTokenizer:
    """Tokenize FortiGate CLI syntax without interpreting FortiOS semantics."""

    def __init__(self, text: str):
        self.text = text

    def tokenize(self) -> Iterator[Token]:
        logical_lines: list[str] = []
        start_line_number: int | None = None
        quote: str | None = None
        escaped = False

        for line_number, raw_line in enumerate(
            io.StringIO(self.text),
            start=1,
        ):
            physical_line = raw_line[:-1] if raw_line.endswith("\n") else raw_line
            if physical_line.endswith("\r"):
                physical_line = physical_line[:-1]
            stripped = physical_line.strip()

            # Ignore empty lines outside a multiline command.
            if not logical_lines and not stripped:
                continue

            # Preserve standalone comments.
            if not logical_lines and stripped.startswith("#"):
                yield Token(
                    TokenType.COMMENT,
                    stripped,
                    line_number,
                )
                continue

            if not logical_lines:
                start_line_number = line_number

            # Preserve physical-line contents for multiline quoted values.
            logical_lines.append(physical_line)

            quote, escaped = self._scan_lexical_state(
                physical_line + ("\n" if raw_line.endswith("\n") else ""),
                quote=quote,
                escaped=escaped,
            )
            if quote is not None or escaped:
                continue

            logical_command = "\n".join(logical_lines)

            try:
                parts = self._split_command(logical_command)
            except ValueError as exc:
                raise TokenizerError(
                    f"Malformed syntax at line {start_line_number}: {exc}"
                ) from exc

            assert start_line_number is not None

            yield from self._tokens_from_parts(
                parts,
                start_line_number,
            )

            logical_lines.clear()
            start_line_number = None
            quote = None
            escaped = False

        # Unterminated quote / malformed logical command.
        if logical_lines:
            assert start_line_number is not None

            yield Token(
                TokenType.UNKNOWN,
                "\n".join(logical_lines),
                start_line_number,
            )

    @staticmethod
    def _split_command(command: str) -> list[str]:
        if not any(character in command for character in ('"', "'", "\\")):
            return command.split()

        lexer = shlex.shlex(command, posix=True)

        lexer.whitespace_split = True
        lexer.commenters = ""

        return list(lexer)

    @staticmethod
    def _scan_lexical_state(
        text: str,
        *,
        quote: str | None,
        escaped: bool,
    ) -> tuple[str | None, bool]:
        """Track only quote/escape state across physical lines."""

        for character in text:
            if escaped:
                escaped = False
                continue

            if quote == "'":
                if character == "'":
                    quote = None
                continue

            if character == "\\":
                escaped = True
            elif quote is None and character in ('"', "'"):
                quote = character
            elif quote == '"' and character == '"':
                quote = None

        return quote, escaped

    @staticmethod
    def _is_incomplete_command(
        error: ValueError,
    ) -> bool:
        return str(error) in {
            "No closing quotation",
            "No escaped character",
        }

    @staticmethod
    def _tokens_from_parts(
        parts: list[str],
        line_number: int,
    ) -> Iterator[Token]:
        if not parts:
            return

        keyword = parts[0].lower()

        try:
            token_type = TokenType(keyword)
        except ValueError:
            yield Token(
                TokenType.UNKNOWN,
                parts[0],
                line_number,
            )

            for part in parts[1:]:
                yield Token(
                    TokenType.STRING,
                    part,
                    line_number,
                )

            return

        yield Token(
            token_type,
            parts[0],
            line_number,
        )

        for part in parts[1:]:
            yield Token(
                TokenType.STRING,
                part,
                line_number,
            )
