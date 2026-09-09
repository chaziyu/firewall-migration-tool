import enum
import shlex
import dataclasses
from typing import Iterator

class TokenType(enum.Enum):
    CONFIG = "config"
    EDIT = "edit"
    SET = "set"
    UNSET = "unset"
    NEXT = "next"
    END = "end"
    APPEND = "append"
    STRING = "string"  # A value (unquoted or quoted)
    COMMENT = "comment"

@dataclasses.dataclass
class Token:
    type: TokenType
    value: str
    line_number: int

class TokenizerError(Exception):
    pass

class FortiGateTokenizer:
    """Tokenizes a FortiGate configuration file."""
    
    def __init__(self, text: str):
        self.text = text
        
    def tokenize(self) -> Iterator[Token]:
        """Yields tokens from the configuration text."""
        logical_lines: list[str] = []
        start_line_number = 0

        for line_number, physical_line in enumerate(
            self.text.splitlines(),
            start=1,
        ):
            line = physical_line.strip()

            if not logical_lines and not line:
                continue

            if not logical_lines and line.startswith("#"):
                yield Token(TokenType.COMMENT, line, line_number)
                continue

            if not logical_lines:
                start_line_number = line_number

            logical_lines.append(line)
            logical_line = "\n".join(logical_lines)

            try:
                # A quoted FortiGate value may span multiple physical lines.
                # Let shlex determine when the logical command is complete so
                # this remains generic rather than PEM/certificate-specific.
                lexer = shlex.shlex(logical_line, posix=True)
                lexer.whitespace_split = True
                lexer.quotes = '"\''
                lexer.commenters = ""
                parts = list(lexer)
            except ValueError:
                continue

            yield from self._tokens_from_parts(
                parts,
                start_line_number,
            )
            logical_lines = []

        if logical_lines:
            # Retain the previous tolerant behavior for malformed/unbalanced
            # input at EOF without preventing earlier configuration extraction.
            yield from self._tokens_from_parts(
                "\n".join(logical_lines).split(),
                start_line_number,
            )

    @staticmethod
    def _tokens_from_parts(
        parts: list[str],
        line_number: int,
    ) -> Iterator[Token]:
        """Convert one completed logical command into parser tokens."""
        if not parts:
            return

        keyword = parts[0].lower()

        try:
            token_type = TokenType(keyword)
            yield Token(token_type, parts[0], line_number)

            for part in parts[1:]:
                yield Token(TokenType.STRING, part, line_number)
        except ValueError:
            for part in parts:
                yield Token(TokenType.STRING, part, line_number)
