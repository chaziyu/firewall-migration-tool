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
        for line_number, line in enumerate(self.text.splitlines(), start=1):
            line = line.strip()
            
            if not line:
                continue
                
            if line.startswith("#"):
                yield Token(TokenType.COMMENT, line, line_number)
                continue
                
            try:
                # Use shlex to handle quoted strings and escape characters properly
                lexer = shlex.shlex(line, posix=True)
                lexer.whitespace_split = True
                lexer.quotes = '"\''
                
                parts = list(lexer)
            except ValueError:
                # For multiline strings or unbalanced quotes (like HTML buffers)
                parts = line.split()
                
            if not parts:
                continue
                
            keyword = parts[0].lower()
            
            # Check if it's a known directive
            try:
                token_type = TokenType(keyword)
                yield Token(token_type, parts[0], line_number)
                
                # The rest of the line are STRING tokens (arguments)
                for part in parts[1:]:
                    yield Token(TokenType.STRING, part, line_number)
            except ValueError:
                # If it's not a known keyword at the start of a line,
                # treat the whole line as string tokens.
                for part in parts:
                    yield Token(TokenType.STRING, part, line_number)
