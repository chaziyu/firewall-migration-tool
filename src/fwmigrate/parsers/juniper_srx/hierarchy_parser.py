"""Normalize hierarchical Junos configuration into display-set commands."""

from __future__ import annotations

import shlex
from dataclasses import dataclass


@dataclass
class _Token:
    value: str
    line: int


def _lex(content: str) -> list[_Token]:
    tokens: list[_Token] = []
    buf: list[str] = []
    quote: str | None = None
    line = 1
    token_line = 1
    i = 0

    def flush() -> None:
        nonlocal buf
        if buf:
            tokens.append(_Token("".join(buf), token_line))
            buf = []

    while i < len(content):
        char = content[i]
        if char == "\n":
            line += 1
        if quote:
            if char == quote:
                quote = None
            else:
                buf.append(char)
            i += 1
            continue
        if content.startswith("/*", i):
            end = content.find("*/", i + 2)
            if end < 0:
                break
            line += content[i:end + 2].count("\n")
            i = end + 2
            continue
        if char == "#":
            end = content.find("\n", i)
            i = len(content) if end < 0 else end
            continue
        if char in "\"'":
            if not buf:
                token_line = line
            quote = char
        elif char in "{};[]":
            flush()
            tokens.append(_Token(char, line))
        elif char.isspace():
            flush()
        else:
            if not buf:
                token_line = line
            buf.append(char)
        i += 1
    flush()
    return tokens


def normalize_hierarchy(content: str) -> str:
    """Return equivalent root-level ``set``/``deactivate`` lines."""
    tokens = _lex(content)
    output: list[str] = []
    index = 0

    def parse_block(prefix: list[str], stop: str | None = None) -> None:
        nonlocal index
        statement: list[_Token] = []
        while index < len(tokens):
            token = tokens[index]
            index += 1
            if token.value == stop:
                return
            if token.value == "{":
                parse_block(prefix + [t.value for t in statement], "}")
                statement = []
            elif token.value == ";":
                emit(prefix + [t.value for t in statement], token.line)
                statement = []
            else:
                statement.append(token)
        if statement:
            emit(prefix + [t.value for t in statement], statement[0].line)

    def emit(path: list[str], line: int) -> None:
        if not path:
            return
        inactive = []
        while path and path[0].lower() == "inactive:":
            inactive.append(path.pop(0))
        if path and path[0].lower().startswith("inactive:"):
            path[0] = path[0][len("inactive:"):]
            inactive.append("inactive:")
        if not path:
            return
        path = [p for p in path if p not in ("[", "]")]
        if inactive:
            output.append("deactivate " + " ".join(path))
        output.append("set " + " ".join(path))

    parse_block([])
    return "\n".join(output)


def looks_hierarchical(content: str) -> bool:
    """Detect brace/semicolon Junos syntax without parsing feature semantics."""
    return any(char in content for char in "{};") and not any(
        line.lstrip().startswith(("set ", "activate ", "deactivate "))
        for line in content.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
