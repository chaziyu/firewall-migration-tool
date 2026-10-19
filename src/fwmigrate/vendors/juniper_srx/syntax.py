"""Junos lexical tokens with source spans, independent of command semantics."""

from dataclasses import dataclass
import shlex


@dataclass(frozen=True, slots=True)
class JunosToken:
    value: str
    line: int
    start: int
    end: int
    kind: str = "word"
    quoted: bool = False


def lex_junos(content: str, *, hierarchical: bool = True) -> list[JunosToken]:
    tokens = []
    punctuation = "{};[]" if hierarchical else "[]"
    i, line = 0, 1
    while i < len(content):
        char = content[i]
        if char.isspace():
            if char == "\n":
                if not hierarchical:
                    tokens.append(JunosToken(char, line, i, i + 1, "newline"))
                line += 1
            i += 1
            continue
        start, token_line = i, line
        placeholder = next((value for value in ("[REDACTED]", "[ACCESS-DENIED]")
                            if content.startswith(value, i)), None)
        if placeholder:
            tokens.append(JunosToken(placeholder, line, i, i + len(placeholder)))
            i += len(placeholder)
            continue
        if char == "#" or content.startswith("/*", i):
            if char == "#":
                end = content.find("\n", i)
                end = len(content) if end < 0 else end
            else:
                end = content.find("*/", i + 2)
                if end < 0:
                    raise ValueError(f"Unterminated Junos comment at line {line}.")
                end += 2
            tokens.append(JunosToken(content[i:end], line, i, end, "comment"))
            line += content[i:end].count("\n")
            i = end
            continue
        if char in punctuation:
            tokens.append(JunosToken(char, line, i, i + 1, "symbol"))
            i += 1
            continue
        quote = None
        quoted = False
        while i < len(content):
            char = content[i]
            if char == "\\" and quote != "'":
                if i + 1 >= len(content):
                    raise ValueError(f"Incomplete Junos escape at line {line}.")
                line += content[i:i + 2].count("\n")
                i += 2
                continue
            if quote:
                if char == quote:
                    quote = None
            elif char in "\"'":
                quote, quoted = char, True
            elif char.isspace() or char in punctuation or char == "#" or content.startswith("/*", i):
                break
            line += char == "\n"
            i += 1
        if quote:
            raise ValueError(f"Unterminated Junos quote at line {token_line}.")
        raw = content[start:i]
        try:
            value, = shlex.split(raw, comments=False)
        except ValueError as error:
            raise ValueError(f"Invalid Junos token at line {token_line}.") from error
        tokens.append(JunosToken(value, token_line, start, i, quoted=quoted))
    return tokens


def mask_comments(content: str) -> str:
    """Remove comments outside strings without moving source line numbers.

    Display-set quoting errors are diagnosed per command by its tokenizer, so a
    malformed quoted line must not hide valid commands on subsequent lines.
    """
    output = list(content)
    i, quote, line = 0, None, 1
    while i < len(content):
        char = content[i]
        if char == "\n":
            quote = None
            line += 1
        if char == "\\" and quote != "'":
            i += 2
            continue
        if quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "#" or content.startswith("/*", i):
            if char == "#":
                end = content.find("\n", i)
                end = len(content) if end < 0 else end
            else:
                end = content.find("*/", i + 2)
                if end < 0:
                    raise ValueError(f"Unterminated Junos comment at line {line}.")
                end += 2
            for index in range(i, end):
                if content[index] != "\n":
                    output[index] = " "
            line += content[i:end].count("\n")
            i = end
            continue
        i += 1
    return "".join(output)
