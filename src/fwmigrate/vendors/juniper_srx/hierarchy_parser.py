"""Normalize hierarchical Junos syntax while preserving quotes and provenance."""

from dataclasses import dataclass
import shlex

from .syntax import JunosToken, lex_junos


@dataclass(frozen=True, slots=True)
class HierarchyCommand:
    operation: str
    path: tuple[JunosToken, ...]
    line: int


def hierarchy_commands(content: str) -> tuple[HierarchyCommand, ...]:
    tokens = [token for token in lex_junos(content) if token.kind != "comment"]
    output = []
    index = 0

    def clean(statement):
        inactive = bool(statement and not statement[0].quoted and statement[0].value == "inactive:")
        return (statement[1:] if inactive else statement), inactive

    def parse_block(prefix=(), opening_line=None):
        nonlocal index
        statement = []
        list_open = None
        while index < len(tokens):
            token = tokens[index]
            index += 1
            if token.kind == "symbol":
                if token.value == "[":
                    if list_open is not None:
                        raise ValueError(f"Nested Junos list at line {token.line}.")
                    list_open = token.line
                    continue
                if token.value == "]":
                    if list_open is None:
                        raise ValueError(f"Unexpected Junos list delimiter at line {token.line}.")
                    list_open = None
                    continue
                if list_open is not None:
                    raise ValueError(f"Unclosed Junos list at line {list_open}.")
                if token.value == "}":
                    if opening_line is None or statement:
                        raise ValueError(f"Unexpected Junos block end or missing semicolon at line {token.line}.")
                    return
                if token.value == "{":
                    if not statement:
                        raise ValueError(f"Missing Junos hierarchy at line {token.line}.")
                    children, inactive = clean(statement)
                    path = (*prefix, *children)
                    if inactive:
                        output.append(HierarchyCommand("deactivate", path, statement[0].line))
                    parse_block(path, token.line)
                    statement = []
                    continue
                if token.value == ";":
                    if statement:
                        children, inactive = clean(statement)
                        path = (*prefix, *children)
                        if inactive:
                            output.append(HierarchyCommand("deactivate", path, statement[0].line))
                        output.append(HierarchyCommand("set", path, token.line))
                    statement = []
                    continue
            statement.append(token)
        if list_open is not None or opening_line is not None or statement:
            line = list_open or opening_line or statement[0].line
            raise ValueError(f"Incomplete Junos hierarchy at line {line}.")

    parse_block()
    return tuple(output)


def normalize_hierarchy_with_provenance(content: str) -> tuple[str, tuple[int, ...]]:
    commands = hierarchy_commands(content)
    return (
        "\n".join(command.operation + " " + " ".join(shlex.quote(token.value) for token in command.path)
                  for command in commands),
        tuple(command.line for command in commands),
    )


def looks_hierarchical(content: str) -> bool:
    """Detect the source format before doing any normalization or redaction."""
    # Inspect only leading trivia before a command prefix. Scanning all lines
    # with display-set quote rules would misread multiline hierarchy strings.
    offset = 0
    while offset < len(content):
        if content[offset].isspace():
            offset += 1
        elif content[offset] == "#":
            end = content.find("\n", offset)
            offset = len(content) if end < 0 else end + 1
        elif content.startswith("/*", offset):
            end = content.find("*/", offset + 2)
            if end < 0:
                raise ValueError(f"Unterminated Junos comment at line {content[:offset].count(chr(10)) + 1}.")
            offset = end + 2
        else:
            break
    first = content[offset:].split(None, 1)
    if first and first[0] in {"set", "activate", "deactivate"}:
        return False
    return any(token.kind == "symbol" and token.value in "{};" for token in lex_junos(content))
