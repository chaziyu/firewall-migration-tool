"""Line-aware FortiOS block reader; preserves unsupported settings for inventory."""

from dataclasses import dataclass, field
import shlex
from typing import Any


@dataclass
class Block:
    kind: str
    name: str
    line_start: int
    line_end: int = 0
    settings: dict[str, list[str]] = field(default_factory=dict)
    commands: list[dict[str, Any]] = field(default_factory=list)
    children: list["Block"] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def inventory(self) -> dict[str, Any]:
        values = {k: v[0] if len(v) == 1 else v for k, v in self.settings.items()}
        if self.commands:
            values["_commands"] = self.commands
        if self.children:
            values["_nested"] = [
                {"kind": b.kind, "name": b.name, "settings": b.inventory()}
                for b in self.children
            ]
        return values

    def all_errors(self) -> list[str]:
        return self.errors + [e for child in self.children for e in child.all_errors()]


def read_blocks(text: str) -> Block:
    root = Block("root", "", 1)
    stack = [root]
    lines = text.splitlines()
    numbered_lines = iter(enumerate(lines, 1))
    for number, line in numbered_lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        # FortiOS quoted comments, certificates and replacement messages can span
        # physical lines. Preserve their newlines rather than tokenizing secrets
        # in the continuation lines as independent commands.
        while True:
            try:
                parts = shlex.split(line, comments=False, posix=True)
                break
            except ValueError:
                continuation = next(numbered_lines, None)
                if continuation is None:
                    stack[-1].errors.append(f"Invalid quoting starting at line {number}; content withheld.")
                    parts = []
                    break
                line += "\n" + continuation[1]
        if not parts:
            continue
        command, args = parts[0].lower(), parts[1:]
        if command in {"config", "edit"}:
            if command == "edit" and stack[-1].kind == "edit":
                stack[-1].errors.append(f"Missing next before line {number}.")
                stack.pop().line_end = number - 1
            child = Block(command, " ".join(args), number)
            if not args:
                child.errors.append(f"Missing {command} name at line {number}.")
            if command == "edit" and (len(args) != 1 or stack[-1].kind != "config"):
                child.errors.append(f"Invalid edit header/context at line {number}.")
            stack[-1].children.append(child)
            stack.append(child)
        elif command in {"next", "end"}:
            if args:
                stack[-1].errors.append(f"Unexpected arguments after {command} at line {number}.")
            expected = "edit" if command == "next" else "config"
            if command == "end" and stack[-1].kind == "edit":
                stack[-1].errors.append(f"Missing next before end at line {number}.")
                stack.pop().line_end = number
            if len(stack) == 1 or stack[-1].kind != expected:
                stack[-1].errors.append(f"Unexpected {command} at line {number}.")
            else:
                stack.pop().line_end = number
        elif command in {"set", "unset", "append"} and args:
            key, values = args[0].replace("-", "_"), args[1:]
            if command == "set":
                stack[-1].settings[key] = values
                if not values:
                    stack[-1].errors.append(f"Missing value for {key} at line {number}.")
            elif command == "unset":
                if values:
                    stack[-1].errors.append(f"Unexpected unset arguments at line {number}.")
                stack[-1].settings.pop(key, None)
                stack[-1].commands.append({"operation": "unset", "setting": key})
            else:
                current = stack[-1].settings.setdefault(key, [])
                current.extend(v for v in values if v not in current)
                stack[-1].commands.append({"operation": "append", "setting": key})
        else:
            # Do not guess ordering or mutation semantics for scripts/deltas.
            operation = command if command in {"move", "delete", "rename", "purge", "select"} else "unrecognized"
            stack[-1].commands.append({"operation": operation, "arguments": "[WITHHELD]"})
            stack[-1].errors.append(f"Unsupported command at line {number}; content withheld.")
    for block in stack[1:]:
        block.line_end = len(lines)
        block.errors.append(f"Unclosed {block.kind} block starting at line {block.line_start}.")
    root.line_end = len(lines)
    return root
