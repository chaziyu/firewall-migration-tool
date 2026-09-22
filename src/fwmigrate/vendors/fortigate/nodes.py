from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class CommandNode:
    """
    One CLI command inside a config or edit block.

    Examples:
        set subnet 10.0.0.0 255.255.255.0
        append member "server2"
        unset comment

    No FortiOS semantic interpretation is performed here.
    """

    operation: str
    key: str
    values: list[str] = field(default_factory=list)

    line_number: int | None = None


@dataclass(slots=True)
class UnknownCommandNode:
    """
    A command whose leading keyword is not understood by the parser.

    Keeping it allows unsupported source syntax to be preserved rather
    than silently discarded.
    """

    keyword: str
    values: list[str] = field(default_factory=list)

    line_number: int | None = None


@dataclass(slots=True)
class CommentNode:
    """A source comment preserved with its original line number."""

    value: str
    line_number: int | None = None


@dataclass(slots=True)
class EditNode:
    """
    One FortiGate `edit ... next` block.

    Example:

        edit "server1"
            set subnet 10.0.0.1 255.255.255.255

            config tagging
                ...
            end
        next
    """

    name: str

    commands: list[CommandNode | UnknownCommandNode] = field(
        default_factory=list
    )

    children: list[ConfigNode] = field(default_factory=list)

    comments: list[CommentNode] = field(default_factory=list)

    start_line_number: int | None = None
    end_line_number: int | None = None


@dataclass(slots=True)
class ConfigNode:
    """
    One FortiGate `config ... end` block.

    Example:

        config firewall address
            edit "server1"
                ...
            next
        end
    """

    name: str

    commands: list[CommandNode | UnknownCommandNode] = field(
        default_factory=list
    )

    edits: list[EditNode] = field(default_factory=list)

    children: list[ConfigNode] = field(default_factory=list)

    comments: list[CommentNode] = field(default_factory=list)

    start_line_number: int | None = None
    end_line_number: int | None = None


@dataclass(slots=True)
class FortiGateConfigTree:
    """
    Root structural representation of a FortiGate configuration file.

    This is syntax/structure only. It is not the typed FortiGate
    configuration model used by extraction.
    """

    configs: list[ConfigNode] = field(default_factory=list)
    comments: list[CommentNode] = field(default_factory=list)

    unknown_commands: list[UnknownCommandNode] = field(
        default_factory=list
    )

    @property
    def top_level_sections(self) -> list[str]:
        return [node.name for node in self.configs]

    def find_configs(self, name: str) -> list[ConfigNode]:
        """Return all config nodes whose exact structural name matches `name`,
        including nested config blocks.
        """

        result: list[ConfigNode] = []

        def walk_config(node: ConfigNode) -> None:
            if node.name == name:
                result.append(node)

            for child in node.children:
                walk_config(child)

            for edit in node.edits:
                walk_edit(edit)

        def walk_edit(node: EditNode) -> None:
            for child in node.children:
                walk_config(child)

        for config in self.configs:
            walk_config(config)

        return result