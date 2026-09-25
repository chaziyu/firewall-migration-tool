from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from ..command_evaluator import (
    CommandEvaluation,
    evaluate_commands,
)
from ..nodes import (
    ConfigNode,
    EditNode,
    FortiGateConfigTree,
)
from .section_index import SectionIndex
from ..section_registry import get_section_spec


@dataclass(frozen=True, slots=True)
class SectionEdit:
    """One edit block with its FortiGate source context."""

    section_path: str
    edit: EditNode
    vdom: str = "root"


@dataclass(frozen=True, slots=True)
class SectionConfig:
    """One config block with its FortiGate source context."""

    section_path: str
    config: ConfigNode
    vdom: str = "root"


def normalize_source_key(
    key: str,
) -> str:
    """
    Convert raw FortiGate CLI spelling to ordinary Python field spelling.

    This normalization is intentionally generic.

    Domain-specific mappings belong in the calling extractor through
    `field_map`.

    Examples:
        associated-interface -> associated_interface
        exclude-member       -> exclude_member

    The tokenizer, parser, nodes, section registry, and command evaluator
    retain the original FortiGate CLI spelling.
    """

    return key.replace("-", "_")


def _model_field_name(
    source_key: str,
    field_map: Mapping[str, str],
) -> str:
    """
    Resolve one raw FortiGate source key to its source-model field.

    `field_map` may use either raw FortiGate CLI spelling or the normally
    normalized Python spelling.

    Examples:

        field_map={
            "member": "members",
            "exclude-member": "exclude_members",
            "tacacs+-server": "tacacs_server",
        }
    """

    normalized = normalize_source_key(
        source_key
    )

    if source_key in field_map:
        return field_map[source_key]

    if normalized in field_map:
        return field_map[normalized]

    return normalized


def _record_raw_extra(
    raw_extra: dict[str, Any],
    key: str,
    value: Any,
) -> None:
    """
    Preserve source evidence without overwriting an earlier value.

    Raw-extra keys retain original FortiGate CLI spelling whenever
    possible.
    """

    if key not in raw_extra:
        raw_extra[key] = value
        return

    current = raw_extra[key]

    if not isinstance(current, list):
        current = [current]

    if isinstance(value, list):
        raw_extra[key] = [
            *current,
            *value,
        ]
    else:
        raw_extra[key] = [
            *current,
            value,
        ]


def _evaluate_section_commands(
    section_path: str,
    commands,
) -> CommandEvaluation:
    """
    Evaluate commands using primitive field metadata from the section
    registry.

    The registry supplies only primitive source shapes. No FortiGate
    semantic interpretation occurs here.
    """

    spec = get_section_spec(
        section_path
    )

    if spec is None:
        return evaluate_commands(
            commands
        )

    return evaluate_commands(
        commands,
        list_fields=spec.list_fields,
        integer_fields=spec.integer_fields,
        integer_list_fields=spec.integer_list_fields,
        scalar_fields=spec.scalar_fields,
    )


def evaluate_edit(
    section_path: str,
    edit: EditNode,
) -> CommandEvaluation:
    """
    Evaluate explicit commands attached to one `edit ... next` block.

    This function does not:
        - normalize source keys
        - construct source models
        - apply FortiOS defaults
        - resolve references
        - derive topology
        - perform validation
    """

    return _evaluate_section_commands(
        section_path,
        edit.commands,
    )


def evaluate_edit_sequence(
    section_path: str,
    edits: Iterable[EditNode],
) -> CommandEvaluation:
    """Evaluate repeated edits to one keyed source object in source order."""

    return _evaluate_section_commands(
        section_path,
        (command for edit in edits for command in edit.commands),
    )


def evaluate_config(
    section_path: str,
    config: ConfigNode,
) -> CommandEvaluation:
    """
    Evaluate explicit commands attached directly to one config block.

    This is required for FortiGate sections such as:

        config system sdwan
            set status enable
            ...
        end

    and:

        config vpn ssl settings
            set status enable
            ...
        end
    """

    return _evaluate_section_commands(
        section_path,
        config.commands,
    )


def source_model_kwargs(
    evaluation: CommandEvaluation,
    *,
    model_type: type[BaseModel],
    name: str | None = None,
    vdom: str | None = None,
    field_map: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """
    Convert evaluated FortiGate source state into source-model kwargs.

    Processing flow:

        raw FortiGate source key
            ↓
        generic Python-name normalization
            ↓
        optional extractor-specific field mapping
            ↓
        source-model field
            OR
        raw_extra

    Declared registry fields deliberately omitted from the small source
    model are retained in `raw_extra` instead of being silently dropped.

    Untyped, malformed, or unsupported source evidence from the command
    evaluator is also retained in `raw_extra`.

    Structural metadata such as `name` and `vdom` is not included in
    `explicit_fields`.
    """

    field_map = dict(
        field_map or {}
    )

    model_fields = set(
        model_type.model_fields
    )

    values: dict[str, Any] = {}

    raw_extra: dict[str, Any] = dict(
        evaluation.untyped_values
    )

    explicit_fields: set[str] = set()

    # --------------------------------------------------------------
    # Evaluated declared source fields
    # --------------------------------------------------------------

    for (
        source_key,
        value,
    ) in evaluation.values.items():
        target_key = _model_field_name(
            source_key,
            field_map,
        )

        if target_key in model_fields:
            values[target_key] = value
            continue

        # The registry understands this source field, but the small
        # source model deliberately does not expose it.
        #
        # Preserve the original source key/value rather than allowing
        # Pydantic to silently discard it.
        _record_raw_extra(
            raw_extra,
            source_key,
            value,
        )

    # --------------------------------------------------------------
    # Explicit-field tracking
    # --------------------------------------------------------------

    for source_key in evaluation.explicit_fields:
        target_key = _model_field_name(
            source_key,
            field_map,
        )

        if target_key in model_fields:
            explicit_fields.add(
                target_key
            )

    # --------------------------------------------------------------
    # Structural source identity/context
    # --------------------------------------------------------------

    if name is not None:
        if "name" not in model_fields:
            raise ValueError(
                f"{model_type.__name__} does not define "
                f"a 'name' field"
            )

        values["name"] = name

    if vdom is not None:
        if "vdom" not in model_fields:
            raise ValueError(
                f"{model_type.__name__} does not define "
                f"a 'vdom' field"
            )

        values["vdom"] = vdom

    # --------------------------------------------------------------
    # Source-preservation metadata
    # --------------------------------------------------------------

    if raw_extra:
        if "raw_extra" not in model_fields:
            raise ValueError(
                f"{model_type.__name__} cannot preserve "
                f"raw source fields because it does not define "
                f"'raw_extra'"
            )

        values["raw_extra"] = raw_extra

    elif "raw_extra" in model_fields:
        values["raw_extra"] = {}

    if "explicit_fields" in model_fields:
        values["explicit_fields"] = (
            explicit_fields
        )

    return values


def get_child_config(
    parent: EditNode | ConfigNode,
    name: str,
) -> ConfigNode | None:
    """
    Return the first direct child config matching the requested
    structural name.

    Nested names are literal structural names.

    Example:

        config system sdwan
            config members
                ...
            end
        end

    The nested ConfigNode name is `members`, not
    `system sdwan members`.
    """

    for child in parent.children:
        if child.name == name:
            return child

    return None


def iter_section_edits(
    tree: FortiGateConfigTree | SectionIndex,
    section_path: str,
) -> Iterator[SectionEdit]:
    """
    Yield edit blocks belonging to an exact structural config section.

    VDOM context is derived structurally from `config vdom`.

    `section_path` must correspond to an actual ConfigNode name.

    Semantic registry paths for nested configs, such as:

        system sdwan members

    are not structural ConfigNode names. Nested configs should be reached
    from their parent with `get_child_config()`.
    """

    index = (
        tree
        if isinstance(tree, SectionIndex)
        else SectionIndex.build(tree)
    )
    yield from index.iter_edits(section_path)


def iter_section_configs(
    tree: FortiGateConfigTree | SectionIndex,
    section_path: str,
) -> Iterator[SectionConfig]:
    """
    Yield config blocks matching an exact structural section name.

    Used for FortiGate sections whose source commands are attached
    directly to the ConfigNode rather than inside an edit block.
    """

    index = (
        tree
        if isinstance(tree, SectionIndex)
        else SectionIndex.build(tree)
    )
    yield from index.iter_configs(section_path)


def _iter_configs_with_context(
    tree: FortiGateConfigTree | SectionIndex,
) -> Iterator[tuple[ConfigNode, str]]:
    """
    Traverse every ConfigNode while deriving its FortiGate VDOM context.

    Both edit-based and config-based extraction use this traversal so
    VDOM handling cannot diverge between extractors.
    """

    if isinstance(tree, SectionIndex):
        yield from (
            (entry.node, entry.vdom)
            for entry in tree.entries
        )
        return

    def walk_config(
        node: ConfigNode,
        *,
        vdom: str,
    ) -> Iterator[tuple[ConfigNode, str]]:
        yield node, vdom

        # FortiGate VDOM structure:
        #
        # config vdom
        #     edit <vdom-name>
        #         config ...
        #             ...
        #         end
        #     next
        # end
        #
        # Config blocks beneath each VDOM edit inherit that edit name
        # as their VDOM context.
        if node.name == "vdom":
            for edit in node.edits:
                for child in edit.children:
                    yield from walk_config(
                        child,
                        vdom=edit.name,
                    )

            return

        # Direct nested configs retain the current VDOM context.
        for child in node.children:
            yield from walk_config(
                child,
                vdom=vdom,
            )

        # Configs nested beneath ordinary edit blocks also retain the
        # current VDOM context.
        for edit in node.edits:
            for child in edit.children:
                yield from walk_config(
                    child,
                    vdom=vdom,
                )

    for root in tree.configs:
        yield from walk_config(
            root,
            vdom="root",
        )
