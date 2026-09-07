from __future__ import annotations

from typing import Any, Dict, Optional, Set

from pydantic import BaseModel, Field

from fwmigrate.parsers.fortigate.extraction import sanitize_source_attributes
from fwmigrate.parsers.fortigate.model import FGConfig
from fwmigrate.parsers.fortigate.source_tree import FGSourceNode


class FGSystemFSSOPolling(BaseModel):
    """Typed, source-only FortiOS ``config system fsso-polling`` settings."""

    source_context: str = "root"
    status: Optional[str] = None
    listening_port: Optional[int] = None
    authentication: Optional[str] = None
    has_auth_password: bool = False
    source_explicit_fields: Set[str] = Field(default_factory=set)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGConfigWithSystemFSSOPolling(FGConfig):
    """FortiGate config extension carrying the system FSSO polling singleton."""

    system_fsso_polling: Optional[FGSystemFSSOPolling] = None


def parse_system_fsso_polling_node(
    node: FGSourceNode,
    source_context: str,
) -> FGSystemFSSOPolling:
    """Build typed FSSO polling settings without retaining credential values.

    The recursive source tree remains authoritative for command operations.
    Unknown future fields are sanitized into ``extra_settings``.
    """

    attributes: Dict[str, Any] = {
        "source_context": source_context or "root",
        "source_explicit_fields": set(),
        "has_auth_password": False,
    }
    unknown: Dict[str, Any] = {}

    for command in node.commands:
        key = command.key.replace("-", "_")
        operation = getattr(command, "operation", "set")
        values = list(command.values)

        if operation == "unset":
            attributes["source_explicit_fields"].discard(key)
            if key == "auth_password":
                attributes["has_auth_password"] = False
            elif key in {"status", "listening_port", "authentication"}:
                attributes.pop(key, None)
            else:
                unknown.pop(key, None)
            continue

        attributes["source_explicit_fields"].add(key)

        if key == "auth_password":
            # Never retain the actual password, including in source fallback.
            attributes["has_auth_password"] = bool(values)
            continue

        # ``append`` has no documented meaning for these scalar settings.
        # Keep that operation in the recursive source tree, but do not invent
        # typed semantics for it.
        if operation != "set":
            continue

        value: Any = (
            values[0]
            if len(values) == 1
            else (" ".join(values) if values else True)
        )
        if key in {"status", "listening_port", "authentication"}:
            attributes[key] = value
        else:
            unknown[key] = value

    raw_port = attributes.get("listening_port")
    if raw_port is not None:
        try:
            attributes["listening_port"] = int(raw_port)
        except (TypeError, ValueError):
            attributes.pop("listening_port", None)
            unknown["unparsed_listening_port"] = raw_port

    attributes["extra_settings"] = sanitize_source_attributes(unknown)
    return FGSystemFSSOPolling(**attributes)


_INSTALLED = False


def install_system_fsso_polling_support() -> None:
    """Register typed system FSSO polling support with the FortiGate adapter.

    The repository installs several FortiGate source-parser extensions in phase
    order. This wrapper follows the same pattern and delegates every section
    except ``system fsso-polling`` to the behavior already installed before it.
    """

    global _INSTALLED
    if _INSTALLED:
        return

    from fwmigrate.parsers.fortigate import coverage as coverage_module
    from fwmigrate.parsers.fortigate import extractor as extractor_module
    from fwmigrate.parsers.fortigate import parser as parser_module

    parser_cls = parser_module.FortiGateParser
    original_init = parser_cls.__init__
    original_build = parser_cls._build_structured_typed_parents

    def patched_init(self: Any, tokenizer: Any) -> None:
        original_init(self, tokenizer)
        # The parser starts with an empty FGConfig. Replace it with a strict
        # superset before any source data is parsed so existing collections and
        # behavior remain unchanged.
        self.config = FGConfigWithSystemFSSOPolling()

    def patched_build(
        self: Any,
        source_path: str,
        top_edits: list[FGSourceNode],
    ) -> None:
        if source_path == "system fsso-polling":
            root = top_edits[0] if top_edits else FGSourceNode(
                node_type="config",
                name=source_path,
            )
            self.config.system_fsso_polling = parse_system_fsso_polling_node(
                root,
                self.current_context or "root",
            )
            return
        original_build(self, source_path, top_edits)

    parser_cls.__init__ = patched_init
    parser_cls._build_structured_typed_parents = patched_build

    coverage_module.TYPED_SECTIONS.add("system fsso-polling")
    coverage_module.TYPED_EXTRACT_ONLY_SECTIONS.add("system fsso-polling")
    coverage_module.SEMANTIC_SUPPORT_LEVELS[
        "system fsso-polling"
    ] = "TYPED_EXTRACT_ONLY"
    coverage_module._COLLECTIONS[
        "system fsso-polling"
    ] = ("system_fsso_polling", "system_fsso_polling")

    original_classify = coverage_module.classify_section_coverage

    def classify_with_system_fsso(
        source_sections: list[Any],
        fg_config: FGConfig,
        ir_config: Any,
    ) -> None:
        original_classify(source_sections, fg_config, ir_config)
        for section in source_sections:
            if section.path != "system fsso-polling":
                continue
            if section.object_count_source == 0:
                section.object_count_source = 1
            section.object_count_parsed = (
                1 if getattr(fg_config, "system_fsso_polling", None) is not None else 0
            )
            section.object_count_normalized = None
            section.status = coverage_module.ExtractionStatus.EXTRACT_ONLY
            section.parser_handler = "FortiGateParser._build_structured_typed_parents"
            typed_note = (
                "Typed system FSSO polling settings are retained as "
                "source-only operational semantics."
            )
            if typed_note not in section.notes:
                section.notes.append(typed_note)
            support_note = "Semantic support level: TYPED_EXTRACT_ONLY."
            if support_note not in section.notes:
                section.notes.append(support_note)

    coverage_module.classify_section_coverage = classify_with_system_fsso
    # extractor imported the function object before this extension is installed,
    # so update its local binding as well.
    extractor_module.classify_section_coverage = classify_with_system_fsso
    extractor_module.SOURCE_ONLY_OPERATIONAL_SECTIONS.add("system fsso-polling")

    _INSTALLED = True
