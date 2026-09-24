from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Iterator, Mapping

from ..nodes import ConfigNode, FortiGateConfigTree


@dataclass(frozen=True, slots=True)
class IndexedConfig:
    node: ConfigNode
    vdom: str
    source_path: str
    parent_objects: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SectionIndex:
    entries: tuple[IndexedConfig, ...]
    source_entries: tuple[IndexedConfig, ...]
    by_name: Mapping[str, tuple[IndexedConfig, ...]]

    @classmethod
    def build(cls, tree: FortiGateConfigTree) -> "SectionIndex":
        entries: list[IndexedConfig] = []

        def walk(
            node: ConfigNode,
            *,
            vdom: str,
            parent_path: str | None,
            parent_objects: tuple[str, ...],
        ) -> tuple[list[IndexedConfig], list[IndexedConfig]]:
            if node.name == "vdom":
                entries: list[IndexedConfig] = []
                source_entries: list[IndexedConfig] = []
                for edit in node.edits:
                    for child in edit.children:
                        child_entries, child_source_entries = walk(
                            child,
                            vdom=edit.name,
                            parent_path=None,
                            parent_objects=(),
                        )
                        entries.extend(child_entries)
                        source_entries.extend(child_source_entries)
                return entries, source_entries

            source_path = (
                f"{parent_path} {node.name}"
                if parent_path
                else node.name
            )
            entry = IndexedConfig(
                node=node,
                vdom=vdom,
                source_path=source_path,
                parent_objects=parent_objects,
            )

            direct_entries: list[IndexedConfig] = []
            direct_source_entries: list[IndexedConfig] = []
            for child in node.children:
                child_entries, child_source_entries = walk(
                    child,
                    vdom=vdom,
                    parent_path=source_path,
                    parent_objects=parent_objects,
                )
                direct_entries.extend(child_entries)
                direct_source_entries.extend(child_source_entries)

            edit_entries: list[IndexedConfig] = []
            edit_source_entries: list[IndexedConfig] = []
            for edit in node.edits:
                for child in edit.children:
                    child_entries, child_source_entries = walk(
                        child,
                        vdom=vdom,
                        parent_path=source_path,
                        parent_objects=(*parent_objects, edit.name),
                    )
                    edit_entries.extend(child_entries)
                    edit_source_entries.extend(child_source_entries)

            return (
                [entry, *direct_entries, *edit_entries],
                [entry, *edit_source_entries, *direct_source_entries],
            )

        ordered_entries: list[IndexedConfig] = []
        source_entries: list[IndexedConfig] = []
        for root in tree.configs:
            root_entries, root_source_entries = walk(
                root,
                vdom="root",
                parent_path=None,
                parent_objects=(),
            )
            ordered_entries.extend(root_entries)
            source_entries.extend(root_source_entries)

        grouped: dict[str, list[IndexedConfig]] = {}
        for entry in ordered_entries:
            grouped.setdefault(entry.node.name, []).append(entry)

        return cls(
            entries=tuple(ordered_entries),
            source_entries=tuple(source_entries),
            by_name=MappingProxyType(
                {name: tuple(items) for name, items in grouped.items()}
            ),
        )

    def iter_edits(self, section_path: str) -> Iterator[object]:
        from .common import SectionEdit

        for entry in self.by_name.get(section_path, ()):
            for edit in entry.node.edits:
                yield SectionEdit(
                    section_path=section_path,
                    edit=edit,
                    vdom=entry.vdom,
                )

    def iter_configs(self, section_path: str) -> Iterator[object]:
        from .common import SectionConfig

        for entry in self.by_name.get(section_path, ()):
            yield SectionConfig(
                section_path=section_path,
                config=entry.node,
                vdom=entry.vdom,
            )
