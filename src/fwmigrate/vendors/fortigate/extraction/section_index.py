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
        ordered_entries: list[IndexedConfig] = []
        source_entries: list[IndexedConfig] = []
        grouped: dict[str, list[IndexedConfig]] = {}
        entries_by_node: dict[int, IndexedConfig] = {}

        def walk_ordered(
            node: ConfigNode,
            *,
            vdom: str,
            parent_path: str | None,
            parent_objects: tuple[str, ...],
        ) -> None:
            if node.name == "vdom":
                for edit in node.edits:
                    for child in edit.children:
                        walk_ordered(
                            child,
                            vdom=edit.name,
                            parent_path=None,
                            parent_objects=(),
                        )
                return

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

            ordered_entries.append(entry)
            grouped.setdefault(node.name, []).append(entry)
            entries_by_node[id(node)] = entry

            for child in node.children:
                walk_ordered(
                    child,
                    vdom=vdom,
                    parent_path=source_path,
                    parent_objects=parent_objects,
                )
            for edit in node.edits:
                for child in edit.children:
                    walk_ordered(
                        child,
                        vdom=vdom,
                        parent_path=source_path,
                        parent_objects=(*parent_objects, edit.name),
                    )

        def walk_source(node: ConfigNode) -> None:
            if node.name == "vdom":
                for edit in node.edits:
                    for child in edit.children:
                        walk_source(child)
                return

            source_entries.append(entries_by_node[id(node)])
            for edit in node.edits:
                for child in edit.children:
                    walk_source(child)
            for child in node.children:
                walk_source(child)

        for root in tree.configs:
            walk_ordered(
                root,
                vdom="root",
                parent_path=None,
                parent_objects=(),
            )
        for root in tree.configs:
            walk_source(root)

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
