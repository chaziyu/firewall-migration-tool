"""Narrow dependency safety for FortiGate IP-pool group name collisions."""

from __future__ import annotations

from typing import Any, Iterable

from fwmigrate.extraction.models import SourceInventoryItem


def install_ippool_group_dependency_safety(
    dependencies_module: Any,
    extractor_module: Any,
) -> None:
    """Mark policy poolname references ambiguous across pool and group types."""

    current = dependencies_module.build_dependency_registry
    if getattr(current, "_ippool_group_dependency_safety", False):
        return

    def build_dependency_registry(
        items: Iterable[SourceInventoryItem],
    ) -> list[Any]:
        item_list = list(items)
        records = current(item_list)

        object_types: dict[tuple[str, str], set[str]] = {}
        for item in item_list:
            path = dependencies_module._norm(item.source_path)
            if path not in {"firewall ippool", "firewall ippool_grp"}:
                continue
            context = item.source_context or "root"
            for name in (item.name, item.source_id):
                if name is None or not str(name):
                    continue
                object_types.setdefault((context, str(name)), set()).add(path)

        ambiguous_keys = {
            key
            for key, paths in object_types.items()
            if {"firewall ippool", "firewall ippool_grp"}.issubset(paths)
        }
        if not ambiguous_keys:
            return records

        result = []
        for record in records:
            source_path = dependencies_module._norm(record.source_path)
            source_field = dependencies_module._norm(record.source_field)
            key = (record.source_context or "root", record.reference)
            if (
                source_path == "firewall policy"
                and source_field == "poolname"
                and key in ambiguous_keys
            ):
                result.append(
                    record.model_copy(
                        update={
                            "result": "UNRESOLVED",
                            "target_path": None,
                            "target_uid": None,
                            "target_name": None,
                            "notes": (
                                "Reference is ambiguous in the same VDOM/context; "
                                "both firewall ippool and firewall ippool_grp "
                                "match this policy poolname."
                            ),
                            "reason": "ambiguous-reference",
                        }
                    )
                )
            else:
                result.append(record)
        return result

    build_dependency_registry._ippool_group_dependency_safety = True
    dependencies_module.build_dependency_registry = build_dependency_registry
    extractor_module.build_dependency_registry = build_dependency_registry
