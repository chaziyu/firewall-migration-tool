"""Phase 48 effective-state dependency accounting for FortiGate profile groups."""

from __future__ import annotations

from typing import Any, Iterable

from fwmigrate.extraction.models import DependencyRecord, SourceInventoryItem
from fwmigrate.parsers.fortigate.phase_46_50_extensions import (
    PROFILE_GROUP_REFERENCE_RULES,
)


def install_phase_48_effective_profile_group_dependencies(
    dependencies_module: Any,
    extractor_module: Any,
) -> None:
    """Filter profile-group dependencies to the final operation-aware state.

    The generic dependency registry intentionally walks source commands so it
    can preserve reference evidence.  For ``firewall profile-group``, however,
    Phase 48 requires dependency validation against the final effective value,
    not every historical ``set``.  This wrapper leaves source commands intact
    and only filters dependency records after the generic resolver has done its
    context/type resolution.
    """

    current = dependencies_module.build_dependency_registry
    if getattr(current, "_phase_48_effective_wrapped", False):
        extractor_module.build_dependency_registry = current
        return

    profile_fields = {
        dependencies_module._norm(field)
        for field in PROFILE_GROUP_REFERENCE_RULES
    }

    def build_dependency_registry(
        items: Iterable[SourceInventoryItem],
    ) -> list[DependencyRecord]:
        materialized = list(items)
        dependencies = current(materialized)

        effective: dict[tuple[str, str | None, str], list[str]] = {}
        for item in dependencies_module._flatten(materialized):
            if dependencies_module._norm(item.source_path) != "firewall profile-group":
                continue

            context = item.source_context or "root"
            source_object = item.name or item.source_id
            for command in item.commands:
                field = dependencies_module._norm(command.key)
                if field not in profile_fields:
                    continue

                key = (context, source_object, field)
                values = dependencies_module._reference_values(command.values)
                operation = command.operation.lower()
                if operation == "set":
                    effective[key] = list(values)
                elif operation == "append":
                    effective.setdefault(key, []).extend(values)
                elif operation == "unset":
                    effective.pop(key, None)

        filtered: list[DependencyRecord] = []
        seen_profile_dependencies: set[tuple[str, str | None, str, str]] = set()
        for dependency in dependencies:
            source_path = dependencies_module._norm(dependency.source_path)
            field = dependencies_module._norm(dependency.source_field)
            if source_path != "firewall profile-group" or field not in profile_fields:
                filtered.append(dependency)
                continue

            context = dependency.source_context or "root"
            key = (context, dependency.source_object, field)
            if dependency.reference not in effective.get(key, []):
                continue

            dependency_key = (
                context,
                dependency.source_object,
                field,
                dependency.reference,
            )
            if dependency_key in seen_profile_dependencies:
                continue
            seen_profile_dependencies.add(dependency_key)
            filtered.append(dependency)

        return filtered

    build_dependency_registry._phase_48_effective_wrapped = True
    dependencies_module.build_dependency_registry = build_dependency_registry

    # extractor.py imports the resolver symbol directly, so update that alias
    # as well.  Its extraction orchestration remains otherwise unchanged.
    extractor_module.build_dependency_registry = build_dependency_registry
