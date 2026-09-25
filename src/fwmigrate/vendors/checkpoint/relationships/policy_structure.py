from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..model.policy import CPAccessLayer, CPAccessRule, CPAccessSection
from ..model.source import CheckPointConfig
from .references import CPBrokenReference, CPReferenceIndex, CPReferenceKind, CPResolvedReference


@dataclass(frozen=True, slots=True)
class CPPackageLayerRelationship:
    package: Any; layer: CPAccessLayer | None; source_field: str = "access_layers"; issue: CPBrokenReference | None = None


@dataclass(frozen=True, slots=True)
class CPSectionRelationship:
    layer: CPAccessLayer | None; section: CPAccessSection; section_path: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CPInlineLayerRelationship:
    parent_layer: CPAccessLayer | None; parent_rule: CPAccessRule; inline_layer: CPAccessLayer | None; issue: CPBrokenReference | None = None


@dataclass(frozen=True, slots=True)
class CPPolicyStructure:
    package_layers: tuple[CPPackageLayerRelationship, ...] = ()
    sections: tuple[CPSectionRelationship, ...] = ()
    rules: tuple[CPAccessRule, ...] = ()
    inline_layers: tuple[CPInlineLayerRelationship, ...] = ()
    issues: tuple[CPBrokenReference, ...] = ()

    @property
    def package_layer_map(self):
        result = {}
        for item in self.package_layers:
            key = item.package.uid or item.package.name
            if key and item.layer: result.setdefault(key, []).append(item.layer.uid or item.layer.name)
        return {key: tuple(value) for key, value in result.items()}

    @property
    def inline_layer_map(self):
        return {item.inline_layer.uid or item.inline_layer.name: item.parent_layer.uid or item.parent_layer.name
                for item in self.inline_layers if item.inline_layer and item.parent_layer}


def build_policy_structure(config: CheckPointConfig, references: CPReferenceIndex | None = None) -> CPPolicyStructure:
    references = references or __import__(__package__ + ".references", fromlist=["build_reference_index"]).build_reference_index(config)
    package_layers = []; issues = []
    for package in config.policy_packages:
        for value in package.access_layers:
            resolved = references.resolve(value, owner=package, expected_kinds=(CPReferenceKind.ACCESS_LAYER,), source_field="access_layers")
            if isinstance(resolved, CPResolvedReference): package_layers.append(CPPackageLayerRelationship(package, resolved.target))
            else: package_layers.append(CPPackageLayerRelationship(package, None, issue=resolved)); issues.append(resolved)
    for layer in config.access_layers:
        if {"package_uid", "package"} & set(layer.explicit_fields) and (layer.package_uid or layer.package):
            package = references.by_uid.get(layer.package_uid or "")
            if package is None:
                package = next((item for item in config.policy_packages if item.name == layer.package and (item.domain_uid or item.domain) == (layer.domain_uid or layer.domain)), None)
            if package and not any(item.package is package and item.layer is layer for item in package_layers): package_layers.append(CPPackageLayerRelationship(package, layer))
    sections = tuple(CPSectionRelationship(next((layer for layer in config.access_layers if (layer.uid or layer.name) == section.layer_uid), None), section, tuple(section.section_path)) for section in config.access_sections)
    inline_layers = []
    for rule in config.access_rules:
        if not rule.inline_layer: continue
        resolved = references.resolve(rule.inline_layer, owner=rule, expected_kinds=(CPReferenceKind.ACCESS_LAYER,), source_field="inline_layer")
        parent = next((layer for layer in config.access_layers if layer.uid == (rule.layer_uid or rule.parent_layer_uid) or layer.name == rule.layer), None)
        if isinstance(resolved, CPResolvedReference): inline_layers.append(CPInlineLayerRelationship(parent, rule, resolved.target))
        else: inline_layers.append(CPInlineLayerRelationship(parent, rule, None, resolved)); issues.append(resolved)
    return CPPolicyStructure(tuple(package_layers), sections, tuple(config.access_rules), tuple(inline_layers), tuple(issues))


__all__ = ["CPInlineLayerRelationship", "CPPackageLayerRelationship", "CPPolicyStructure", "CPSectionRelationship", "build_policy_structure"]
