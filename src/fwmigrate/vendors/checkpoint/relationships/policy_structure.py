from __future__ import annotations

from ..model.source import CheckPointConfig


def build_policy_structure(config: CheckPointConfig) -> tuple[dict[str, tuple[str, ...]], dict[str, str]]:
    package_layers: dict[str, list[str]] = {}

    def add(package_key: str | None, layer_key: str | None) -> None:
        if package_key and layer_key and layer_key not in package_layers.setdefault(package_key, []):
            package_layers[package_key].append(layer_key)

    for package in config.policy_packages:
        package_key = package.uid or package.name
        if not package_key:
            continue
        for ref in package.access_layers:
            layer_key = ref.uid or ref.name or str(ref) if hasattr(ref, "uid") else str(ref)
            add(package_key, layer_key)
    for layer in config.access_layers:
        add(layer.package_uid or layer.package, layer.uid or layer.name)
    inline_layers = {layer.uid or layer.name or "": layer.parent_layer_uid for layer in config.access_layers if layer.parent_layer_uid}
    return {key: tuple(value) for key, value in package_layers.items()}, inline_layers
