from __future__ import annotations

from ..model.source import CheckPointConfig


def build_policy_structure(config: CheckPointConfig) -> tuple[dict[str, tuple[str, ...]], dict[str, str]]:
    package_layers: dict[str, list[str]] = {}
    for layer in config.access_layers:
        if layer.package_uid or layer.package:
            package_layers.setdefault(layer.package_uid or layer.package or "", []).append(layer.uid or layer.name or "")
    inline_layers = {layer.uid or layer.name or "": layer.parent_layer_uid for layer in config.access_layers if layer.parent_layer_uid}
    return {key: tuple(value) for key, value in package_layers.items()}, inline_layers
