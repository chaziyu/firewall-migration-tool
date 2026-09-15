from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Type


class PluginType(str, Enum):
    SOURCE_PARSER = "source_parser"
    TARGET_GENERATOR = "target_generator"
    DEPLOYER = "deployer"


def normalize_vendor_id(value: str) -> str:
    """Normalize case and surrounding whitespace without fuzzy matching."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Plugin vendor identifiers must be non-empty strings")
    return value.strip().casefold()


@dataclass(frozen=True)
class PluginSpec:
    vendor_id: str
    display_name: str
    plugin_type: PluginType
    implementation: Type[Any]
    aliases: tuple[str, ...] = ()
    supported_formats: tuple[str, ...] = ()
    supported_extensions: tuple[str, ...] = ()
    experimental: bool = False
    description: str = ""
    capabilities: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
    supports_deployment: bool = False
    supports_terraform: bool = False

    def normalized(self) -> "PluginSpec":
        return PluginSpec(
            vendor_id=normalize_vendor_id(self.vendor_id),
            display_name=self.display_name,
            plugin_type=PluginType(self.plugin_type),
            implementation=self.implementation,
            aliases=tuple(normalize_vendor_id(alias) for alias in self.aliases),
            supported_formats=tuple(self.supported_formats),
            supported_extensions=tuple(self.supported_extensions),
            experimental=self.experimental,
            description=self.description,
            capabilities=tuple(self.capabilities),
            metadata=dict(self.metadata),
            supports_deployment=self.supports_deployment,
            supports_terraform=self.supports_terraform,
        )
