from typing import Any, Dict, List

from fwmigrate.core.base_deployer import BaseDeployer
from fwmigrate.core.base_generator import BaseTargetGenerator
from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.core.plugins import PluginSpec, PluginType, normalize_vendor_id


class PluginRegistrationError(ValueError):
    """Raised when a plugin identifier collides with another implementation."""


class PluginRegistry:
    """Metadata registry and factory for source, target, and deployment plugins."""

    _parser_specs: Dict[str, PluginSpec] = {}
    _generator_specs: Dict[str, PluginSpec] = {}
    _deployer_specs: Dict[str, PluginSpec] = {}

    @classmethod
    def _storage(cls, plugin_type: PluginType) -> Dict[str, PluginSpec]:
        return {
            PluginType.SOURCE_PARSER: cls._parser_specs,
            PluginType.TARGET_GENERATOR: cls._generator_specs,
            PluginType.DEPLOYER: cls._deployer_specs,
        }[plugin_type]

    @classmethod
    def register(cls, spec: PluginSpec) -> PluginSpec:
        if not isinstance(spec, PluginSpec):
            raise TypeError("PluginRegistry.register expects a PluginSpec")
        normalized = spec.normalized()
        storage = cls._storage(normalized.plugin_type)
        existing = storage.get(normalized.vendor_id)
        if existing:
            if existing.implementation is not normalized.implementation:
                raise PluginRegistrationError(
                    f"Plugin '{normalized.vendor_id}' is already registered with "
                    f"{existing.implementation.__name__}"
                )
            return existing

        identifiers = {normalized.vendor_id, *normalized.aliases}
        if len(identifiers) != len(normalized.aliases) + 1:
            raise PluginRegistrationError(
                f"Plugin '{normalized.vendor_id}' declares duplicate identifiers"
            )
        for other_id, other in storage.items():
            collision = identifiers & {other_id, *other.aliases}
            if collision:
                raise PluginRegistrationError(
                    f"Plugin identifier collision for {sorted(collision)[0]!r}"
                )
        storage[normalized.vendor_id] = normalized
        return normalized

    @classmethod
    def register_parser(cls, spec: PluginSpec) -> PluginSpec:
        if not isinstance(spec, PluginSpec):
            raise TypeError("Parser registrations require a PluginSpec")
        if PluginType(spec.plugin_type) != PluginType.SOURCE_PARSER:
            raise ValueError("Parser registrations require SOURCE_PARSER PluginSpec")
        return cls.register(spec)

    @classmethod
    def register_generator(cls, spec: PluginSpec) -> PluginSpec:
        if not isinstance(spec, PluginSpec):
            raise TypeError("Generator registrations require a PluginSpec")
        if PluginType(spec.plugin_type) != PluginType.TARGET_GENERATOR:
            raise ValueError("Generator registrations require TARGET_GENERATOR PluginSpec")
        return cls.register(spec)

    @classmethod
    def register_deployer(cls, spec: PluginSpec) -> PluginSpec:
        if not isinstance(spec, PluginSpec):
            raise TypeError("Deployer registrations require a PluginSpec")
        if PluginType(spec.plugin_type) != PluginType.DEPLOYER:
            raise ValueError("Deployer registrations require DEPLOYER PluginSpec")
        return cls.register(spec)

    @classmethod
    def _resolve(cls, storage: Dict[str, PluginSpec], vendor_id: str, kind: str) -> PluginSpec:
        requested = normalize_vendor_id(vendor_id)
        spec = storage.get(requested)
        if spec is None:
            spec = next(
                (candidate for candidate in storage.values() if requested in candidate.aliases),
                None,
            )
        if spec is None:
            raise KeyError(
                f"{kind} '{vendor_id}' is not registered. Available: {list(storage)}"
            )
        return spec

    @classmethod
    def get_parser_spec(cls, vendor_id: str) -> PluginSpec:
        return cls._resolve(cls._parser_specs, vendor_id, "Source parser")

    @classmethod
    def get_generator_spec(cls, vendor_id: str) -> PluginSpec:
        return cls._resolve(cls._generator_specs, vendor_id, "Target generator")

    @classmethod
    def get_deployer_spec(cls, deployer_id: str) -> PluginSpec:
        return cls._resolve(cls._deployer_specs, deployer_id, "Deployer")

    @classmethod
    def get_parser(cls, vendor_id: str) -> BaseSourceParser:
        return cls.get_parser_spec(vendor_id).implementation()

    @classmethod
    def get_generator(cls, vendor_id: str, **kwargs: Any) -> BaseTargetGenerator:
        return cls.get_generator_spec(vendor_id).implementation(**kwargs)

    @classmethod
    def get_deployer(cls, deployer_id: str, **kwargs: Any) -> BaseDeployer:
        return cls.get_deployer_spec(deployer_id).implementation(**kwargs)

    @classmethod
    def list_parsers(cls) -> List[PluginSpec]:
        return list(cls._parser_specs.values())

    @classmethod
    def list_generators(cls) -> List[PluginSpec]:
        return list(cls._generator_specs.values())

    @classmethod
    def list_deployers(cls) -> List[PluginSpec]:
        return list(cls._deployer_specs.values())

    @classmethod
    def list_source_vendors(cls) -> List[Dict[str, Any]]:
        return [
            {
                **dict(spec.metadata),
                "vendor_id": spec.vendor_id,
                "display_name": spec.display_name,
                "file_extensions": list(spec.supported_extensions),
                "aliases": list(spec.aliases),
                "experimental": spec.experimental,
                "description": spec.description,
                "capabilities": list(spec.capabilities),
            }
            for spec in cls.list_parsers()
        ]

    @classmethod
    def list_target_vendors(cls) -> List[Dict[str, Any]]:
        return [
            {
                **dict(spec.metadata),
                "vendor_id": spec.vendor_id,
                "display_name": spec.display_name,
                "supported_formats": list(spec.supported_formats),
                "aliases": list(spec.aliases),
                "experimental": spec.experimental,
                "description": spec.description,
                "capabilities": list(spec.capabilities),
                "supports_deployment": spec.supports_deployment,
                "supports_terraform": spec.supports_terraform,
            }
            for spec in cls.list_generators()
        ]
