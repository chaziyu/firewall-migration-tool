from typing import Dict, Type, List, Optional, Any, Union
from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.core.base_api_client import BaseAPIClient
from fwmigrate.core.base_generator import BaseTargetGenerator
from fwmigrate.core.base_deployer import BaseDeployer

class PluginRegistry:
    """Central registry and factory for all source parsers, API clients, target generators, and deployers."""

    _parsers: Dict[str, Type[BaseSourceParser]] = {}
    _api_clients: Dict[str, Type[BaseAPIClient]] = {}
    _generators: Dict[str, Type[BaseTargetGenerator]] = {}
    _deployers: Dict[str, Type[BaseDeployer]] = {}

    @classmethod
    def register_parser(cls, parser_or_cls: Any, instance: Any = None) -> Any:
        if instance is not None:
            inst = instance() if isinstance(instance, type) else instance
            cls._parsers[parser_or_cls] = inst.__class__
            return instance
        if isinstance(parser_or_cls, type):
            temp_inst = parser_or_cls()
            cls._parsers[temp_inst.vendor_id] = parser_or_cls
            return parser_or_cls
        else:
            cls._parsers[parser_or_cls.vendor_id] = parser_or_cls.__class__
            return parser_or_cls

    @classmethod
    def register_api_client(cls, client_cls: Type[BaseAPIClient]) -> Type[BaseAPIClient]:
        cls._api_clients[client_cls.vendor_id_class()] = client_cls
        return client_cls

    @classmethod
    def register_generator(cls, generator_or_cls: Any, instance: Any = None) -> Any:
        if instance is not None:
            inst = instance() if isinstance(instance, type) else instance
            cls._generators[generator_or_cls] = inst.__class__
            return instance
        if isinstance(generator_or_cls, type):
            temp_inst = generator_or_cls()
            cls._generators[temp_inst.vendor_id] = generator_or_cls
            return generator_or_cls
        else:
            cls._generators[generator_or_cls.vendor_id] = generator_or_cls.__class__
            return generator_or_cls

    @classmethod
    def register_deployer(cls, deployer_or_cls: Any, instance: Any = None) -> Any:
        if instance is not None:
            inst = instance() if isinstance(instance, type) else instance
            cls._deployers[deployer_or_cls] = inst.__class__
            return instance
        if isinstance(deployer_or_cls, type):
            temp_inst = deployer_or_cls()
            cls._deployers[temp_inst.deployer_id] = deployer_or_cls
            return deployer_or_cls
        else:
            cls._deployers[deployer_or_cls.deployer_id] = deployer_or_cls.__class__
            return deployer_or_cls

    @classmethod
    def get_parser(cls, vendor_id: str) -> BaseSourceParser:
        if vendor_id not in cls._parsers:
            raise KeyError(f"Source parser '{vendor_id}' is not registered. Available: {list(cls._parsers.keys())}")
        return cls._parsers[vendor_id]()

    @classmethod
    def get_api_client_cls(cls, vendor_id: str) -> Type[BaseAPIClient]:
        if vendor_id not in cls._api_clients:
            raise KeyError(f"API client for vendor '{vendor_id}' is not registered. Available: {list(cls._api_clients.keys())}")
        return cls._api_clients[vendor_id]

    @classmethod
    def get_generator(cls, vendor_id: str, **kwargs) -> BaseTargetGenerator:
        if vendor_id not in cls._generators:
            raise KeyError(f"Target generator '{vendor_id}' is not registered. Available: {list(cls._generators.keys())}")
        return cls._generators[vendor_id](**kwargs)

    @classmethod
    def get_deployer(cls, deployer_id: str, **kwargs) -> BaseDeployer:
        if deployer_id not in cls._deployers:
            raise KeyError(f"Deployer '{deployer_id}' is not registered. Available: {list(cls._deployers.keys())}")
        return cls._deployers[deployer_id](**kwargs)

    @classmethod
    def list_source_vendors(cls) -> List[Dict[str, Any]]:
        """Returns metadata list of all available source parsers for UI/CLI."""
        results = []
        for vid, p_cls in cls._parsers.items():
            inst = p_cls()
            exts = getattr(inst, 'supported_extensions', getattr(inst, 'file_extensions', ['.conf', '.txt']))
            results.append({
                "vendor_id": inst.vendor_id,
                "display_name": inst.display_name,
                "file_extensions": exts,
                "has_api_client": inst.vendor_id in cls._api_clients
            })
        return results

    @classmethod
    def list_target_vendors(cls) -> List[Dict[str, Any]]:
        """Returns metadata list of all available target generators for UI/CLI."""
        results = []
        for vid, g_cls in cls._generators.items():
            inst = g_cls()
            results.append({
                "vendor_id": inst.vendor_id,
                "display_name": inst.display_name,
                "supported_formats": inst.supported_formats
            })
        return results
