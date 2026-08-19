from typing import Dict, Type, List, Optional, Any
from fg2pan.core.base_parser import BaseSourceParser
from fg2pan.core.base_api_client import BaseAPIClient
from fg2pan.core.base_generator import BaseTargetGenerator
from fg2pan.core.base_deployer import BaseDeployer

class PluginRegistry:
    """Central registry and factory for all source parsers, API clients, target generators, and deployers."""

    _parsers: Dict[str, Type[BaseSourceParser]] = {}
    _api_clients: Dict[str, Type[BaseAPIClient]] = {}
    _generators: Dict[str, Type[BaseTargetGenerator]] = {}
    _deployers: Dict[str, Type[BaseDeployer]] = {}

    @classmethod
    def register_parser(cls, parser_cls: Type[BaseSourceParser]) -> Type[BaseSourceParser]:
        temp_inst = parser_cls()
        cls._parsers[temp_inst.vendor_id] = parser_cls
        return parser_cls

    @classmethod
    def register_api_client(cls, client_cls: Type[BaseAPIClient]) -> Type[BaseAPIClient]:
        cls._api_clients[client_cls.vendor_id_class()] = client_cls
        return client_cls

    @classmethod
    def register_generator(cls, generator_cls: Type[BaseTargetGenerator]) -> Type[BaseTargetGenerator]:
        temp_inst = generator_cls()
        cls._generators[temp_inst.vendor_id] = generator_cls
        return generator_cls

    @classmethod
    def register_deployer(cls, deployer_cls: Type[BaseDeployer]) -> Type[BaseDeployer]:
        temp_inst = deployer_cls()
        cls._deployers[temp_inst.deployer_id] = deployer_cls
        return deployer_cls

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
        results = []
        for v_id, p_cls in cls._parsers.items():
            inst = p_cls()
            api_fields = []
            if v_id in cls._api_clients:
                api_fields = cls._api_clients[v_id].get_field_definitions()
            results.append({
                'vendor_id': inst.vendor_id,
                'display_name': inst.display_name,
                'supported_extensions': inst.supported_extensions,
                'supports_live_api': v_id in cls._api_clients,
                'api_fields': api_fields,
            })
        return results

    @classmethod
    def list_target_vendors(cls) -> List[Dict[str, Any]]:
        results = []
        for v_id, g_cls in cls._generators.items():
            inst = g_cls()
            results.append({
                'vendor_id': inst.vendor_id,
                'display_name': inst.display_name,
                'supported_formats': inst.supported_formats,
            })
        return results
