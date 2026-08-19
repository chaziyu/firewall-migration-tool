from fg2pan.core.registry import PluginRegistry
from fg2pan.parsers.palo_alto.parser import PANOSSourceParser
from fg2pan.parsers.palo_alto.api_client import PANOSLiveAPIClient

# Auto-register source parser and API client
PluginRegistry.register_parser(PANOSSourceParser)
PluginRegistry.register_api_client(PANOSLiveAPIClient)

__all__ = ["PANOSSourceParser", "PANOSLiveAPIClient"]
