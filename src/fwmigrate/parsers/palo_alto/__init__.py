from fwmigrate.core.registry import PluginRegistry
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser
from fwmigrate.parsers.palo_alto.api_client import PANOSLiveAPIClient

# Auto-register source parser and API client
PluginRegistry.register_parser(PANOSSourceParser)
PluginRegistry.register_api_client(PANOSLiveAPIClient)

__all__ = ["PANOSSourceParser", "PANOSLiveAPIClient"]
