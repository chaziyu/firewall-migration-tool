from fwmigrate.core.registry import PluginRegistry
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser

# Auto-register source parser and API client
PluginRegistry.register_parser(PANOSSourceParser)

