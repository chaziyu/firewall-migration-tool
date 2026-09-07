from fwmigrate.core.registry import PluginRegistry
from fwmigrate.parsers.palo_alto import parser as _parser_module
from fwmigrate.parsers.palo_alto.registered_parser import PANOSSourceParser

# Keep the historical parser module import path stable while registering the
# completeness-enhanced, fail-closed subclass for all normal package imports.
_parser_module.PANOSSourceParser = PANOSSourceParser
PluginRegistry.register_parser(PANOSSourceParser)
