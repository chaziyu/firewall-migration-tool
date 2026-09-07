from typing import List, Optional, Dict, Any
from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.extraction.models import ExtractionResult
from fwmigrate.ir.core import IRConfig
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate import parser as _parser_module
from fwmigrate.parsers.fortigate import transformer as _transformer_module
from fwmigrate.parsers.fortigate import dependencies as _dependencies_module
from fwmigrate.parsers.fortigate.shaping_models import install_phase22_parser_support
from fwmigrate.parsers.fortigate.phase_23_25_extensions import (
    install_phase_23_25_extensions,
)
from fwmigrate.parsers.fortigate.service_parser_extensions import (
    install_service_parser_extensions,
)
from fwmigrate.parsers.fortigate.phase_28_30_extensions import (
    install_phase_28_30_extensions,
)
from fwmigrate.parsers.fortigate.policy_nat_preservation_extensions import (
    install_policy_nat_preservation_extensions,
)
from fwmigrate.parsers.fortigate.system_fsso import (
    install_system_fsso_polling_support,
)
from fwmigrate.parsers.fortigate.phase_41_security_profiles import (
    install_phase_41_security_profile_support,
)
from fwmigrate.parsers.fortigate.phase_42_antivirus import (
    install_phase_42_antivirus_support,
)
from fwmigrate.parsers.fortigate.phase_43_webfilter import (
    install_phase_43_webfilter_support,
)


# Install FortiGate source-parser extensions in phase order so later wrappers
# delegate through earlier behavior rather than replacing it.
install_phase22_parser_support()
install_phase_23_25_extensions(_parser_module)
install_service_parser_extensions(_parser_module)
install_phase_28_30_extensions(_parser_module)
install_policy_nat_preservation_extensions(
    _parser_module,
    _transformer_module,
    _dependencies_module,
)
install_system_fsso_polling_support()
install_phase_41_security_profile_support(_parser_module)
install_phase_42_antivirus_support(_parser_module)
install_phase_43_webfilter_support(_parser_module)


class FortiGateSourceParser(BaseSourceParser):
    @property
    def vendor_id(self) -> str:
        return "fortigate"

    @property
    def display_name(self) -> str:
        return "Fortinet FortiGate"

    @property
    def supported_extensions(self) -> List[str]:
        return [".conf", ".cfg", ".txt"]

    def parse(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> IRConfig:
        return self.extract(content, zone_mapping=zone_mapping).canonical_ir

    def extract(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> ExtractionResult:
        return extract_fortigate_config(content, zone_mapping=zone_mapping)


# Register automatically
PluginRegistry.register_parser(FortiGateSourceParser)
