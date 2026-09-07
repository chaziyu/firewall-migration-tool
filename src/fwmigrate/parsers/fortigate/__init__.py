from typing import List, Optional, Dict, Any
from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.extraction.models import ExtractionResult
from fwmigrate.ir.core import IRConfig
from fwmigrate.parsers.fortigate import extractor as _extractor_module
from fwmigrate.parsers.fortigate import parser as _parser_module
from fwmigrate.parsers.fortigate import transformer as _transformer_module
from fwmigrate.parsers.fortigate import dependencies as _dependencies_module
from fwmigrate.parsers.fortigate import source_tree as _source_tree_module
from fwmigrate.parsers.fortigate import phase_46_50_extensions as _phase_46_50_module
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
    _effective_node_attributes as _phase_41_effective_node_attributes,
    install_phase_41_security_profile_support,
)
from fwmigrate.parsers.fortigate.phase_42_antivirus import (
    install_phase_42_antivirus_support,
)
from fwmigrate.parsers.fortigate.phase_48_profile_group_dependencies import (
    install_phase_48_effective_profile_group_dependencies,
)


def _phase_46_50_effective_node_attributes(
    source: Any,
    model: Any = None,
    field_spec: Optional[Dict[str, set[str]]] = None,
):
    """Use the Phase 41 evaluator with Phase 46-50 declarative field specs."""
    if isinstance(model, dict) and field_spec is None:
        field_spec = model
        model = None
    if field_spec:
        field_spec = dict(field_spec)
        if "int_fields" in field_spec:
            field_spec["integer_fields"] = set(field_spec.pop("int_fields"))
        if "int_list_fields" in field_spec:
            field_spec["integer_list_fields"] = set(field_spec.pop("int_list_fields"))
    return _phase_41_effective_node_attributes(
        source,
        model=model,
        field_spec=field_spec,
    )


# Keep one operation engine.  Phase 46-50 only adapts declarative field-spec
# names and legacy positional calls; the semantics remain Phase 41's.
_phase_46_50_module._effective_node_attributes = _phase_46_50_effective_node_attributes


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
_phase_46_50_module.install_phase_46_50_extensions(
    _parser_module,
    _dependencies_module,
    _extractor_module,
    _source_tree_module,
)
install_phase_48_effective_profile_group_dependencies(
    _dependencies_module,
    _extractor_module,
)

# Phase 49 wraps the extractor's IPv6 inventory classifier.  Bind the public
# package alias only after all FortiGate extensions are installed.
extract_fortigate_config = _extractor_module.extract_fortigate_config


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
