from copy import deepcopy
from types import SimpleNamespace
from typing import List, Optional, Dict
from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.extraction.models import ExtractionResult
from fwmigrate.ir import IRConfig
from fwmigrate.parsers.fortigate import coverage as _coverage_module
from fwmigrate.parsers.fortigate import extractor as _extractor_module
from fwmigrate.parsers.fortigate import model as _model_module
from fwmigrate.parsers.fortigate import parser as _parser_module
from fwmigrate.parsers.fortigate import transformer as _transformer_module
from fwmigrate.parsers.fortigate import dependencies as _dependencies_module
from fwmigrate.parsers.fortigate import source_tree as _source_tree_module
from fwmigrate.parsers.fortigate import phase_46_50_extensions as _phase_46_50_module
from fwmigrate.parsers.fortigate.session_ttl_extensions import (
    install_final_session_ttl_serialization,
    install_session_ttl_extensions,
)
from fwmigrate.parsers.fortigate.ztna_relationship_extensions import (
    install_ztna_relationship_support,
)
from fwmigrate.parsers.fortigate.certificate_reference_extensions import (
    install_certificate_reference_support,
)
from fwmigrate.parsers.fortigate.authentication_scheme_extensions import (
    install_authentication_scheme_support,
)
from fwmigrate.parsers.fortigate.policy_nat_preservation_extensions import (
    install_policy_nat_preservation_extensions,
)
from fwmigrate.parsers.fortigate.policy_dlp_profile_fix import (
    install_policy_dlp_profile_fix,
)
from fwmigrate.parsers.fortigate.policy_ips_voip_filter_fix import (
    install_policy_ips_voip_filter_fix,
)
from fwmigrate.parsers.fortigate.policy_security_profile_dependency_fix import (
    install_policy_security_profile_dependency_fix,
)
from fwmigrate.parsers.fortigate.policy_ipv6_vip_dependency_fix import (
    install_policy_ipv6_vip_dependency_fix,
)
from fwmigrate.parsers.fortigate.system_fsso import (
    install_system_fsso_polling_support,
)
from fwmigrate.parsers.fortigate.phase_41_security_profiles import install_phase_41_security_profile_support
from fwmigrate.parsers.fortigate.phase_42_antivirus import (
    install_phase_42_antivirus_support,
)
from fwmigrate.parsers.fortigate.phase_43_webfilter import (
    install_phase_43_webfilter_support,
)
from fwmigrate.parsers.fortigate.phase_44_dnsfilter import (
    install_phase_44_dnsfilter_support,
)
from fwmigrate.parsers.fortigate.phase_45_application_control import (
    install_phase_45_application_control_support,
)
from fwmigrate.parsers.fortigate.phase_48_profile_group_dependencies import (
    install_phase_48_effective_profile_group_dependencies,
)
from fwmigrate.parsers.fortigate.phase_46_50_regression_fixes import (
    install_phase_46_50_regression_fixes,
)
from fwmigrate.parsers.fortigate.routing_ngfw_semantics_fix import (
    install_routing_ngfw_semantics_fix,
)
from fwmigrate.parsers.fortigate.fortios_746_address_schedule_fixes import (
    install_fortios_746_address_schedule_fixes,
)
from fwmigrate.parsers.fortigate.fortios_746_ci_regression_fixes import (
    install_fortios_746_ci_regression_fixes,
)
from fwmigrate.parsers.fortigate.ippool_group_support import (
    install_ippool_group_support,
)
from fwmigrate.parsers.fortigate.dependency_resolution_safety_fix import (
    install_dependency_resolution_safety_fix,
)
from fwmigrate.parsers.fortigate.ippool_group_dependency_safety import (
    install_ippool_group_dependency_safety,
)
from fwmigrate.parsers.fortigate.audit_remediation import (
    install_fortios_746_audit_remediation,
)

_static_model_config = _model_module.FGConfig
_parser_extensions = SimpleNamespace(**vars(_parser_module))
_parser_extensions.SECTION_LIST_FIELDS = deepcopy(_parser_module.SECTION_LIST_FIELDS)
_parser_extensions.SECTION_EXPLICIT_FIELDS = deepcopy(_parser_module.SECTION_EXPLICIT_FIELDS)
_parser_extensions.FortiGateParser = type(
    "FortiGateParserExtensionSink",
    (_parser_module.FortiGateParser,),
    {},
)

# Run mixed legacy installers against an isolated parser subclass. Their
# dependency, extraction, transformer, and coverage hooks remain active while
# the public parser and its statically imported models stay unchanged.
install_session_ttl_extensions(_parser_extensions)
install_ztna_relationship_support(_dependencies_module)
install_certificate_reference_support(_dependencies_module)
install_authentication_scheme_support(
    _parser_extensions,
    _dependencies_module,
    _extractor_module,
    _transformer_module,
)
install_policy_nat_preservation_extensions(
    _parser_extensions,
    _transformer_module,
    _dependencies_module,
)
install_policy_dlp_profile_fix(
    _parser_extensions,
    _dependencies_module,
    _transformer_module,
)
install_policy_ips_voip_filter_fix(
    _parser_extensions,
    _dependencies_module,
    _transformer_module,
)
install_policy_security_profile_dependency_fix(
    _parser_extensions,
    _dependencies_module,
    _transformer_module,
)
install_policy_ipv6_vip_dependency_fix(_dependencies_module)
install_system_fsso_polling_support(patch_parser=False)
install_phase_41_security_profile_support(_parser_extensions)
install_phase_42_antivirus_support(_parser_extensions)
install_phase_43_webfilter_support(_parser_extensions)
install_phase_44_dnsfilter_support(_parser_extensions)
install_phase_45_application_control_support(_parser_extensions)
_phase_46_50_module.install_phase_46_50_extensions(
    _parser_extensions,
    _dependencies_module,
    _extractor_module,
    _source_tree_module,
)
install_phase_48_effective_profile_group_dependencies(
    _dependencies_module,
    _extractor_module,
)
install_phase_46_50_regression_fixes(
    _parser_extensions,
    _dependencies_module,
    _extractor_module,
    _coverage_module,
)
install_routing_ngfw_semantics_fix(_transformer_module)

# Phase 1 must compose with the final root model after all later installers.
install_final_session_ttl_serialization(_parser_extensions)

# Install the audited 7.4.6 address/schedule fixes against the final active
# root model so no earlier serializer specialization is lost.
install_fortios_746_address_schedule_fixes(
    _parser_extensions,
    _transformer_module,
    _dependencies_module,
)
install_fortios_746_ci_regression_fixes(
    _transformer_module,
    _coverage_module,
)

# Preserve FortiGate IP-pool groups as typed source/canonical evidence before
# the final dependency safety wrapper validates multi-target pool references.
install_ippool_group_support(
    _parser_extensions,
    _transformer_module,
    _dependencies_module,
    _coverage_module,
    _extractor_module,
)

# Apply dependency safety after every earlier FortiGate dependency wrapper so
# their source-specific relationships remain intact and are checked uniformly.
install_dependency_resolution_safety_fix(
    _dependencies_module,
    _extractor_module,
)

# The generic dependency guard intentionally checks same-type ambiguity only.
# Pool and pool-group name collisions are cross-type, so fail closed here.
install_ippool_group_dependency_safety(
    _dependencies_module,
    _extractor_module,
)

# Apply the 7.4.6 audit wrapper after dependency safety so unsupported raw
# syntax and source-accounting checks observe the final extraction behavior.
install_fortios_746_audit_remediation(_extractor_module)

_model_module.FGConfig = _static_model_config

# Bind the public package alias only after all FortiGate extensions are installed.
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

