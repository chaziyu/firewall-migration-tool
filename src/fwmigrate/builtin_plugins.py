from fwmigrate.core.plugins import PluginSpec, PluginType
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.generators.checkpoint import CheckPointTargetGenerator
from fwmigrate.generators.cisco_asa import CiscoASATargetGenerator
from fwmigrate.generators.fortigate import FortiGateTargetGenerator
from fwmigrate.generators.juniper_srx import JuniperSRXTargetGenerator
from fwmigrate.generators.palo_alto import PANOSTargetGenerator
from fwmigrate.parsers.checkpoint import CheckPointSourceParser
from fwmigrate.parsers.cisco_asa import CiscoASASourceParser
from fwmigrate.parsers.cisco_ftd import CiscoFTDSourceParser
from fwmigrate.parsers.fortigate import FortiGateSourceParser
from fwmigrate.parsers.juniper_srx import JuniperSRXSourceParser
from fwmigrate.parsers.palo_alto.registered_parser import PANOSSourceParser


BUILTIN_PLUGIN_SPECS = (
    PluginSpec(
        "fortigate", "Fortinet FortiGate", PluginType.SOURCE_PARSER,
        FortiGateSourceParser, aliases=("fortinet", "fg"),
        supported_extensions=(".conf", ".cfg", ".txt"),
    ),
    PluginSpec(
        "palo_alto", "Palo Alto Networks (PAN-OS / Panorama)", PluginType.SOURCE_PARSER,
        PANOSSourceParser, aliases=("panos", "paloalto"),
        supported_extensions=(".xml", ".json", ".txt"),
    ),
    PluginSpec(
        "cisco_asa", "Cisco ASA", PluginType.SOURCE_PARSER,
        CiscoASASourceParser, aliases=("asa",),
        supported_extensions=(".cfg", ".txt", ".conf"),
    ),
    PluginSpec(
        "cisco_ftd", "Cisco Firepower Threat Defense", PluginType.SOURCE_PARSER,
        CiscoFTDSourceParser, aliases=("ftd",),
        supported_extensions=(".cfg", ".txt", ".conf", ".json"),
    ),
    PluginSpec(
        "checkpoint", "Check Point R80/R81 (JSON Dump / API)", PluginType.SOURCE_PARSER,
        CheckPointSourceParser, aliases=("check_point",),
        supported_extensions=(".json", ".txt", ".cfg"),
    ),
    PluginSpec(
        "juniper_srx", "Juniper SRX (Junos root-level display set)", PluginType.SOURCE_PARSER,
        JuniperSRXSourceParser, aliases=("srx", "junos"),
        supported_extensions=(".set", ".txt", ".conf"),
    ),
    PluginSpec(
        "palo_alto", "Palo Alto Networks (PAN-OS / Panorama)", PluginType.TARGET_GENERATOR,
        PANOSTargetGenerator, aliases=("panos", "paloalto"),
        supported_formats=("xml", "terraform"), supports_terraform=True,
    ),
    PluginSpec(
        "fortigate", "Fortinet FortiGate (FortiOS CLI / Terraform)", PluginType.TARGET_GENERATOR,
        FortiGateTargetGenerator, aliases=("fortinet", "fg"),
        supported_formats=("cli", "terraform"), supports_terraform=True,
    ),
    PluginSpec(
        "cisco_asa", "Cisco ASA / Firepower", PluginType.TARGET_GENERATOR,
        CiscoASATargetGenerator, aliases=("asa",),
        supported_formats=("cli", "terraform"), supports_terraform=True,
    ),
    PluginSpec(
        "checkpoint", "Check Point Quantum / CloudGuard", PluginType.TARGET_GENERATOR,
        CheckPointTargetGenerator, aliases=("check_point",),
        supported_formats=("cli", "terraform"), supports_terraform=True,
    ),
    PluginSpec(
        "juniper_srx", "Juniper SRX / JunOS", PluginType.TARGET_GENERATOR,
        JuniperSRXTargetGenerator, aliases=("srx", "junos"),
        supported_formats=("set", "cli", "terraform"), supports_terraform=True,
    ),
)


def register_builtin_plugins() -> None:
    for spec in BUILTIN_PLUGIN_SPECS:
        PluginRegistry.register(spec)
