from typing import Dict, List, Optional
from fwmigrate.core.base_generator import BaseTargetGenerator, MigrationArtifact
from fwmigrate.ir import IRConfig
from fwmigrate.generators.fortigate import cli_generator as _cli_generator_module
from fwmigrate.generators.fortigate.cli_generator import FortiGateCLIGenerator
from fwmigrate.generators.fortigate.terraform_generator import FortiGateTerraformGenerator
from fwmigrate.generators.fortigate.audit_remediation import (
    install_fortigate_cli_audit_remediation,
)
from fwmigrate.generators.fortigate.context_mapping import generate_context_mapped_cli

install_fortigate_cli_audit_remediation(_cli_generator_module)


class FortiGateTargetGenerator(BaseTargetGenerator):
    def __init__(self, context_mapping: Optional[Dict[str, str]] = None):
        self.context_mapping = dict(context_mapping or {})

    @property
    def vendor_id(self) -> str:
        return "fortigate"

    @property
    def display_name(self) -> str:
        return "Fortinet FortiGate (FortiOS CLI / Terraform)"

    @property
    def supported_formats(self) -> List[str]:
        return ["cli", "terraform"]

    def generate(self, ir: IRConfig, format: Optional[str] = None) -> List[MigrationArtifact]:
        target_format = (format or "all").lower()
        artifacts = []

        if self.context_mapping:
            if target_format != "cli":
                raise ValueError(
                    "FortiGate context mapping is currently supported only for CLI generation"
                )
            return generate_context_mapped_cli(
                ir,
                self.context_mapping,
                FortiGateCLIGenerator,
            )

        if target_format in ["cli", "all"]:
            cli_gen = FortiGateCLIGenerator()
            artifacts.extend(cli_gen.generate(ir))

        if target_format in ["terraform", "all"]:
            tf_gen = FortiGateTerraformGenerator()
            artifacts.extend(tf_gen.generate(ir))

        return artifacts


__all__ = ["FortiGateTargetGenerator"]
