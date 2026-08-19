from typing import List, Optional
from fg2pan.core.base_generator import BaseTargetGenerator, MigrationArtifact
from fg2pan.core.registry import PluginRegistry
from fg2pan.ir.core import IRConfig
from fg2pan.generators.cisco_asa.cli_generator import CiscoASACLIGenerator
from fg2pan.generators.cisco_asa.terraform_generator import CiscoASATerraformGenerator

class CiscoASATargetGenerator(BaseTargetGenerator):
    """Target generator for Cisco ASA / Firepower CLI scripts and Terraform HCL suites."""

    @property
    def vendor_id(self) -> str:
        return "cisco_asa"

    @property
    def display_name(self) -> str:
        return "Cisco ASA / Firepower"

    @property
    def supported_formats(self) -> List[str]:
        return ["cli", "terraform"]

    def generate(self, ir: IRConfig, format: Optional[str] = None) -> List[MigrationArtifact]:
        artifacts: List[MigrationArtifact] = []

        cli_gen = CiscoASACLIGenerator()
        artifacts.append(MigrationArtifact(
            filename="cisco_asa_config.cfg",
            content=cli_gen.generate(ir),
            format="cli"
        ))

        tf_gen = CiscoASATerraformGenerator()
        artifacts.append(MigrationArtifact(
            filename="provider.tf",
            content=tf_gen.generate_provider_tf(),
            format="terraform"
        ))
        artifacts.append(MigrationArtifact(
            filename="variables.tf",
            content=tf_gen.generate_variables_tf(),
            format="terraform"
        ))
        artifacts.append(MigrationArtifact(
            filename="main.tf",
            content=tf_gen.generate_main_tf(ir),
            format="terraform"
        ))

        return artifacts

# Auto-register with PluginRegistry
PluginRegistry.register_generator("cisco_asa", CiscoASATargetGenerator())
