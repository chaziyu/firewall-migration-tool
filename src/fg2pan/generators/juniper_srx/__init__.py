from typing import List, Optional
from fg2pan.core.base_generator import BaseTargetGenerator, MigrationArtifact
from fg2pan.core.registry import PluginRegistry
from fg2pan.ir.core import IRConfig
from fg2pan.generators.juniper_srx.cli_generator import JuniperSRXCLIGenerator
from fg2pan.generators.juniper_srx.terraform_generator import JuniperSRXTerraformGenerator

class JuniperSRXTargetGenerator(BaseTargetGenerator):
    """Target generator for Juniper SRX set commands and Terraform HCL suites."""

    @property
    def vendor_id(self) -> str:
        return "juniper_srx"

    @property
    def display_name(self) -> str:
        return "Juniper SRX / JunOS"

    @property
    def supported_formats(self) -> List[str]:
        return ["set", "cli", "terraform"]

    def generate(self, ir: IRConfig, format: Optional[str] = None) -> List[MigrationArtifact]:
        artifacts: List[MigrationArtifact] = []

        cli_gen = JuniperSRXCLIGenerator()
        artifacts.append(MigrationArtifact(
            filename="junos_srx_config.set",
            content=cli_gen.generate(ir),
            format="set"
        ))

        tf_gen = JuniperSRXTerraformGenerator()
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
PluginRegistry.register_generator("juniper_srx", JuniperSRXTargetGenerator())
