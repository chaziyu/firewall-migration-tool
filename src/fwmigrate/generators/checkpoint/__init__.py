from typing import List, Optional
from fwmigrate.core.base_generator import BaseTargetGenerator, MigrationArtifact
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.core import IRConfig
from fwmigrate.generators.checkpoint.cli_generator import CheckPointCLIGenerator
from fwmigrate.generators.checkpoint.terraform_generator import CheckPointTerraformGenerator

class CheckPointTargetGenerator(BaseTargetGenerator):
    """Target generator for Check Point mgmt_cli automation scripts and Terraform HCL suites."""

    @property
    def vendor_id(self) -> str:
        return "checkpoint"

    @property
    def display_name(self) -> str:
        return "Check Point Quantum / CloudGuard"

    @property
    def supported_formats(self) -> List[str]:
        return ["cli", "terraform"]

    def generate(self, ir: IRConfig, format: Optional[str] = None) -> List[MigrationArtifact]:
        artifacts: List[MigrationArtifact] = []

        cli_gen = CheckPointCLIGenerator()
        artifacts.append(MigrationArtifact(
            filename="checkpoint_mgmt_cli.sh",
            content=cli_gen.generate(ir),
            format="cli"
        ))

        tf_gen = CheckPointTerraformGenerator()
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
PluginRegistry.register_generator("checkpoint", CheckPointTargetGenerator())
