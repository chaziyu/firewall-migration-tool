from typing import List, Optional
from fg2pan.core.base_generator import BaseTargetGenerator, MigrationArtifact
from fg2pan.core.registry import PluginRegistry
from fg2pan.ir.core import IRConfig
from fg2pan.generators.fortigate.cli_generator import FortiGateCLIGenerator
from fg2pan.generators.fortigate.terraform_generator import FortiGateTerraformGenerator

class FortiGateTargetGenerator(BaseTargetGenerator):
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

        if target_format in ["cli", "all"]:
            cli_gen = FortiGateCLIGenerator()
            artifacts.extend(cli_gen.generate(ir))

        if target_format in ["terraform", "all"]:
            tf_gen = FortiGateTerraformGenerator()
            artifacts.extend(tf_gen.generate(ir))

        return artifacts

# Auto-register
PluginRegistry.register_generator(FortiGateTargetGenerator)

__all__ = ["FortiGateTargetGenerator"]
