from typing import List, Optional
from fwmigrate.core.base_generator import BaseTargetGenerator, MigrationArtifact
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.core import IRConfig
from fwmigrate.generators.palo_alto.xml_generator import PANOSXMLGenerator
from fwmigrate.generators.palo_alto.terraform_generator import PANOSTerraformGenerator

class PANOSTargetGenerator(BaseTargetGenerator):
    @property
    def vendor_id(self) -> str:
        return "palo_alto"

    @property
    def display_name(self) -> str:
        return "Palo Alto Networks (PAN-OS / Panorama)"

    @property
    def supported_formats(self) -> List[str]:
        return ["xml", "terraform"]

    def __init__(self, vsys: str = "vsys1", device_group: str = "shared"):
        self.vsys = vsys
        self.device_group = device_group

    def generate(self, ir: IRConfig, format: Optional[str] = None) -> List[MigrationArtifact]:
        target_format = (format or "all").lower()
        artifacts = []

        if target_format in ["xml", "all"]:
            xml_gen = PANOSXMLGenerator()
            artifacts.extend(xml_gen.generate(ir))

        if target_format in ["terraform", "all"]:
            tf_gen = PANOSTerraformGenerator(vsys=self.vsys, device_group=self.device_group)
            artifacts.extend(tf_gen.generate(ir))

        return artifacts

# Register automatically
PluginRegistry.register_generator(PANOSTargetGenerator)
