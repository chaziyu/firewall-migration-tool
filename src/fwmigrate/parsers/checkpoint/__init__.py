from typing import List, Optional, Dict

from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.extraction.models import ExtractionResult
from fwmigrate.ir.core import IRConfig
from fwmigrate.parsers.checkpoint import extractor as _extractor
from fwmigrate.parsers.checkpoint.fidelity import apply_checkpoint_fidelity
from fwmigrate.parsers.checkpoint.gaia_scope_policy import parse_gaia_configuration as _parse_gaia_configuration_scoped

# Keep the large extractor stable while upgrading Gaia parsing as an explicit
# source-adapter layer. Importing any checkpoint submodule initializes this
# package first, so direct extractor imports receive the same scoped parser.
_extractor.parse_gaia_configuration = _parse_gaia_configuration_scoped
_original_extract_checkpoint_config = _extractor.extract_checkpoint_config


def extract_checkpoint_config(
    content: str,
    zone_mapping: Optional[Dict[str, str]] = None,
) -> ExtractionResult:
    """Run the core extractor and attach Check Point policy/NAT fidelity context."""
    result = _original_extract_checkpoint_config(content, zone_mapping=zone_mapping)
    return apply_checkpoint_fidelity(result)


# Direct imports of fwmigrate.parsers.checkpoint.extractor receive the same
# fidelity wrapper after the checkpoint package is initialized.
_extractor.extract_checkpoint_config = extract_checkpoint_config


class CheckPointSourceParser(BaseSourceParser):
    @property
    def vendor_id(self) -> str:
        return "checkpoint"

    @property
    def display_name(self) -> str:
        return "Check Point R80/R81 (JSON Dump / API)"

    @property
    def supported_extensions(self) -> List[str]:
        return [".json", ".txt", ".cfg"]

    def parse(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> IRConfig:
        return self.extract(content, zone_mapping=zone_mapping).canonical_ir

    def extract(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> ExtractionResult:
        return extract_checkpoint_config(content, zone_mapping=zone_mapping)


# Auto-register
PluginRegistry.register_parser(CheckPointSourceParser)