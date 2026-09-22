from typing import List, Optional, Dict
from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.extraction import ExtractionResult, finalize_extraction
from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser
from fwmigrate.vendors.juniper_srx.source_report import JuniperSRXSourceReporter, extract_juniper_source

class JuniperSRXSourceParser(BaseSourceParser):
    @property
    def vendor_id(self) -> str:
        return "juniper_srx"

    @property
    def display_name(self) -> str:
        return "Juniper SRX (Junos root-level display set)"

    @property
    def supported_extensions(self) -> List[str]:
        return [".set", ".txt", ".conf"]

    def extract(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> ExtractionResult:
        """One authoritative extraction pipeline returning complete ExtractionResult."""
        parser = JuniperSRXParser(content, zone_mapping=zone_mapping)
        return finalize_extraction(parser.extract())


__all__ = ["JuniperSRXSourceParser", "JuniperSRXSourceReporter", "extract_juniper_source"]
