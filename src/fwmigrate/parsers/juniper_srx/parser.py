"""Compatibility parser that preserves the legacy Juniper IR projection."""

from fwmigrate.vendors.juniper_srx.parser import JuniperSRXParser as _JuniperSRXParser
from fwmigrate.vendors.juniper_srx.parser import *


class JuniperSRXParser(_JuniperSRXParser):
    """Legacy import path with IR conversion kept outside source extraction."""

    def extract(self):
        from fwmigrate.parsers.juniper_srx.transformer import JuniperToIRTransformer
        from fwmigrate.vendors.juniper_srx.coverage import (
            build_extraction_result,
            build_juniper_dependencies,
        )

        self.extract_source()
        canonical_ir = JuniperToIRTransformer(
            self.config,
            zone_mapping=self.zone_mapping,
            source_format=self.source_format,
        ).transform()
        return build_extraction_result(
            self.commands,
            canonical_ir,
            dependencies=build_juniper_dependencies(self.config),
        )

    def parse_raw(self):
        self.extract_source()
        return self.config

    def transform_to_ir(self):
        return self.extract().canonical_ir
