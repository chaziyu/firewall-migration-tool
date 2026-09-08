from io import BytesIO

from openpyxl import load_workbook

from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer
from fwmigrate.report.excel_exporter import IRExcelExporter


CONFIG = """
config firewall internet-service-addition
    edit 100
        set comment "Added service"
        config entry
            edit 1
                set addr-mode ipv4
                set protocol 6
                config port-range
                    edit 1
                        set start-port 80
                        set end-port 443
                    next
                end
            next
        end
    next
end
"""


def test_addition_survives_model_ir_coverage_and_excel():
    fg = parse_fortigate_config(CONFIG)
    addition = fg.internet_service_additions[0]
    assert addition.id == 100
    assert addition.entries[0].port_ranges[0].start_port == 80

    ir = FGToIRTransformer(fg).transform()
    assert ir.internet_service_additions[0].migration_status == "EXTRACT_ONLY"

    result = extract_fortigate_config(CONFIG)
    assert all(section.status.value == "EXTRACT_ONLY" for section in result.source_sections)
    workbook = load_workbook(BytesIO(IRExcelExporter(result.canonical_ir, result).generate()))
    assert workbook["IS Additions"].cell(4, 1).value == 100
    assert workbook["IS Addition Ports"].cell(4, 4).value == 80
