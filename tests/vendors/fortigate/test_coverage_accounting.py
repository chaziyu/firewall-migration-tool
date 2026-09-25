from __future__ import annotations

import io
import unittest
from types import SimpleNamespace

from openpyxl import load_workbook
from fwmigrate.vendors.fortigate.config import ExtractionConfig
from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.vendors.fortigate.export import export_excel
from fwmigrate.vendors.fortigate.export.excel_schema import SHEET_HEADERS
from fwmigrate.vendors.fortigate.extraction.extractor import extract_fortigate_config
from fwmigrate.vendors.fortigate.extraction.coverage import (
    TypedSourceObject,
    build_typed_source_identity_index,
    find_typed_source_object,
)
from fwmigrate.vendors.fortigate.extraction.source_inventory import SourceObjectRecord
from fwmigrate.vendors.fortigate.parser import parse_fortigate_config
from fwmigrate.source_reporting import ExcelExportProfile
from fwmigrate.vendors.fortigate.validation.validator import validate_config


class CoverageAccountingTest(unittest.TestCase):
    def _report(self, source: str, profile: ExcelExportProfile = ExcelExportProfile.FULL):
        extracted = extract_fortigate_config(parse_fortigate_config(source), config=ExtractionConfig())
        derived = build_derived_views(extracted.config)
        output = io.BytesIO()
        export_excel(
            extracted=extracted,
            derived=derived,
            validation=validate_config(extracted.config, derived=derived),
            output=output,
            profile=profile,
        )
        output.seek(0)
        return extracted, load_workbook(output, data_only=False)

    @staticmethod
    def _rows(sheet):
        headers = [sheet.cell(3, column).value for column in range(1, sheet.max_column + 1)]
        return headers, list(sheet.iter_rows(min_row=4, values_only=True))

    @staticmethod
    def _record(parent_objects):
        return SourceObjectRecord(
            vdom="root",
            source_path="nested",
            object_name="child",
            parent_objects=parent_objects,
            values={},
            explicit_fields=(),
            unset_fields=(),
            commands=(),
            start_line_number=None,
            end_line_number=None,
        )

    def test_typed_identity_index_preserves_nested_parents_and_first_match(self):
        first_model = SimpleNamespace(name="first")
        second_model = SimpleNamespace(name="second")
        inventory = {
            "nested": (
                TypedSourceObject(("root", "nested", "child", ("parent-a",)), first_model),
                TypedSourceObject(("root", "nested", "child", ("parent-b",)), second_model),
                TypedSourceObject(("root", "nested", "child", ("parent-a",)), second_model),
            )
        }
        identity_index = build_typed_source_identity_index(inventory)

        self.assertIs(first_model, find_typed_source_object(identity_index, self._record(("parent-a",))).model)
        self.assertIs(second_model, find_typed_source_object(identity_index, self._record(("parent-b",))).model)


    def test_workbook_keeps_registration_model_coverage_and_raw_extra_separate(self):
        extracted, workbook = self._report('''
config system interface
    edit "port1"
        set ip 192.0.2.1 255.255.255.0
        set mtu 1500
        set future-option preserve-me
    next
    edit "port2"
    next
end
config system dhcp server
    edit 1
        config exclude-range
            edit 4
                set start-ip 192.0.2.20
                set end-ip 192.0.2.30
            next
        end
    next
end
config firewall unsupported-section
    edit "source-only"
        set future-setting preserve-me
    next
end
''')
        coverage_headers, coverage_rows = self._rows(workbook["Extraction Coverage"])
        coverage = {row[coverage_headers.index("Source Section")]: row for row in coverage_rows}
        interface = coverage["system interface"]
        self.assertEqual("REGISTERED", interface[coverage_headers.index("Primitive Registration")])
        self.assertEqual("TYPED", interface[coverage_headers.index("Model Coverage")])
        self.assertEqual(len(extracted.config.interfaces), interface[coverage_headers.index("Typed Objects")])
        self.assertEqual(1, interface[coverage_headers.index("Raw Extra Objects")])
        self.assertGreaterEqual(interface[coverage_headers.index("Raw Extra Entries")], 2)
        self.assertEqual(0, interface[coverage_headers.index("Source-only Records")])

        inventory_headers, inventory_rows = self._rows(workbook["FortiGate Source Inventory"])
        port1 = next(row for row in inventory_rows if row[inventory_headers.index("Object")] == "port1")
        self.assertEqual("TYPED_WITH_RAW_EXTRA", port1[inventory_headers.index("Extraction Status")])
        self.assertGreaterEqual(port1[inventory_headers.index("Raw Extra Entries")], 2)
        excluded = next(row for row in inventory_rows if row[inventory_headers.index("Source Path")] == "system dhcp server exclude-range")
        self.assertEqual("TYPED", excluded[inventory_headers.index("Extraction Status")])
        generic = next(row for row in inventory_rows if row[inventory_headers.index("Object")] == "source-only")
        self.assertEqual("GENERIC", generic[inventory_headers.index("Primitive Registration")])
        self.assertEqual("SOURCE_ONLY", generic[inventory_headers.index("Extraction Status")])
        self.assertEqual(list(SHEET_HEADERS["FortiGate Source Inventory"]), inventory_headers)
        self.assertEqual(f"A3:L{len(inventory_rows) + 3}", workbook["FortiGate Source Inventory"].auto_filter.ref)

        unsupported_headers, unsupported_rows = self._rows(workbook["Unsupported"])
        source_only = next(row for row in unsupported_rows if row[unsupported_headers.index("Section")] == "firewall unsupported-section")
        self.assertEqual("SOURCE_ONLY", source_only[unsupported_headers.index("Model Coverage")])
        self.assertNotIn("system interface", {row[unsupported_headers.index("Section")] for row in unsupported_rows})
        source_only_coverage = coverage["firewall unsupported-section"]
        self.assertEqual(1, source_only_coverage[coverage_headers.index("Source-only Records")])
        self.assertEqual(0, source_only_coverage[coverage_headers.index("Typed Objects")])
        coverage_values = [cell.value for row in workbook["Extraction Coverage"].iter_rows() for cell in row]
        self.assertNotIn("preserve-me", coverage_values)

    def test_fully_typed_input_counts_model_instances_not_source_records(self):
        extracted, workbook = self._report('''
config system interface
    edit "port1"
        set ip 192.0.2.1 255.255.255.0
    next
    edit "port2"
        set ip 192.0.2.2 255.255.255.0
    next
end
''')
        headers, rows = self._rows(workbook["Extraction Coverage"])
        row = next(item for item in rows if item[headers.index("Source Section")] == "system interface")
        self.assertEqual("REGISTERED", row[headers.index("Primitive Registration")])
        self.assertEqual("TYPED", row[headers.index("Model Coverage")])
        self.assertEqual(len(extracted.config.interfaces), row[headers.index("Typed Objects")])
        self.assertEqual(0, row[headers.index("Raw Extra Objects")])
        self.assertEqual(0, row[headers.index("Raw Extra Entries")])
        self.assertEqual(0, row[headers.index("Source-only Records")])

    def test_fast_omits_traceability_appendices_and_redirects_unsupported_evidence(self):
        source = '''
config system interface
    edit "port1"
        set ip 192.0.2.1 255.255.255.0
        set future-option preserve-me
    next
    edit "port2"
    next
end
config firewall unsupported-section
    edit "source-only"
        set future-setting preserve-me
    next
end
'''
        _, full = self._report(source)
        _, fast = self._report(source, ExcelExportProfile.FAST)

        assert "FortiGate Source Inventory" in full.sheetnames
        assert "Extraction Coverage" in full.sheetnames
        assert "FortiGate Source Inventory" not in fast.sheetnames
        assert "Extraction Coverage" not in fast.sheetnames

        headers, rows = self._rows(fast["Unsupported"])
        source_only = next(row for row in rows if row[headers.index("Section")] == "firewall unsupported-section")
        assert source_only[headers.index("Raw Capture Location")] == "Full Excel export / sanitized source evidence"



if __name__ == "__main__":
    unittest.main()
