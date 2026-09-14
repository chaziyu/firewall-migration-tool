"""Excel projection for audited FortiGate address/schedule corrections."""

from __future__ import annotations

from copy import copy
import json
from typing import Any

from openpyxl.utils import get_column_letter

from fwmigrate.report.excel_readability import ReadableFortiGateExcelExporter


ADDRESS6_TEMPLATE_SHEET = "IPv6 Address Templates"


class FortiGateAddressScheduleExcelExporter(ReadableFortiGateExcelExporter):
    """Expose corrected FortiGate address and schedule semantics."""

    def _active_sheet_order(self) -> tuple[str, ...]:
        order = list(super()._active_sheet_order())
        if self._source_vendor() not in {"fortigate", "fortinet"}:
            return tuple(
                sheet_name
                for sheet_name in order
                if sheet_name != ADDRESS6_TEMPLATE_SHEET
            )

        if ADDRESS6_TEMPLATE_SHEET not in order:
            insert_at = (
                order.index("Address Groups")
                if "Address Groups" in order
                else len(order)
            )
            order.insert(insert_at, ADDRESS6_TEMPLATE_SHEET)
        return tuple(order)

    @staticmethod
    def _copy_cell_style(source: Any, target: Any) -> None:
        target.font = copy(source.font)
        target.fill = copy(source.fill)
        target.border = copy(source.border)
        target.alignment = copy(source.alignment)
        target.protection = copy(source.protection)
        target.number_format = source.number_format

    def _build_addresses(self, workbook: Any) -> None:
        super()._build_addresses(workbook)

        if "Addresses" in workbook.sheetnames:
            sheet = workbook["Addresses"]
            template_column = sheet.max_column + 1
            resolved_column = sheet.max_column + 2
            template_header = sheet.cell(3, template_column, "IPv6 Template Reference")
            resolved_header = sheet.cell(
                3,
                resolved_column,
                "Template Reference Resolved",
            )
            if template_column > 1:
                self._copy_cell_style(
                    sheet.cell(3, template_column - 1),
                    template_header,
                )
                self._copy_cell_style(template_header, resolved_header)

            for row_number, address in enumerate(self.ir.addresses, start=4):
                template_cell = sheet.cell(
                    row_number,
                    template_column,
                    getattr(address, "source_template", None),
                )
                resolved = getattr(
                    address,
                    "source_template_reference_resolved",
                    None,
                )
                resolved_cell = sheet.cell(
                    row_number,
                    resolved_column,
                    self._optional_bool_literal(resolved),
                )
                if template_column > 1:
                    self._copy_cell_style(
                        sheet.cell(row_number, template_column - 1),
                        template_cell,
                    )
                    self._copy_cell_style(template_cell, resolved_cell)

            sheet.column_dimensions[
                get_column_letter(template_column)
            ].width = 24
            sheet.column_dimensions[
                get_column_letter(resolved_column)
            ].width = 28

        self._build_address6_templates(workbook)

    def _build_address6_templates(self, workbook: Any) -> None:
        templates = list(getattr(self.ir, "address6_templates", []) or [])
        rows = []
        for item in templates:
            segment_payload = [
                {
                    "source_id": segment.source_id,
                    "bits": segment.bits,
                    "exclusive": segment.exclusive,
                    "name": segment.name,
                    "values": [
                        {
                            "source_id": value.source_id,
                            "value": value.value,
                            "source_attributes": value.source_attributes,
                        }
                        for value in segment.values
                    ],
                    "source_attributes": segment.source_attributes,
                }
                for segment in item.subnet_segments
            ]
            rows.append(
                (
                    item.name,
                    item.source_context,
                    item.ip6,
                    item.subnet_segment_count,
                    len(item.subnet_segments),
                    item.source_fabric_object,
                    json.dumps(
                        segment_payload,
                        ensure_ascii=False,
                        sort_keys=True,
                        default=str,
                    ),
                    item.migration_status,
                    self._optional_bool_literal(item.requires_manual_review),
                    item.review_reasons,
                    self._format_settings(item.source_attributes),
                )
            )

        self._table_sheet(
            workbook,
            ADDRESS6_TEMPLATE_SHEET,
            (
                "Name",
                "Source Context",
                "IPv6 Prefix",
                "Declared Segment Count",
                "Parsed Segment Count",
                "Fabric Object",
                "Subnet Segments",
                "Migration Status",
                "Manual Review",
                "Review Reasons",
                "Additional Settings",
            ),
            rows,
            empty_note="No FortiGate IPv6 address templates were extracted.",
            subtitle=(
                "FortiOS 7.4.6 address6-template inventory retained without "
                "expanding template semantics into inferred concrete addresses."
            ),
        )

    def _apply_sheet_view(self, sheet: Any) -> None:
        super()._apply_sheet_view(sheet)
        if sheet.title == "Addresses" and sheet.max_row >= 3:
            headers = {
                str(cell.value or ""): cell.column
                for cell in sheet[3]
            }
            for header in (
                "IPv6 Template Reference",
                "Template Reference Resolved",
            ):
                column = headers.get(header)
                if column:
                    sheet.column_dimensions[
                        get_column_letter(column)
                    ].hidden = False

    def _build_schedule_groups(self, workbook: Any) -> None:
        rows = [
            (
                item.name,
                item.source_context,
                item.members,
                item.unresolved_members,
                item.source_attributes.get("color"),
                item.source_attributes.get("fabric_object"),
                item.migration_status,
                self._optional_bool_literal(item.requires_manual_review),
                self._format_settings({
                    key: value
                    for key, value in item.source_attributes.items()
                    if key not in {"color", "fabric_object"}
                }),
                item.description,
            )
            for item in self.ir.schedule_groups
        ]
        self._table_sheet(
            workbook,
            "Schedule Groups",
            (
                "Name",
                "Source Context",
                "Members",
                "Unresolved Members",
                "Source Color",
                "Source Fabric Object",
                "Migration Status",
                "Manual Review",
                "Additional Settings",
                "Description",
            ),
            rows,
            empty_note="No schedule groups were extracted.",
            subtitle="Ordered FortiGate schedule-group membership and source metadata retained for review.",
        )
