"""Excel projection for audited FortiGate address/schedule corrections."""

from __future__ import annotations

from typing import Any

from fwmigrate.report.excel_readability import ReadableFortiGateExcelExporter


class FortiGateAddressScheduleExcelExporter(ReadableFortiGateExcelExporter):
    """Expose schedule-group metadata preserved by the FortiGate transformer."""

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
