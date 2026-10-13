from io import BytesIO
from pathlib import Path

from openpyxl import load_workbook

from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.admin import FGAdministrator
from fwmigrate.vendors.fortigate.model.schedule import FGScheduleGroup, FGOneTimeSchedule, FGRecurringSchedule
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.relationships.references import collect_broken_references
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from fwmigrate.source_reporting import ExcelExportProfile


FIXTURES = Path(__file__).parents[2] / "fixtures" / "fortigate"


def test_all_schedule_forms_are_extracted_from_source():
    reporter = FortiGateSourceReporter()
    result = reporter.analyze_source((FIXTURES / "p0_migration_critical.conf").read_text())
    config = result.extracted.config

    assert [item.name for item in config.recurring_schedules] == ["WORK_HOURS"]
    assert config.recurring_schedules[0].days == ["monday", "tuesday", "wednesday", "thursday", "friday"]
    assert [item.name for item in config.one_time_schedules] == ["MAINT_WINDOW"]
    assert config.one_time_schedules[0].start == "01:00 2026/10/01"
    assert config.schedule_groups[0].members == ["WORK_HOURS", "MAINT_WINDOW"]
    preview = reporter.build_preview(result)
    assert preview["summary"]["objects"]["schedules"] == 2
    assert preview["sections"]["schedule_groups"][0]["members"] == ["WORK_HOURS", "MAINT_WINDOW"]


def test_schedule_references_are_vdom_scoped_and_groups_resolve():
    config = FGConfig(
        one_time_schedules=[
            FGOneTimeSchedule(name="maintenance", vdom="vdom-a"),
            FGOneTimeSchedule(name="maintenance", vdom="root"),
        ],
        recurring_schedules=[FGRecurringSchedule(name="business", vdom="vdom-b")],
        schedule_groups=[FGScheduleGroup(name="group", vdom="vdom-a", members=["maintenance"])],
        administrators=[FGAdministrator(name="admin", schedule="maintenance")],
        policies=[
            FGPolicy(policy_id=1, vdom="vdom-a", schedule="group"),
            FGPolicy(policy_id=2, vdom="vdom-a", schedule="business"),
            FGPolicy(policy_id=3, vdom="vdom-a", schedule="missing"),
            FGPolicy(policy_id=4, vdom="vdom-a", schedule="always"),
        ],
    )

    broken = collect_broken_references(config)
    assert [(item.source_name, item.reference) for item in broken] == [("2", "business"), ("3", "missing")]


def test_unknown_schedule_fields_remain_in_raw_extra():
    result = FortiGateSourceReporter().analyze_source(
        """config firewall schedule recurring
    edit custom
        set day monday
        set start 08:00
        set end 18:00
        set future-setting retain-me
    next
end
"""
    )
    schedule = result.extracted.config.recurring_schedules[0]
    assert schedule.raw_extra["future-setting"] == "retain-me"


def test_schedule_sheets_are_removed_but_policy_schedule_is_exported():
    analysis = FortiGateSourceReporter().analyze_source((FIXTURES / "p0_migration_critical.conf").read_text())
    for profile in ExcelExportProfile:
        output = BytesIO()
        FortiGateSourceReporter().export_excel(analysis, output, profile=profile)
        workbook = load_workbook(BytesIO(output.getvalue()), data_only=True)
        assert "Schedules" not in workbook.sheetnames
        assert "Schedule Groups" not in workbook.sheetnames
        if profile == ExcelExportProfile.FULL:
            policies = workbook["Policies"]
            headers = {cell.value: cell.column for cell in policies[3]}
            assert policies.cell(4, headers["Schedule"]).value == "BUSINESS_SCHEDULES"
        if profile == ExcelExportProfile.FAST:
            summary = workbook["Summary"]
            assert all(
                "Schedules" not in (cell.hyperlink.target if cell.hyperlink else "")
                and "Schedule Groups" not in (cell.hyperlink.target if cell.hyperlink else "")
                for row in summary.iter_rows()
                for cell in row
            )
