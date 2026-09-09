from io import BytesIO

import pytest

from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer
from fwmigrate.report.excel_exporter import IRExcelExporter


FORTIGATE_CONFIG = """
config system global
    set hostname "FG-TEST"
end

config system session-ttl
    config port
        edit 1
            set protocol 6
            set timeout 3600
            set start-port 3389
            set end-port 3389
        next
        edit 2
            set protocol 17
            set timeout 3600
            set start-port 3389
            set end-port 3389
        next
    end
end
"""

SESSION_TTL_GAPS_CONFIG = """
config system session-ttl
    set default 900
    config port
        edit 1
            set protocol 6
            set start-port 443
            set end-port 443
            set timeout 300
        next
        edit 2
            set protocol 17
            set start-port 53
            set end-port 53
            set timeout never
            set refresh-direction outgoing
        next
    end
end
"""

SESSION_TTL_NEVER_CONFIG = """
config system session-ttl
    set default never
end
"""


def test_session_ttl_parser():
    fg = parse_fortigate_config(FORTIGATE_CONFIG)

    assert len(fg.session_ttl_overrides) == 2

    tcp = fg.session_ttl_overrides[0]

    assert tcp.id == 1
    assert tcp.protocol == 6
    assert tcp.timeout == 3600
    assert tcp.start_port == 3389
    assert tcp.end_port == 3389


def test_session_ttl_transformer():
    fg = parse_fortigate_config(FORTIGATE_CONFIG)

    ir = FGToIRTransformer(fg).transform()

    assert len(ir.session_ttl_overrides) == 2

    tcp = ir.session_ttl_overrides[0]
    udp = ir.session_ttl_overrides[1]

    assert tcp.protocol_name == "TCP"
    assert tcp.protocol_number == 6
    assert tcp.start_port == 3389
    assert tcp.end_port == 3389
    assert tcp.timeout_seconds == 3600
    assert tcp.migration_status == "EXTRACT_ONLY"
    assert tcp.requires_manual_review is True

    assert udp.protocol_name == "UDP"
    assert udp.protocol_number == 17


def test_session_ttl_excel():
    openpyxl = pytest.importorskip("openpyxl")

    fg = parse_fortigate_config(FORTIGATE_CONFIG)
    ir = FGToIRTransformer(fg).transform()
    workbook_bytes = IRExcelExporter(ir).generate()
    workbook = openpyxl.load_workbook(BytesIO(workbook_bytes))

    assert "Session TTL Overrides" in workbook.sheetnames

    sheet = workbook["Session TTL Overrides"]
    headers = [cell.value for cell in sheet[3]]

    assert "Protocol" in headers
    assert "Timeout" in headers
    assert "Refresh Direction" in headers
    assert "Manual Review" in headers

    assert sheet["B4"].value == "TCP"
    assert sheet["D4"].value == 3389
    assert sheet["E4"].value == 3389
    assert sheet["F4"].value == 3600
    assert sheet["H4"].value == "EXTRACT_ONLY"
    assert sheet["I4"].value == "Yes"

    assert sheet["B5"].value == "UDP"


def test_session_ttl_numeric_never_and_refresh_direction():
    openpyxl = pytest.importorskip("openpyxl")
    fg = parse_fortigate_config(SESSION_TTL_GAPS_CONFIG)
    ir = FGToIRTransformer(fg).transform()

    assert fg.session_ttl_settings.default_timeout == 900
    assert fg.session_ttl_settings.default_never is False
    assert ir.session_ttl_settings.default_timeout_seconds == 900
    assert ir.session_ttl_settings.default_never is False

    first, second = ir.session_ttl_overrides
    assert first.timeout_seconds == 300
    assert first.timeout_never is False
    assert second.timeout_seconds is None
    assert second.timeout_never is True
    assert second.refresh_direction == "outgoing"
    assert "refresh_direction" not in second.source_attributes

    workbook = openpyxl.load_workbook(
        BytesIO(IRExcelExporter(ir).generate())
    )
    settings = workbook["Session TTL Settings"]
    settings_headers = {cell.value: cell.column for cell in settings[3]}
    assert settings.cell(4, settings_headers["Default TTL"]).value == 900

    overrides = workbook["Session TTL Overrides"]
    headers = {cell.value: cell.column for cell in overrides[3]}
    assert overrides.cell(5, headers["Timeout"]).value == "never"
    assert overrides.cell(5, headers["Refresh Direction"]).value == "outgoing"


def test_session_ttl_never_global_default_is_not_unparsed():
    openpyxl = pytest.importorskip("openpyxl")
    fg = parse_fortigate_config(SESSION_TTL_NEVER_CONFIG)
    ir = FGToIRTransformer(fg).transform()

    assert fg.session_ttl_settings.default_timeout is None
    assert fg.session_ttl_settings.default_never is True
    assert "unparsed_default" not in fg.session_ttl_settings.extra_settings
    assert ir.session_ttl_settings.default_timeout_seconds is None
    assert ir.session_ttl_settings.default_never is True

    workbook = openpyxl.load_workbook(BytesIO(IRExcelExporter(ir).generate()))
    sheet = workbook["Session TTL Settings"]
    headers = {cell.value: cell.column for cell in sheet[3]}
    assert sheet.cell(4, headers["Default TTL"]).value == "never"


def test_system_global_session_timers_are_typed_and_distinct():
    fg = parse_fortigate_config(
        """config system global
    set tcp-halfclose-timer 120
    set tcp-halfopen-timer 30
    set tcp-rst-timer 5
    set tcp-timewait-timer 1
    set udp-idle-timer 180
end
"""
    )

    assert fg.system_global is not None
    assert fg.system_global.tcp_halfclose_timer == 120
    assert fg.system_global.tcp_halfopen_timer == 30
    assert fg.system_global.tcp_rst_timer == 5
    assert fg.system_global.tcp_timewait_timer == 1
    assert fg.system_global.udp_idle_timer == 180
    assert "tcp_halfclose_timer" not in fg.system_global.extra_settings
    assert fg.model_dump()["system_global"]["udp_idle_timer"] == 180


def test_system_global_session_timer_unset_clears_typed_and_malformed_state():
    fg = parse_fortigate_config(
        """config system global
    set tcp-halfopen-timer invalid
    unset tcp-halfopen-timer
end
"""
    )

    assert fg.system_global is not None
    assert fg.system_global.tcp_halfopen_timer is None
    assert "unparsed_tcp_halfopen_timer" not in fg.system_global.extra_settings


def test_malformed_system_global_session_timer_is_preserved():
    fg = parse_fortigate_config(
        """config system global
    set tcp-rst-timer invalid
end
"""
    )

    assert fg.system_global is not None
    assert fg.system_global.tcp_rst_timer is None
    assert fg.system_global.extra_settings["unparsed_tcp_rst_timer"] == "invalid"


def test_service_custom_session_timers_remain_per_service():
    fg = parse_fortigate_config(
        """config firewall service custom
    edit "svc-a"
        set protocol TCP/UDP/SCTP
        set session-ttl 120
        set tcp-halfclose-timer 30
        set udp-idle-timer 60
    next
    edit "svc-b"
        set protocol TCP/UDP/SCTP
        set session-ttl 300
        set tcp-timewait-timer 15
    next
end
"""
    )

    services = {service.name: service for service in fg.services}
    assert services["svc-a"].session_ttl == 120
    assert services["svc-a"].tcp_halfclose_timer == 30
    assert services["svc-a"].udp_idle_timer == 60
    assert services["svc-a"].tcp_timewait_timer is None

    assert services["svc-b"].session_ttl == 300
    assert services["svc-b"].tcp_timewait_timer == 15
    assert services["svc-b"].tcp_halfclose_timer is None
    assert services["svc-b"].udp_idle_timer is None

    dumped = fg.model_dump()
    dumped_services = {service["name"]: service for service in dumped["services"]}
    assert dumped_services["svc-a"]["session_ttl"] == 120
    assert dumped_services["svc-b"]["tcp_timewait_timer"] == 15


def test_service_custom_timer_unset_and_malformed_values_are_safe():
    fg = parse_fortigate_config(
        """config firewall service custom
    edit "unset-service"
        set session-ttl 120
        set tcp-rst-timer 10
        unset session-ttl
        unset tcp-rst-timer
    next
    edit "malformed-service"
        set session-ttl invalid
        set udp-idle-timer not-a-number
    next
end
"""
    )

    services = {service.name: service for service in fg.services}
    assert services["unset-service"].session_ttl is None
    assert services["unset-service"].tcp_rst_timer is None

    malformed = services["malformed-service"]
    assert malformed.session_ttl is None
    assert malformed.udp_idle_timer is None
    assert malformed.extra_settings["unparsed_session_ttl"] == "invalid"
    assert malformed.extra_settings["unparsed_udp_idle_timer"] == "not-a-number"


def test_session_ttl_default_malformed_and_unset_do_not_leave_stale_state():
    fg = parse_fortigate_config(
        """config system session-ttl
    set default 3600
    set default invalid
end
"""
    )
    assert fg.session_ttl_settings is not None
    assert fg.session_ttl_settings.default_timeout is None
    assert fg.session_ttl_settings.default_never is False
    assert fg.session_ttl_settings.extra_settings["unparsed_default"] == "invalid"

    fg = parse_fortigate_config(
        """config system session-ttl
    set default never
    unset default
end
"""
    )
    assert fg.session_ttl_settings is not None
    assert fg.session_ttl_settings.default_timeout is None
    assert fg.session_ttl_settings.default_never is False
    assert "unparsed_default" not in fg.session_ttl_settings.extra_settings


def test_session_ttl_port_override_normalizes_numeric_fields_and_never():
    fg = parse_fortigate_config(
        """config system session-ttl
    config port
        edit 1
            set protocol 6
            set start-port 443
            set end-port 443
            set refresh-direction outgoing
            set timeout never
        next
        edit 2
            set protocol invalid
            set start-port bad
            set end-port 65535
            set timeout broken
        next
    end
end
"""
    )

    overrides = {override.id: override for override in fg.session_ttl_overrides}
    first = overrides[1]
    assert first.protocol == 6
    assert first.start_port == 443
    assert first.end_port == 443
    assert first.timeout is None
    assert first.timeout_never is True
    assert first.refresh_direction == "outgoing"

    malformed = overrides[2]
    assert malformed.protocol is None
    assert malformed.start_port is None
    assert malformed.end_port == 65535
    assert malformed.timeout is None
    assert malformed.timeout_never is False
    assert malformed.extra_settings["unparsed_protocol"] == "invalid"
    assert malformed.extra_settings["unparsed_start_port"] == "bad"
    assert malformed.extra_settings["unparsed_timeout"] == "broken"
