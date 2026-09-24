import io
import json

from openpyxl import load_workbook

from fwmigrate.source_reporting import source_reporters
from fwmigrate.web import create_app
from fwmigrate.vendors.fortigate.source_report import (
    FortiGateSourceReporter,
    FortiGateSourceResult,
)


SOURCE = """config system global
    set hostname fg-report
end
config vdom
    edit root
        config firewall address
            edit web
                set subnet 192.0.2.10 255.255.255.255
            next
        end
    next
end
"""

UNSUPPORTED_SOURCE = """config firewall unsupported-section
    edit source-only
        set unsupported-setting preserve-me
    next
end
"""

SOURCE_INVENTORY = """config vdom
    edit tenant-a
        config firewall unsupported-section
            edit source-only
                set known value
                append member one
                unset comment
                mystery raw
                config tagging
                    edit tag-a
                        set color blue
                    next
                end
            next
        end
    next
end
"""

SECRET_SOURCE = """config vpn ipsec phase1-interface
    edit VPN-HQ
        set psksecret do-not-export-this-secret
    next
end
config user local
    edit alice
        set type password
        set passwd another-do-not-export-secret
    next
end
"""


def test_fortigate_reporter_is_registered_and_keeps_analysis_opaque():
    reporter = source_reporters.get("FORTIGATE")

    assert isinstance(reporter, FortiGateSourceReporter)
    analysis = reporter.analyze_source(SOURCE)
    assert isinstance(analysis, FortiGateSourceResult)
    assert analysis.extracted.config.interfaces == []
    assert analysis.extracted.source_objects
    assert not hasattr(analysis.extracted, "canonical_ir")


def test_fortigate_reporter_builds_preview_and_excel():
    reporter = source_reporters.get("fortigate")
    analysis = reporter.analyze_source(SOURCE)

    preview = reporter.build_preview(analysis)
    assert preview["summary"]["objects"]["addresses"] == 1

    output = io.BytesIO()
    reporter.export_excel(analysis, output)
    workbook = load_workbook(io.BytesIO(output.getvalue()), read_only=True)
    assert "Summary" in workbook.sheetnames
    assert "Addresses" in workbook.sheetnames


def test_shared_web_host_uses_fortigate_reporter_for_preview_and_excel():
    client = create_app({"TESTING": True}).test_client()
    preview = client.post(
        "/api/preview",
        data={
            "source_vendor": "fortigate",
            "file": (io.BytesIO(SOURCE.encode()), "fortigate.conf"),
        },
        content_type="multipart/form-data",
    )

    assert preview.status_code == 200
    preview_payload = preview.get_json()
    assert preview_payload["summary"]["objects"]["addresses"] == 1
    assert preview_payload["preview_id"]

    workbook = client.post(
        "/api/extract/excel",
        data={
            "source_vendor": "fortigate",
            "preview_id": preview_payload["preview_id"],
        },
    )
    assert workbook.status_code == 200
    assert workbook.mimetype == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def test_fortigate_web_upload_handles_vdom_config_and_downloads_workbook():
    client = create_app({"TESTING": True}).test_client()

    response = client.post(
        "/api/preview",
        data={"file": (io.BytesIO(SOURCE.encode()), "vdom.conf")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    assert response.get_json()["summary"]["top_level_sections"] == 2


def test_fortigate_web_rejects_invalid_input():
    client = create_app({"TESTING": True}).test_client()

    response = client.post(
        "/api/preview",
        data={"file": (io.BytesIO(b"\xff\xfe"), "invalid.conf")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert response.get_json()["stage"] == "decode"


def test_fortigate_unsupported_source_is_preserved_without_failing_preview():
    client = create_app({"TESTING": True}).test_client()
    response = client.post(
        "/api/preview",
        data={"file": (io.BytesIO(UNSUPPORTED_SOURCE.encode()), "unsupported.conf")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    assert response.get_json()["summary"]["top_level_sections"] == 1


def test_source_inventory_preserves_indexed_source_evidence():
    analysis = source_reporters.get("fortigate").analyze_source(SOURCE_INVENTORY)

    records = analysis.extracted.source_objects
    assert [
        (record.vdom, record.source_path, record.object_name, record.parent_objects)
        for record in records
    ] == [
        ("tenant-a", "firewall unsupported-section", "source-only", ()),
        (
            "tenant-a",
            "firewall unsupported-section tagging",
            "tag-a",
            ("source-only",),
        ),
    ]

    parent, nested = records
    assert parent.values == {
        "known": "value",
        "member": ["one"],
        "unknown_command:mystery": ["raw"],
    }
    assert parent.explicit_fields == ()
    assert parent.unset_fields == ("comment",)
    assert [command.operation for command in parent.commands] == [
        "set",
        "append",
        "unset",
        "unknown",
    ]
    assert all(command.line_number is not None for command in parent.commands)
    assert parent.start_line_number is not None
    assert parent.end_line_number is not None
    assert nested.values == {"color": "blue"}


def test_unknown_command_secret_evidence_is_redacted():
    source = """config firewall unsupported-section
    edit source-only
        mystery password do-not-export-unknown
        mystery authpasswd do-not-export-auth
    next
end
"""
    record = source_reporters.get("fortigate").analyze_source(source).extracted.source_objects[0]
    assert "do-not-export-unknown" not in str(record)
    assert "do-not-export-auth" not in str(record)
    assert record.commands[0].values[-1] == "[REDACTED]"


def test_fortigate_web_preview_and_excel_redact_secrets():
    client = create_app({"TESTING": True}).test_client()
    preview = client.post(
        "/api/preview",
        data={"file": (io.BytesIO(SECRET_SOURCE.encode()), "secrets.conf")},
        content_type="multipart/form-data",
    )
    assert preview.status_code == 200
    assert "do-not-export-this-secret" not in json.dumps(preview.get_json())
    assert "another-do-not-export-secret" not in json.dumps(preview.get_json())

    workbook = client.post(
        "/api/extract/excel",
        data={"preview_id": preview.get_json()["preview_id"]},
    )
    assert workbook.status_code == 200
    assert b"do-not-export-this-secret" not in workbook.data
    assert b"another-do-not-export-secret" not in workbook.data


def test_vpn_ipv6_selectors_and_credential_evidence_reach_reports_safely():
    source = """config firewall address6
    edit ipv6-peer
        set ip6 2001:db8:2::1/128
    next
end
config vpn ipsec phase1-interface
    edit tunnel
        set ppk-secret do-not-export-ppk
        set authpasswd do-not-export-auth
        set group-authentication-secret do-not-export-group
    next
end
config vpn ipsec phase2-interface
    edit selectors
        set phase1name tunnel
        set src-addr-type subnet6
        set src-subnet6 2001:db8:1::/126
        set dst-addr-type name6
        set dst-name6 ipv6-peer
    next
    edit mixed
        set src-addr-type range6
        set src-start-ip6 2001:db8:3::1
        set src-end-ip6 2001:db8:3::5
        set dst-addr-type subnet
        set dst-subnet 192.0.2.0 255.255.255.0
    next
end
"""
    reporter = source_reporters.get("fortigate")
    analysis = reporter.analyze_source(source)
    phase1 = analysis.extracted.config.ipsec_phase1[0]
    phase2 = analysis.extracted.config.ipsec_phase2[0]
    assert phase1.ppk_secret_configured
    assert phase1.auth_password_configured
    assert phase1.group_authentication_secret_configured
    assert phase2.src_subnet6 == "2001:db8:1::/126"
    assert phase2.dst_name6 == "ipv6-peer"
    assert analysis.extracted.config.addresses[0].ip6 == "2001:db8:2::1/128"
    assert "do-not-export" not in str(phase1.model_dump())
    assert "do-not-export" not in str(analysis.extracted.config.model_dump())
    assert "do-not-export" not in str(analysis.extracted.source_objects)

    preview = reporter.build_preview(analysis)
    assert preview["sections"]["addresses"][0]["value"] == "2001:db8:2::1/128"
    row = preview["sections"]["vpn_phase2"][0]
    assert row["source_range6"] == "2001:db8:1::-2001:db8:1::3"
    assert row["destination_range6"] == "2001:db8:2::1-2001:db8:2::1"
    assert row["source_range"] is None
    mixed = preview["sections"]["vpn_phase2"][1]
    assert mixed["source_range6"] == "2001:db8:3::1-2001:db8:3::5"
    assert mixed["destination_range"] == "192.0.2.0-192.0.2.255"
    assert "do-not-export" not in json.dumps(preview)

    output = io.BytesIO()
    reporter.export_excel(analysis, output)
    workbook = load_workbook(io.BytesIO(output.getvalue()), read_only=True)
    address_headers = [cell.value for cell in workbook["Addresses"][3]]
    address_values = [cell.value for cell in workbook["Addresses"][4]]
    assert address_values[address_headers.index("Value")] == "2001:db8:2::1/128"
    headers = [cell.value for cell in workbook["VPN Phase 2"][3]]
    values = [cell.value for cell in workbook["VPN Phase 2"][4]]
    assert values[headers.index("Source Range IPv6")] == row["source_range6"]
    assert values[headers.index("Destination Range IPv6")] == row["destination_range6"]
    mixed_values = [cell.value for cell in workbook["VPN Phase 2"][5]]
    assert mixed_values[headers.index("Source Range IPv6")] == mixed["source_range6"]
    assert mixed_values[headers.index("Destination Range")] == mixed["destination_range"]
    headers = [cell.value for cell in workbook["VPN Tunnels"][3]]
    values = [cell.value for cell in workbook["VPN Tunnels"][4]]
    assert values[headers.index("PPK Secret Configured")] == "Yes"


def test_unnamed_policy_nat_review_stays_with_policy_id():
    source = """config firewall policy
    edit 1
        set nat enable
        set ippool enable
        set poolname missing
    next
    edit 2
    next
end
"""
    reporter = source_reporters.get("fortigate")
    analysis = reporter.analyze_source(source)
    output = io.BytesIO()
    reporter.export_excel(analysis, output)
    workbook = load_workbook(io.BytesIO(output.getvalue()), read_only=True)
    headers = [cell.value for cell in workbook["Policies"][3]]
    rows = {row[headers.index("Rule #")]: row for row in workbook["Policies"].iter_rows(min_row=4, values_only=True)}
    assert rows[1][headers.index("Analysis Status")] == "REVIEW_REQUIRED"
    assert rows[2][headers.index("Analysis Status")] == "EXTRACTED"


def test_phase1_unset_secret_has_no_presence_flag():
    source = """config vpn ipsec phase1-interface
    edit tunnel
        set ppk-secret do-not-export-ppk
        unset ppk-secret
    next
end
"""
    analysis = source_reporters.get("fortigate").analyze_source(source)
    assert not analysis.extracted.config.ipsec_phase1[0].ppk_secret_configured
    assert "do-not-export-ppk" not in str(analysis.extracted.source_objects)
