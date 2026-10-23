from copy import deepcopy
import hashlib
import io
import json
import zipfile

import pytest

from fwmigrate.collection.snapshot import sanitize_source
from fwmigrate.conversion.fortigate_to_palo_alto import PANMigrationOptions, run_migration_pipeline
from fwmigrate.main import cli
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter


def source_text(comment="VIP owner", extra=""):
    setting = "" if comment is None else f'set comment "{comment}"'
    return f"""config firewall vip
edit published
set type static-nat
set extip 198.51.100.10
set mappedip 10.0.0.10
set extintf any
{setting}
{extra}
next
end
"""


def migrate(text, options=None, **kwargs):
    analysis = FortiGateSourceReporter().analyze_source(sanitize_source("fortigate", text))
    before = deepcopy(analysis.extracted)
    result = run_migration_pipeline(analysis.extracted.config, analysis.derived,
        options=options or PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}),
        source_inventory=analysis.extracted.source_objects, **kwargs)
    assert analysis.extracted == before
    return result


@pytest.mark.parametrize("comment", [None, "", "VIP owner"])
def test_vip_comments_reach_address_description_without_filling_absent_values(comment):
    result = migrate(source_text(comment))
    item, = result.plan.addresses
    assert item.description == comment
    descriptions = [command for command in result.rendered.commands if " description " in command]
    assert descriptions == ([] if comment is None else [f'set vsys vsys1 address published description "{comment}"'])


def test_unset_vip_comment_stays_absent():
    result = migrate(source_text(extra="unset comment"))
    assert result.plan.addresses[0].description is None
    assert not any(" description " in command for command in result.rendered.commands)


def test_same_named_vips_keep_their_own_vdom_metadata():
    text = "config vdom\n" + "".join(
        f"edit {vdom}\n{source_text(comment)}next\n" for vdom, comment in (("root", "Root owner"), ("blue", "Blue owner"))
    ) + "end\n"
    result = migrate(text, PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}, "blue": {"vsys": "vsys2"}}))
    assert {row.source_vdom: row.description for row in result.plan.addresses} == {"root": "Root owner", "blue": "Blue owner"}
    assert 'set vsys vsys1 address published description "Root owner"' in result.rendered.commands
    assert 'set vsys vsys2 address published description "Blue owner"' in result.rendered.commands


@pytest.mark.parametrize("source_comment,target_comment,expected", [
    ("VIP owner", "VIP owner", "EXACT_MATCH"),
    ("VIP owner", "Destination owner", "NAME_CONFLICT"),
    ("VIP owner", None, "AMBIGUOUS"),
    ("", "", "EXACT_MATCH"),
    ("", None, "AMBIGUOUS"),
    (None, "Destination owner", "EXACT_MATCH"),
])
def test_vip_address_reuse_requires_matching_explicit_description(source_comment, target_comment, expected):
    description = "" if target_comment is None else f"<description>{target_comment}</description>"
    target = PaloAltoSourceReporter().analyze_source(f"""<config><devices><entry name="fw"><vsys><entry name="vsys1">
<address><entry name="published"><ip-netmask>198.51.100.10/32</ip-netmask>{description}</entry></address>
</entry></vsys></entry></devices></config>""")
    before = deepcopy(target.config)
    result = migrate(source_text(source_comment), target=target, target_device="fw")
    row, = [row for row in result.target_object_reuse if row["family"] == "address"]
    assert row["status"] == expected
    assert target.config == before
    assert not result.rendered.commands


@pytest.mark.parametrize("comment", ["VIP owner", "unsafe\x01value", "unsafe\tvalue", "x" * 1024],
                         ids=["valid", "control", "tab", "over-limit"])
def test_invalid_vip_metadata_is_retained_and_blocks_consuming_security_rule(comment):
    from dataclasses import replace
    from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus, PlannedZone
    from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer

    policy = """config firewall policy
edit 1
set srcintf outside
set dstintf inside
set srcaddr all
set dstaddr published
set service ALL
set action accept
set schedule always
next
end
"""
    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}, interfaces={"root": {
        "outside": {"target_zone": "outside"}, "inside": {"target_zone": "inside"}}})
    result = migrate(source_text(comment, extra="set extintf outside") + policy, options)
    item, = result.plan.addresses
    assert item.description == comment
    invalid = comment != "VIP owner"
    assert any("target description" in warning for warning in item.warnings) == invalid
    assert any(issue.code == "invalid_target_description" for issue in result.validation.issues) == invalid
    zones = tuple(PlannedZone(source_vdom="root", source_object_type="zone", source_name=name,
        target_name=name, target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED) for name in ("outside", "inside"))
    rendered = PANSetRenderer().render(replace(result.plan, zones=zones))
    assert any("address published " in command for command in rendered.commands) != invalid
    assert any("rulebase security" in command for command in rendered.commands) != invalid


def test_vip_metadata_uses_sanitized_source_evidence():
    text = source_text(extra='set password "SYNTHETIC-CREDENTIAL"')
    sanitized = sanitize_source("fortigate", text)
    assert "SYNTHETIC-CREDENTIAL" not in sanitized
    assert "[REDACTED]" in sanitized
    result = migrate(sanitized)
    assert "SYNTHETIC-CREDENTIAL" not in repr(result.plan) + repr(result.rendered.report)
    assert result.plan.addresses[0].description == "VIP owner"


def test_unreferenced_vip_addresses_require_only_their_explicit_vsys_placement():
    from fwmigrate.conversion.fortigate_to_palo_alto.requirements import build_mapping_requirements

    text = "config vdom\n" + "".join(
        f"edit {vdom}\n{source_text()}next\n" for vdom in ("root", "blue")
    ) + "end\n"
    analysis = FortiGateSourceReporter().analyze_source(text)
    requirements = build_mapping_requirements(analysis.extracted.config, analysis.derived)
    assert requirements["vdoms"] == [
        {"source_vdom": "blue", "requires": ["vsys"]},
        {"source_vdom": "root", "requires": ["vsys"]},
    ]
    assert not requirements["interfaces"]


def test_cli_preserves_vip_description_and_report_digest(tmp_path):
    from click.testing import CliRunner

    source = tmp_path / "source.conf"
    source.write_text(source_text())
    mapping = tmp_path / "mapping.yaml"
    mapping.write_text("vdoms:\n  root:\n    vsys: vsys1\n")
    output = tmp_path / "output"
    response = CliRunner().invoke(cli, ["migrate", "-i", str(source), "-o", str(output),
        "--zone-map", str(mapping), "--automation-mode", "REVIEW_ONLY"])
    assert response.exit_code == 0, response.output
    commands = (output / "palo_alto_config.set").read_bytes()
    assert b'address published description "VIP owner"' in commands
    report = json.loads((output / "migration_report.json").read_text())
    assert report["command_sha256"] == hashlib.sha256(commands).hexdigest()


def test_signed_web_preview_download_and_bundle_keep_vip_description():
    from fwmigrate.web import create_app
    from tests.approved_design import approved_migrate

    client = create_app({"TESTING": True}).test_client()
    preview = client.post("/api/preview", data={"file": (io.BytesIO(source_text().encode()), "source.conf")})
    assert preview.status_code == 200
    response = approved_migrate(client, json={"source": preview.get_json()["source_evidence"],
        "workflow_mode": "OFFLINE_EXPORT", "mapping": {"vdoms": {"root": {"vsys": "vsys1"}}}})
    assert response.status_code == 200
    artifact = response.get_json()["artifact"]
    assert 'set vsys vsys1 address published description "VIP owner"' in artifact["commands"]
    body = {"artifact": artifact, "source": preview.get_json()["source_evidence"]}
    command_preview = client.post("/api/migration/command-preview", json=body)
    download = client.post("/api/migration/download", json=body)
    bundle = client.post("/api/migration/bundle", json=body)
    assert command_preview.status_code == download.status_code == bundle.status_code == 200
    assert command_preview.get_json()["commands"] == artifact["commands"]
    assert hashlib.sha256(download.data).hexdigest() == artifact["command_sha256"]
    with zipfile.ZipFile(io.BytesIO(bundle.data)) as archive:
        assert archive.read("palo_alto_config.set") == download.data


def test_invalid_vip_description_is_manual_before_target_placement():
    from fwmigrate.web import create_app

    client = create_app({"TESTING": True}).test_client()
    preview = client.post("/api/preview", data={"file": (io.BytesIO(source_text("unsafe\x01value").encode()), "source.conf")})
    assert preview.status_code == 200
    prepared = client.post("/api/migration/design/prepare", json={"source": preview.get_json()["source_evidence"],
        "workflow_mode": "OFFLINE_EXPORT"})
    assert prepared.status_code == 200
    draft = prepared.get_json()["draft"]
    row, = [row for row in draft["configuration"] if row["source_kind"] == "vip" and row["family"] == "address"]
    assert row["status"] == "UNSUPPORTED"
    assert any("unsafe CLI controls" in reason for reason in row["blocking_reasons"])
