from io import BytesIO
from pathlib import Path

from fwmigrate.parsers.cisco_ftd.source_report import (
    CiscoFTDSourceReporter,
    extract_cisco_ftd_source,
)


ROOT = Path(__file__).parents[2]


def _fixture(name: str) -> str:
    return (ROOT / "fixtures" / "cisco_ftd" / name).read_text(encoding="utf-8")


def test_fmc_source_plane_keeps_acp_and_nat_native():
    result = extract_cisco_ftd_source(_fixture("fmc_nat_pipeline_conformance.json"))

    assert result.config.source_plane == "fmc-rest-bundle"
    assert result.config.acp_rules == [] or all(item.source_plane == "fmc-rest-bundle" for item in result.config.acp_rules)
    assert result.config.nat_policies
    assert all(item.source_plane == "fmc-rest-bundle" for item in result.config.nat_policies)
    assert not result.derived.unresolved_references


def test_fdm_source_plane_is_not_fmc():
    result = extract_cisco_ftd_source(_fixture("fdm_nat_pipeline_conformance.json"))

    assert result.config.source_plane == "fdm-rest-bundle"
    assert result.config.nat_policies
    assert result.config.source_metadata["source"] == "fdm-rest-api"


def test_cli_evidence_does_not_manufacture_managed_policy_or_nat():
    result = extract_cisco_ftd_source(
        "interface outside\n ip address 203.0.113.1 255.255.255.0\n"
    )

    assert result.config.source_plane == "ftd-text-evidence"
    assert result.config.acp_rules == []
    assert result.config.nat_policies == []


def test_unresolved_native_reference_is_reported():
    result = extract_cisco_ftd_source(
        '{"source":"fmc-rest-api","objects":{"hosts":[]},'
        '"access_policies":[{"name":"p","rules":[{"name":"r",'
        '"source":[{"name":"missing"}]}]}]}'
    )

    assert result.derived.unresolved_references
    assert result.validation.issues


def test_ftd_reporter_exports_source_plane_workbook():
    result = CiscoFTDSourceReporter().analyze_source(
        _fixture("fmc_nat_pipeline_conformance.json")
    )
    output = BytesIO()
    CiscoFTDSourceReporter().export_excel(result, output)

    assert output.getvalue()[:2] == b"PK"
