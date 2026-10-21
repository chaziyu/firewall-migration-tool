from dataclasses import replace
import hashlib
import json
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5
import xml.etree.ElementTree as ET

import pytest

from fwmigrate.conversion.palo_alto_to_cisco_ftd.application import (
    approve_design,
    build_artifact,
    build_review,
    verify_export_artifact,
)
from fwmigrate.conversion.palo_alto_to_cisco_ftd.options import FTDMigrationOptions
from fwmigrate.conversion.palo_alto_to_cisco_ftd.plan_dependencies import dispositions
from fwmigrate.conversion.palo_alto_to_cisco_ftd.planner import PaloAltoToCiscoFTDPlanner
from fwmigrate.conversion.palo_alto_to_cisco_ftd.rendering.fmc import (
    BINDINGS_FILE,
    CURL_FILE,
    INSTRUCTIONS_FILE,
    OPERATION_FILE,
)
from fwmigrate.vendors.cisco_ftd.source_report import CiscoFTDSourceReporter
from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter


FIXTURE = Path(__file__).parents[2] / "fixtures/palo_alto/ftd_policy_explicit.xml"
SCHEMA = Path(__file__).parents[2] / "fixtures/cisco_ftd/panos_target_fmc_7_7_0_fields.json"
TARGET_FIXTURE = Path(__file__).parents[2] / "fixtures/cisco_ftd/pan_migration_target_fmc_770.json"


def analyze(text=None):
    return PaloAltoSourceReporter().analyze_source(text or FIXTURE.read_text(encoding="utf-8"))


def ready(review):
    return [
        row["key"] for row in review["report"]["items"]
        if row["render_disposition"] in {"CREATE", "REUSE"}
    ]


def artifact(analysis=None, options=None, **target):
    analysis = analysis or analyze()
    review = build_review(analysis, options or {}, "source", **target)
    approval = approve_design(review, review["draft"], ready(review))
    built = build_artifact(analysis, options or {}, "source", approval, **target)
    return review, approval, verify_export_artifact(built)


def resolve(value, bindings):
    if isinstance(value, dict):
        if set(value) == {"$response_binding"}:
            return bindings[value["$response_binding"]]
        return {key: resolve(child, bindings) for key, child in value.items()}
    if isinstance(value, list):
        return [resolve(child, bindings) for child in value]
    return value


def test_native_fmc_id_dependencies_ports_order_and_official_request_fields():
    analysis = analyze()
    before = analysis.config.model_dump_json()
    review, _, built = artifact(analysis)
    schema = json.loads(SCHEMA.read_text())["endpoints"]
    spec = json.loads(built["files"][OPERATION_FILE]["content"])
    bindings, seen = {}, set()

    for operation in spec["operations"]:
        assert set(operation["depends_on"]) <= seen
        body = resolve(operation["request_body_template"], bindings)
        # Match path pattern in schema
        norm_path = operation["path"]
        matched_endpoint = None
        for endpoint in schema:
            regex_endpoint = endpoint.replace("{domainUUID}", "[^/]+").replace("{containerUUID}", "[^/]+")
            import re
            if re.match(f"^{regex_endpoint}$", norm_path):
                matched_endpoint = endpoint
                break
        assert matched_endpoint is not None, f"Path {norm_path} not found in official FMC schema"

        allowed = schema[matched_endpoint]
        assert set(body) <= set(allowed)
        for key, value in body.items():
            kind = (
                "boolean" if type(value) is bool
                else "integer" if type(value) is int
                else "string" if isinstance(value, str)
                else "list" if isinstance(value, list)
                else "object"
            )
            assert kind in allowed[key], (key, kind, allowed[key])

        binding = operation.get("response_binding")
        if binding:
            assert binding["json_pointer"] == "/id"
            bindings[binding["binding_id"]] = str(uuid5(NAMESPACE_URL, operation["operation_id"]))
        seen.add(operation["operation_id"])

    planned = [row for row in review["plan"].items if row.family == "policy"]
    assert len(planned) == 3
    # Two active policies allow-unrestricted-zones and allow-zone-traffic and drop-following
    active_planned = [row for row in planned if not row.blockers]
    assert len(active_planned) == 3

    emitted = [op for op in spec["operations"] if op["operation_id"] in {row.key for row in active_planned}]
    assert [op["operation_id"] for op in emitted] == [row.key for row in active_planned]

    assert analysis.config.model_dump_json() == before
    assert "source_vdom" not in json.dumps(built)
    assert CURL_FILE in built["files"]
    assert INSTRUCTIONS_FILE in built["files"]

    manifest = json.loads(built["files"][BINDINGS_FILE]["content"])
    for name, record in manifest["files"].items():
        raw = built["files"][name]["content"].encode("utf-8")
        assert len(raw) == record["byte_count"]
        assert hashlib.sha256(raw).hexdigest() == record["sha256"]
    assert "domain_id" not in manifest["deferred_application_bindings"]


@pytest.mark.parametrize(("field", "value"), [
    ("application/member", "ssl"),
    ("log-end", "yes"),
    ("negate-source", "yes"),
    ("rule-type", "intrazone"),
    ("schedule", "non-existent"),
])
def test_unproved_policy_fails_closed(field, value):
    tree = ET.fromstring(FIXTURE.read_text(encoding="utf-8"))
    rule = tree.find(".//vsys/entry/rulebase/security/rules/entry")
    node = rule.find(field)
    if node is None:
        node = ET.SubElement(rule, field)
    node.text = value
    review = build_review(analyze(ET.tostring(tree, encoding="unicode")), {}, "source")
    state = dispositions(review["plan"])
    first_policy = next(row for row in review["plan"].items if row.family == "policy")
    assert state[first_policy.key] == "BLOCK"
    assert first_policy.key not in {op["operation_id"] for op in json.loads(review["rendered"].operations_text)["operations"]}


def test_default_drop_and_active_nat_blocking():
    original = analyze()
    # Missing default drop rules
    no_defaults = original.config.model_copy(update={"default_security_rules": []})
    plan1 = PaloAltoToCiscoFTDPlanner().plan(no_defaults, original.derived, {})
    state1 = dispositions(plan1)
    assert all(state1[row.key] == "BLOCK" for row in plan1.items if row.family == "policy")

    # Active NAT blocks policy equivalence
    active_nat = original.config.model_copy(
        update={"nat_rules": [row.model_copy(update={"disabled": "no"}) for row in original.config.nat_rules]}
    )
    plan2 = PaloAltoToCiscoFTDPlanner().plan(active_nat, original.derived, {})
    state2 = dispositions(plan2)
    assert all(state2[row.key] == "BLOCK" for row in plan2.items if row.family == "policy")


def test_strict_dependency_approval_expiry_and_context_binding():
    analysis = analyze()
    review = build_review(analysis, {}, "source")
    policy = next(row for row in review["plan"].items if row.family == "policy")
    with pytest.raises(ValueError, match="dependency"):
        approve_design(review, review["draft"], [policy.key])
    approval = approve_design(review, review["draft"], ready(review))
    for expires in [0, float("nan"), float("inf")]:
        with pytest.raises(ValueError):
            build_artifact(analysis, {}, "source", {**approval, "expires_at": expires})
    for source, options in [("changed", {}), ("source", {"policy_name": "another"})]:
        with pytest.raises(ValueError):
            build_artifact(analysis, options, source, approval)
    built = build_artifact(analysis, {}, "source", approval)
    for expires in [0, float("nan"), float("inf")]:
        with pytest.raises(ValueError):
            verify_export_artifact({**built, "expires_at": expires})


def target_destination(families=("objects", "services", "zones", "devices")):
    text = TARGET_FIXTURE.read_text(encoding="utf-8")
    parsed_json = json.loads(text)
    target_analysis = CiscoFTDSourceReporter().analyze_source(text)
    return {
        "target": target_analysis,
        "target_source_text": text,
        "target_metadata": {
            "context": parsed_json["domain"]["name"],
            "version": "7.7.0",
            "mode": "fmc",
            "complete_families": list(families),
        },
    }


def test_existing_fmc_snapshot_object_reuse():
    analysis = analyze()
    options = FTDMigrationOptions(
        target_mode="existing",
        domain_name="Global",
        domain_id="e276abec-e0f2-11e3-8169-6d9ed49b625f",
    )
    initial = build_review(analysis, options, "source")
    target = target_destination()
    review, _, built = artifact(analysis, options, **target)

    # Check reuse disposition
    reused = [row for row in review["report"]["items"] if row["render_disposition"] == "REUSE"]
    assert len(reused) >= 4  # inside-net, app-server, inside, outside
    reused_names = {row["source_name"] for row in reused}
    assert {"inside-net", "app-server", "inside", "outside"} <= reused_names

    # Policies in existing mode stay blocked
    assert all(row["render_disposition"] == "BLOCK" for row in review["report"]["items"] if row["family"] == "policy")

    spec = json.loads(built["files"][OPERATION_FILE]["content"])
    emitted_paths = [op["path"] for op in spec["operations"]]
    assert not any(p.endswith(("/object/networks", "/object/hosts", "/object/securityzones")) for p in emitted_paths)
    assert CURL_FILE not in built["files"]


def test_cli_generates_fmc_review_bundle(tmp_path):
    from click.testing import CliRunner
    from fwmigrate.main import cli
    folder = tmp_path / "review"
    result = CliRunner().invoke(
        cli,
        [
            "migrate",
            "--input", str(FIXTURE),
            "--output", str(folder),
            "--source-vendor", "palo_alto",
            "--target-vendor", "cisco_ftd",
            "--format", "json",
        ],
    )
    assert result.exit_code == 0, result.output
    report = json.loads((folder / "migration_report.json").read_text())
    assert report["pair_id"] == "palo_alto_to_cisco_ftd"
    assert report["fmc_operation_count"] > 0
    assert report["cli_output_is_unapproved_review_material"] is True
    assert (folder / OPERATION_FILE).exists()
    assert (folder / BINDINGS_FILE).exists()
    assert (folder / INSTRUCTIONS_FILE).exists()
