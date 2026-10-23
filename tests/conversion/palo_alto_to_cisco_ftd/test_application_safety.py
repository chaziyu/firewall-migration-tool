"""Exercise actual exported Python requests without contacting an FMC."""

from copy import deepcopy
import io
import json
import re
import shutil
import ssl
import subprocess
import sys
from urllib.error import HTTPError, URLError
import urllib.request
from uuid import NAMESPACE_URL, uuid5
import xml.etree.ElementTree as ET

import pytest

from fwmigrate.conversion.palo_alto_to_cisco_ftd.application import (
    approve_design, build_artifact, build_review, verify_export_artifact,
)
from fwmigrate.conversion.palo_alto_to_cisco_ftd.options import FTDMigrationOptions
from fwmigrate.conversion.palo_alto_to_cisco_ftd.plan_dependencies import dispositions
from fwmigrate.conversion.palo_alto_to_cisco_ftd.rendering.commands import render_fmc_curl_commands
from .test_pipeline import analyze, artifact, ready, resolve, target_destination, TARGET_OPTIONS, FIXTURE


def execute_script(script, monkeypatch, *, failure=None):
    """Execute the exact embedded program, replacing only HTTPS transport and token input."""
    calls, handlers = [], []

    class Response(io.BytesIO):
        status = 201

    class Opener:
        def open(self, request, timeout):
            calls.append(request)
            assert timeout == 30
            if len(calls) == 1 and failure:
                if isinstance(failure, Exception):
                    raise failure
                return Response(failure)
            return Response(json.dumps({"id": str(uuid5(NAMESPACE_URL, str(len(calls))))}).encode())

    def build_opener(*values):
        handlers.extend(values)
        return Opener()

    monkeypatch.setattr(urllib.request, "build_opener", build_opener)
    monkeypatch.setattr("getpass.getpass", lambda prompt: "synthetic-test-token")
    monkeypatch.setattr(sys, "argv", ["-"])
    code = script.split("<<'FWMIGRATE_FMC_PY'\n", 1)[1].rsplit("\nFWMIGRATE_FMC_PY", 1)[0]
    namespace = {"__name__": "__main__"}
    try:
        exec(compile(code, "<exported-fmc-script>", "exec"), namespace)
    except SystemExit as error:
        return calls, handlers, error
    return calls, handlers, None


def test_exported_script_resolves_ids_and_treats_special_text_as_data(monkeypatch, tmp_path, capsys):
    # Apostrophes and shell/Python-looking text must remain ordinary JSON data.
    marker = tmp_path / "must-not-exist"
    name = f"engineer's $(touch {marker}) `ignored` \\ \"quoted\""
    _, _, built = artifact(options={**TARGET_OPTIONS, "policy_name": name})
    script = built["files"]["cisco_fmc_curl.sh"]["content"]
    shell = tmp_path / "application.sh"
    shell.write_text(script, encoding="utf-8")
    if shutil.which("bash"):
        subprocess.run(["bash", "-n", str(shell)], check=True, capture_output=True)
    calls, handlers, error = execute_script(script, monkeypatch)
    assert error is None
    assert not marker.exists()
    spec = json.loads(built["files"]["cisco_fmc_operations.json"]["content"])
    assert len(calls) == len(spec["operations"]) > 3
    bindings = {}
    for index, (request, operation) in enumerate(zip(calls, spec["operations"]), 1):
        path = re.sub(r"\{\$response_binding:\s*([^{}]+?)\s*\}",
                      lambda match: bindings[match[1]], operation["path"])
        assert request.full_url == "https://fmc.lab.invalid" + path
        assert request.method == "POST"
        assert json.loads(request.data) == resolve(operation["request_body_template"], bindings)
        assert b"$fmc_id_" not in request.data
        if operation.get("response_binding"):
            bindings[operation["response_binding"]["binding_id"]] = str(uuid5(NAMESPACE_URL, str(index)))
    assert any(json.loads(request.data).get("name") == name for request in calls)
    https = next(handler for handler in handlers if isinstance(handler, urllib.request.HTTPSHandler))
    assert https._context.check_hostname
    assert https._context.verify_mode == ssl.CERT_REQUIRED
    redirect = next(handler for handler in handlers if isinstance(handler, urllib.request.HTTPRedirectHandler))
    assert redirect.redirect_request(None, None, 302, "redirect", {}, "https://elsewhere.invalid") is None
    assert "synthetic-test-token" not in capsys.readouterr().out


@pytest.mark.parametrize("failure", [
    HTTPError("https://fmc.lab.invalid", 403, "Denied", {}, None),
    HTTPError("https://fmc.lab.invalid", 302, "Redirect", {}, None),
    URLError("connection failed"),
    b"not-json", b"{}", b'{"id":"not-a-uuid"}',
    b'{"id":"../../different-domain"}',
])
def test_exported_script_stops_without_retry_on_failed_request_or_binding(monkeypatch, failure):
    _, _, built = artifact()
    calls, _, error = execute_script(built["files"]["cisco_fmc_curl.sh"]["content"], monkeypatch, failure=failure)
    assert error is not None
    assert len(calls) == 1
    assert "partial changes" in str(error)


@pytest.mark.parametrize("malformation", ["unknown-body-binding", "unknown-path-binding", "wrong-domain"])
def test_script_preflights_all_operations_before_sending_any(monkeypatch, malformation):
    _, _, built = artifact()
    operations = deepcopy(json.loads(built["files"]["cisco_fmc_operations.json"]["content"])["operations"])
    if malformation == "unknown-body-binding":
        operations[-1]["request_body_template"]["sourceNetworks"] = {"$response_binding": "missing.id"}
    elif malformation == "unknown-path-binding":
        operations[-1]["path"] += "/{$response_binding: missing.id}"
    else:
        operations[-1]["path"] = operations[-1]["path"].replace(TARGET_OPTIONS["domain_id"], str(uuid5(NAMESPACE_URL, "other-domain")))
    script = render_fmc_curl_commands(operations, manager_target=TARGET_OPTIONS["manager_target"],
                                      domain_id=TARGET_OPTIONS["domain_id"])
    calls, _, error = execute_script(script, monkeypatch)
    assert error is not None
    assert calls == []


@pytest.mark.parametrize("service", ["application-default", "any"])
def test_application_default_cannot_be_exported_as_any_service(service):
    tree = ET.fromstring(FIXTURE.read_text(encoding="utf-8"))
    tree.find(".//security/rules/entry/service/member").text = service
    analysis = analyze(ET.tostring(tree, encoding="unicode"))
    review = build_review(analysis, TARGET_OPTIONS, "source")
    policy = next(row for row in review["plan"].items if row.family == "policy")
    if service == "application-default":
        assert "PAN_APPLICATION_DEFAULT_ENFORCEMENT_UNPROVEN" in policy.blockers
        state = dispositions(review["plan"])
        assert all(state[row.key] == "BLOCK" for row in review["plan"].items if row.family == "policy")
        with pytest.raises(ValueError, match="blocked"):
            approve_design(review, review["draft"], [policy.key])
    else:
        assert not policy.blockers
        approval = approve_design(review, review["draft"], ready(review))
        built = verify_export_artifact(build_artifact(analysis, TARGET_OPTIONS, "source", approval))
        operations = json.loads(built["files"]["cisco_fmc_operations.json"]["content"])["operations"]
        assert any(row["operation_id"] == policy.key for row in operations)


@pytest.mark.parametrize("field", ["manager_target", "domain_id"])
def test_missing_target_identity_is_not_filled_and_blocks_approval(field):
    options = {**TARGET_OPTIONS, field: None}
    review = build_review(analyze(), options, "source")
    assert getattr(review["options"], field) is None
    assert ready(review) == []
    assert json.loads(review["rendered"].operations_text)["operations"] == []
    with pytest.raises(ValueError):
        approve_design(review, review["draft"], [review["plan"].items[0].key])


@pytest.mark.parametrize(("field", "value"), [
    ("domain_id", "not-a-uuid"), ("domain_id", "../Global"),
    ("manager_target", "https://fmc.lab.invalid"), ("manager_target", "user@fmc.lab.invalid"),
    ("manager_target", "fmc.lab.invalid/path"), ("manager_target", "fmc.lab.invalid?redirect=elsewhere"),
    ("manager_target", "fmc.lab.invalid:65536"), ("manager_target", "bad host"),
])
def test_malformed_target_identity_is_rejected(field, value):
    with pytest.raises(ValueError):
        FTDMigrationOptions(**{**TARGET_OPTIONS, field: value})


@pytest.mark.parametrize("host", ["fmc.lab.invalid", "192.0.2.1", "[2001:db8::1]", "fmc.lab.invalid:8443"])
def test_explicit_hostname_and_ip_targets_are_accepted(host):
    assert FTDMigrationOptions(**{**TARGET_OPTIONS, "manager_target": host}).manager_target == host


def test_native_target_domain_must_match_reviewed_uuid():
    target = target_destination()
    with pytest.raises(ValueError, match="domain UUID"):
        build_review(analyze(), {**TARGET_OPTIONS, "target_mode": "existing",
            "domain_id": str(uuid5(NAMESPACE_URL, "different-domain"))}, "source", **target)


def test_target_edit_invalidates_previous_approval():
    _, approval, _ = artifact()
    with pytest.raises(ValueError):
        build_artifact(analyze(), {**TARGET_OPTIONS, "manager_target": "other-fmc.lab.invalid"}, "source", approval)


def test_legacy_approval_and_artifact_require_fresh_review():
    _, approval, built = artifact()
    with pytest.raises(ValueError):
        build_artifact(analyze(), TARGET_OPTIONS, "source", {**approval, "envelope_type": "palo_alto_to_cisco_ftd_approval_v1"})
    with pytest.raises(ValueError):
        verify_export_artifact({**built, "envelope_type": "palo_alto_to_cisco_ftd_artifact_v1"})
