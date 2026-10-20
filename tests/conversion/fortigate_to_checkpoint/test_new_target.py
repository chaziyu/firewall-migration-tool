import json
import shlex
import shutil
import subprocess
from pathlib import Path
import os

import pytest

from fwmigrate.conversion.fortigate_to_checkpoint.application import (
    approve_design, build_artifact, build_review, verify_export_artifact,
)
from fwmigrate.conversion.fortigate_to_checkpoint.options import CPMigrationOptions
from fwmigrate.conversion.fortigate_to_checkpoint.plan_dependencies import dispositions
from fwmigrate.conversion.fortigate_to_checkpoint.rendering.management import (
    COMMANDS_FILE, CPManagementRenderer,
)
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from .conftest import SOURCE


def test_new_target_needs_only_source_and_keeps_proposals_separate(checkpoint_analysis):
    options = CPMigrationOptions(target_mode="new")
    review = build_review(checkpoint_analysis, options, "source")
    assert options.source_vdom is None
    assert review["options"].source_vdom == "root"
    assert review["options"].policy_package
    assert review["options"].management_domain is None
    assert review["options"].install_on == ()
    assert review["requirements"] == []
    assert all(value == "CREATE" for value in dispositions(review["plan"]).values())
    assert review["report"]["destination_verified"] is False
    operations = json.loads(review["rendered"].management_text)["operations"]
    package = next(row for row in operations if row["path"] == "/web_api/add-package")
    cleanup = next(row for row in operations if row["source"]["kind"] == "cleanup")
    first, last = [row for row in operations if row["source"]["kind"] == "policy"]
    assert package["request_body_template"]["access"] is True
    assert package["response_binding"]["json_pointer"] == "/access-layers/0/uid"
    assert cleanup["request_body_template"]["action"] == "Drop"
    assert cleanup["request_body_template"]["position"] == "top"
    assert first["request_body_template"]["position"] == {"above": {"$response_binding": cleanup["response_binding"]["binding_id"]}}
    assert last["request_body_template"]["position"] == {"below": {"$response_binding": first["response_binding"]["binding_id"]}}
    assert first["request_body_template"]["install-on"] == ["Policy Targets"]
    assert package["operation_id"] in first["depends_on"]
    assert cleanup["operation_id"] in first["depends_on"]


def test_new_target_approval_includes_setup_and_exact_commands(checkpoint_analysis):
    options = {"target_mode": "new"}
    review = build_review(checkpoint_analysis, options, "source")
    last = [row for row in review["plan"].items if row.family == "policy"][-1]
    approval = approve_design(review, review["draft"], [last.key])
    artifact = build_artifact(checkpoint_analysis, options, "source", approval)
    assert verify_export_artifact(artifact) is artifact
    assert artifact["files"][COMMANDS_FILE]["sha256"] == approval["file_sha256"][COMMANDS_FILE]
    included = {row["family"] for row in artifact["report"]["items"] if row["key"] in approval["selected_items"]}
    assert {"package", "cleanup", "policy", "address", "service"} <= included
    commands = artifact["files"][COMMANDS_FILE]["content"]
    assert 'mgmt_cli -s "$session_file" --version 1.8.1 --format json add package' in commands
    assert "position.above" in commands and "position.below" in commands
    assert "$response_binding" not in commands
    assert "set static-route" not in commands
    assert artifact["files"]["gaia_config.clish"]["content"] == ""
    assert " --root" not in commands and " -r true" not in commands
    with pytest.raises(ValueError, match="draft changed"):
        approve_design(build_review(checkpoint_analysis, {**options, "policy_package": "Other"}, "source"), review["draft"], [last.key])


def test_new_target_keeps_ambiguous_scope_and_unsupported_policies_blocked(checkpoint_analysis):
    ambiguous = FortiGateSourceReporter().analyze_source(SOURCE + '''
config vdom
    edit branch
        config firewall address
            edit branch-host
                set type ipmask
                set subnet 192.0.2.1 255.255.255.255
            next
        end
    next
end
''')
    from fwmigrate.conversion.fortigate_to_checkpoint.planner import FortiGateToCheckPointPlanner
    plan = FortiGateToCheckPointPlanner().plan(ambiguous.extracted.config, ambiguous.derived, CPMigrationOptions(target_mode="new"))
    assert plan.source_vdom is None
    assert plan.findings[0].code == "SOURCE_VDOM_REQUIRED"
    bad = FortiGateSourceReporter().analyze_source(SOURCE.replace('set srcintf "any"', 'set srcintf "port1"', 1))
    review = build_review(bad, {"target_mode": "new"}, "source")
    rules = [row for row in review["report"]["items"] if row["family"] == "policy"]
    assert all(row["render_disposition"] == "BLOCK" for row in rules)
    assert "POLICY_INTERFACE_CONSTRAINT_UNREPRESENTABLE" in rules[0]["blockers"]
    assert "EARLIER_SOURCE_POLICY_REMAINS_MANUAL" in rules[1]["blockers"]
    wrong_version = build_review(checkpoint_analysis, {"target_mode": "new", "management_api_version": "2.0"}, "source")
    assert all(row["render_disposition"] == "BLOCK" for row in wrong_version["report"]["items"] if row["family"] in {"package", "cleanup", "policy"})
    with pytest.raises(ValueError, match="cannot use existing-target"):
        build_review(checkpoint_analysis, {"target_mode": "new"}, "source", target=checkpoint_analysis)


def test_commands_quote_target_names_and_have_valid_shell_syntax(checkpoint_analysis, tmp_path):
    name = "new package'; $(touch should-not-exist) #"
    review = build_review(checkpoint_analysis, {"target_mode": "new", "policy_package": name}, "source")
    commands = CPManagementRenderer().render(review["plan"]).commands_text
    package_line = next(line for line in commands.splitlines() if " add package " in line)
    # The untrusted name stays one literal shell argument, including command substitution text.
    assert shlex.quote(name) in package_line
    script = tmp_path / COMMANDS_FILE
    script.write_text(commands, encoding="utf-8", newline="\n")
    bash = shutil.which("bash") if not Path("C:/Program Files/Git/bin/bash.exe").exists() else "C:/Program Files/Git/bin/bash.exe"
    if bash:
        result = subprocess.run([bash, "-n", script.as_posix()], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        capture = tmp_path / "arguments.bin"
        driver = '''
mgmt_cli() {
    printf '%s\\0' "$@" >> "$CP_CAPTURE"
    printf '\\n' >> "$CP_CAPTURE"
    if [[ "$CP_FAIL" == yes && " $* " == *" add package "* ]]; then return 1; fi
    printf '{"uid":"returned-uid"}'
}
jq() { cat >/dev/null; printf 'returned-uid\\n'; }
source "$1" session.json
'''
        env = {**os.environ, "CP_CAPTURE": capture.as_posix(), "CP_FAIL": "no"}
        result = subprocess.run([bash, "-c", driver, "--", script.as_posix()], cwd=tmp_path,
                                env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        calls = [row.split(b"\0")[:-1] for row in capture.read_bytes().splitlines()]
        package_call = next(row for row in calls if b"package" in row)
        assert name.encode() in package_call
        assert not (tmp_path / "should-not-exist").exists()
        rule_calls = [row for row in calls if b"access-rule" in row]
        assert all(row[row.index(b"layer") + 1] == b"returned-uid" for row in rule_calls)
        capture.unlink()
        result = subprocess.run([bash, "-c", driver, "--", script.as_posix()], cwd=tmp_path,
                                env={**env, "CP_FAIL": "yes"}, capture_output=True, text=True)
        assert result.returncode != 0
        assert b"access-rule" not in capture.read_bytes()
