import json

import pytest

from fwmigrate.conversion.fortigate_to_checkpoint.application.workflow import approve_design, build_artifact, build_review
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from .test_target_comparison import destination, target_snapshot


def ipv6_source(source, prefix="2001:db8::1/128", kind="ipprefix"):
    return source.replace('        config firewall address', f'''        config firewall address6
            edit "clients"
                set type {kind}
                set ip6 {prefix}
            next
        end
        config firewall address''', 1)


@pytest.mark.parametrize("prefix,field", [("2001:db8::1/128", "ipv6-address"), ("2001:db8::/64", "subnet6")])
def test_ipv6_objects_have_separate_identity_and_exact_uid_reuse(checkpoint_source_text, checkpoint_options, prefix, field):
    analysis = FortiGateSourceReporter().analyze_source(ipv6_source(checkpoint_source_text, prefix))
    review = build_review(analysis, checkpoint_options, "source")
    item = next(row for row in review["plan"].items if row.family == "address6")
    ipv4 = next(row for row in review["plan"].items if row.family == "address" and row.source_name == "clients")
    assert not item.blockers
    assert item.key != ipv4.key and item.target_name != ipv4.target_name
    approval = approve_design(review, review["draft"], [item.key])
    artifact = build_artifact(analysis, checkpoint_options, "source", approval)
    operations = json.loads(artifact["files"]["checkpoint_management_operations.json"]["content"])["operations"]
    assert len(operations) == 1
    assert operations[0]["request_body_template"][field] == prefix.split('/')[0]
    assert operations[0]["request_body_template"]["nat-settings"] == {"auto-rule": False}
    evidence = destination(target_snapshot(review["plan"], checkpoint_options), checkpoint_options)
    compared = build_review(analysis, checkpoint_options, "source", **evidence)
    assert next(row for row in compared["plan"].items if row.key == item.key).target_disposition == "REUSE"
    approval = approve_design(compared, compared["draft"], [item.key])
    artifact = build_artifact(analysis, checkpoint_options, "source", approval, **evidence)
    assert artifact["report"]["management_operation_count"] == 0
    assert any(row["source_path"] == "firewall address6" and row["status"] == "REUSED"
               for row in artifact["report"]["coverage"]["records"])
    snapshot = target_snapshot(review["plan"], checkpoint_options)
    for response in snapshot["responses"]:
        for obj in response["data"]["objects"]:
            if obj["name"] == item.target_name:
                obj.update({"ipv4-address": "192.0.2.1"} if field == "ipv6-address" else
                           {"subnet4": "192.0.2.0", "mask-length4": 24})
    collision = build_review(analysis, checkpoint_options, "source", **destination(snapshot, checkpoint_options))
    assert next(row for row in collision["plan"].items if row.key == item.key).blockers


@pytest.mark.parametrize("prefix,kind", [("192.0.2.1/32", "ipprefix"), ("2001:db8::1/64", "ipprefix"),
    ("2001:db8::/64", "dynamic"), ("invalid", "ipprefix")])
def test_unverified_ipv6_objects_cannot_be_approved(checkpoint_source_text, checkpoint_options, prefix, kind):
    analysis = FortiGateSourceReporter().analyze_source(ipv6_source(checkpoint_source_text, prefix, kind))
    review = build_review(analysis, checkpoint_options, "source")
    item = next(row for row in review["plan"].items if row.family == "address6")
    assert item.blockers
    with pytest.raises(ValueError, match="blocked"):
        approve_design(review, review["draft"], [item.key])
