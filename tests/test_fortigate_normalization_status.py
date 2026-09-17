from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.model import FGConfig
from fwmigrate.parsers.fortigate.transformer import (
    FGToIRTransformer,
    SemanticIssue,
    SemanticIssueKind,
)


def test_semantic_status_distinguishes_review_from_incomplete_data():
    assert (
        FGToIRTransformer._semantic_issue_kind(
            "FortiGate security profile semantics require target-specific translation"
        )
        == SemanticIssueKind.VENDOR_SPECIFIC
    )
    assert (
        FGToIRTransformer._semantic_issue_kind(
            "unresolved service reference(s): missing-service"
        )
        == SemanticIssueKind.UNRESOLVED
    )
    target_review = [SemanticIssue(SemanticIssueKind.TARGET_REVIEW, "target review")]
    vendor_specific = [SemanticIssue(SemanticIssueKind.VENDOR_SPECIFIC, "vendor")]
    unresolved = [SemanticIssue(SemanticIssueKind.UNRESOLVED, "missing")]
    parse_failure = [SemanticIssue(SemanticIssueKind.PARSE_FAILURE, "invalid")]
    assert FGToIRTransformer._semantic_status(target_review) == "NORMALIZED"
    assert FGToIRTransformer._requires_manual_review(target_review) is True
    assert FGToIRTransformer._semantic_status(vendor_specific) == "VENDOR_EXTENSION"
    assert FGToIRTransformer._semantic_status(unresolved) == "PARTIALLY_NORMALIZED"
    assert FGToIRTransformer._semantic_status(parse_failure) == "PARTIALLY_NORMALIZED"


def test_central_nat_default_is_version_aware():
    known = FGToIRTransformer(FGConfig(source_version="7.2.13"))
    unknown = FGToIRTransformer(FGConfig())

    assert known._effective_central_nat(None) == "disable"
    assert known._effective_central_nat("enable") == "enable"
    assert unknown._effective_central_nat(None) is None


def test_route_destination_group_requires_one_concrete_prefix():
    ir = extract_fortigate_config(
        """\
config firewall address
    edit "single"
        set type ipmask
        set subnet 192.0.2.0 255.255.255.0
    next
    edit "other"
        set type ipmask
        set subnet 198.51.100.0 255.255.255.0
    next
end
config firewall addrgrp
    edit "single-group"
        set member "single"
    next
    edit "multi-group"
        set member "single" "other"
    next
end
config router static
    edit 1
        set dstaddr "single-group"
    next
    edit 2
        set dstaddr "multi-group"
    next
end
"""
    ).canonical_ir

    single, multi = ir.routes
    assert single.destination == "192.0.2.0/24"
    assert single.source_destination_reference == "single-group"
    assert single.migration_status == "NORMALIZED"
    assert multi.destination is None
    assert multi.migration_status == "PARTIALLY_NORMALIZED"
    assert multi.review_reasons


def test_fortigate_source_settings_are_typed_without_becoming_partial():
    ir = extract_fortigate_config(
        """\
config system interface
    edit "port2"
        set ip 192.0.2.1 255.255.255.0
        set netflow-sampler both
        set sflow-sampler enable
        set sample-rate 4096
        set polling-interval 60
        set lldp-transmission enable
        set src-check disable
    next
end
config firewall service custom
    edit "HTTPS"
        set id 42
        set tcp-portrange 443
    next
end
config vpn ipsec phase1-interface
    edit "vpn1"
        set interface "port2"
        set remote-gw 198.51.100.1
        set ike-version 2
        set psksecret ENC redacted
    next
end
"""
    ).canonical_ir

    interface = ir.interfaces[0]
    assert interface.migration_status == "VENDOR_EXTENSION"
    assert interface.requires_manual_review is True
    assert interface.vendor_extension.source_lldp_transmission == "enable"
    assert interface.vendor_extension.source_netflow_sampler == "both"
    assert ir.services[0].migration_status == "NORMALIZED"
    tunnel = ir.vpn_tunnels[0]
    assert tunnel.has_psk is True
    assert tunnel.psk is None
    assert tunnel.migration_status == "VENDOR_EXTENSION"
    assert tunnel.requires_manual_review is True
