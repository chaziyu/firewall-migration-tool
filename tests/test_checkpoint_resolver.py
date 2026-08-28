import pytest
from fwmigrate.parsers.checkpoint.resolver import (
    CheckPointObjectResolver,
    SemanticKind,
    is_any_object,
    is_original_object,
    KNOWN_ANY_UID,
)
from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.ir.enums import PolicyAction


def test_is_any_object_detection():
    assert is_any_object("Any")
    assert is_any_object("any")
    assert is_any_object(KNOWN_ANY_UID)
    assert is_any_object({"type": "CpmiAnyObject", "name": "Any"})
    assert is_any_object({"uid": KNOWN_ANY_UID, "name": "Any"})
    assert not is_any_object({"type": "host", "name": "AnyHost"})
    assert not is_any_object(None)


def test_is_original_object_detection():
    assert is_original_object("Original")
    assert is_original_object("original")
    assert is_original_object({"type": "CpmiOriginalObject", "name": "Original"})
    assert not is_original_object("Host1")


def test_typed_object_named_any_does_not_bypass_resolver_typing():
    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": "host-any", "name": "Any", "type": "host"})
    result = resolver.resolve("Any", allow_special_symbolic_names=True)
    assert result.semantic_kind == SemanticKind.ADDRESS
    assert result.uid == "host-any"


def test_resolve_registered_object_by_uid_and_name():
    resolver = CheckPointObjectResolver()
    resolver.register_object({
        "uid": "uid-host-001",
        "name": "Web_Server",
        "type": "host",
        "ipv4-address": "10.1.1.50"
    })

    # Resolve by UID
    res_uid = resolver.resolve("uid-host-001")
    assert res_uid.resolved
    assert res_uid.name == "Web_Server"
    assert res_uid.semantic_kind == SemanticKind.ADDRESS
    assert res_uid.usable_in_canonical_reference

    # Resolve by name
    res_name = resolver.resolve("Web_Server")
    assert res_name.resolved
    assert res_name.uid == "uid-host-001"


def test_resolve_objects_dictionary():
    resolver = CheckPointObjectResolver()
    resolver.register_dictionary([
        {"uid": "uid-svc-tcp-80", "name": "http", "type": "service-tcp", "port": "80"},
        {"uid": "uid-zone-trust", "name": "InternalZone", "type": "security-zone"},
    ])

    res_svc = resolver.resolve("uid-svc-tcp-80")
    assert res_svc.resolved
    assert res_svc.semantic_kind == SemanticKind.SERVICE

    res_zone = resolver.resolve("uid-zone-trust")
    assert res_zone.resolved
    assert res_zone.semantic_kind == SemanticKind.SECURITY_ZONE


def test_unresolved_uid_returns_unusable_result():
    resolver = CheckPointObjectResolver()
    res = resolver.resolve("unknown-uid-99999999-9999-9999-9999-999999999999")
    assert not res.resolved
    assert not res.usable_in_canonical_reference
    assert res.reason == "unresolved-object-reference"


def test_resolve_actions():
    resolver = CheckPointObjectResolver()
    resolver.register_dictionary([
        {"uid": "uid-act-accept", "name": "Accept", "type": "RulebaseAction"},
        {"uid": "uid-act-drop", "name": "Drop", "type": "RulebaseAction"},
        {"uid": "uid-act-reject", "name": "Reject", "type": "RulebaseAction"},
        {"uid": "uid-act-ask", "name": "Ask", "type": "RulebaseAction"},
    ])

    act, res = resolver.resolve_action("uid-act-accept")
    assert act == PolicyAction.ALLOW

    act, res = resolver.resolve_action("uid-act-drop")
    assert act == PolicyAction.DROP

    act, res = resolver.resolve_action("uid-act-reject")
    assert act == PolicyAction.DENY

    act, res = resolver.resolve_action("uid-act-ask")
    assert act is None
    assert res.requires_manual_review
    assert not res.usable_in_canonical_reference


def test_recursive_dependency_taint():
    resolver = CheckPointObjectResolver()

    # Host A (safe)
    resolver.register_object({"uid": "uid-host-a", "name": "Host-A", "type": "host"})
    resolver.set_object_normalization("uid-host-a", "Host-A", ExtractionStatus.NORMALIZED, requires_manual_review=False)

    # Host B (unsafe / manual review)
    resolver.register_object({"uid": "uid-host-b", "name": "Host-B", "type": "host"})
    resolver.set_object_normalization("uid-host-b", "Host-B", ExtractionStatus.PARTIALLY_NORMALIZED, requires_manual_review=True)

    # Group Safe: contains Host A
    resolver.register_object({
        "uid": "uid-grp-safe",
        "name": "Grp-Safe",
        "type": "group",
        "members": [{"uid": "uid-host-a", "name": "Host-A"}]
    })

    # Group Unsafe: contains Host B
    resolver.register_object({
        "uid": "uid-grp-unsafe",
        "name": "Grp-Unsafe",
        "type": "group",
        "members": [{"uid": "uid-host-b", "name": "Host-B"}]
    })

    # Group Nested Unsafe: contains Grp Safe + Grp Unsafe
    resolver.register_object({
        "uid": "uid-grp-nested-unsafe",
        "name": "Grp-Nested-Unsafe",
        "type": "group",
        "members": [
            {"uid": "uid-grp-safe", "name": "Grp-Safe"},
            {"uid": "uid-grp-unsafe", "name": "Grp-Unsafe"}
        ]
    })

    # Group Broken: contains unknown UID
    resolver.register_object({
        "uid": "uid-grp-broken",
        "name": "Grp-Broken",
        "type": "group",
        "members": [{"uid": "uid-non-existent"}]
    })

    assert resolver.is_dependency_safe("uid-host-a")
    assert not resolver.is_dependency_safe("uid-host-b")
    assert resolver.is_dependency_safe("uid-grp-safe")
    assert not resolver.is_dependency_safe("uid-grp-unsafe")
    assert not resolver.is_dependency_safe("uid-grp-nested-unsafe")
    assert not resolver.is_dependency_safe("uid-grp-broken")
