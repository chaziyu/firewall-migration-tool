from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.checkpoint.resolver import CheckPointObjectResolver


def test_scoped_resolution_does_not_cross_domains():
    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": "a1", "name": "Host1", "type": "host"}, domain="A", domain_uid="da")
    resolver.register_object({"uid": "b1", "name": "Host1", "type": "host"}, domain="B", domain_uid="db")
    resolver.set_object_normalization("a1", "Host1", ExtractionStatus.NORMALIZED, domain="A")
    resolver.set_object_normalization("b1", "Host1", ExtractionStatus.NORMALIZED, domain="B")

    local = resolver.resolve_scoped("Host1", domain_uid="da", domain_name="A")
    foreign = resolver.resolve_scoped("b1", domain_uid="da", domain_name="A")

    assert local.resolved and local.uid == "a1"
    assert not foreign.resolved
    assert foreign.reason == "cross-domain-reference-resolution-blocked"


def test_assigned_global_resolution_is_explicit():
    resolver = CheckPointObjectResolver()
    resolver.register_object(
        {"uid": "g1", "name": "Global-Web", "type": "host"},
        domain="global", domain_uid="dg",
    )
    resolver.set_object_normalization("g1", "Global-Web", ExtractionStatus.NORMALIZED, domain="global")
    resolver.register_global_assignment("da", "A", ["g1"])

    assigned = resolver.resolve_scoped("g1", domain_uid="da", domain_name="A")
    unassigned = resolver.resolve_scoped("g1", domain_uid="db", domain_name="B")

    assert assigned.resolved and assigned.uid == "g1"
    assert not unassigned.resolved
