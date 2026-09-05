from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.checkpoint.resolver import CheckPointObjectResolver, normalize_domain_identity


def test_r81_domain_metadata_is_normalized_and_nat_is_scoped():
    resolver = CheckPointObjectResolver()
    domain = {"uid": "domain-a", "name": "Domain A", "domain-type": "domain"}
    resolver.register_object({
        "uid": "object-a", "name": "Web", "type": "host", "domain": domain,
        "nat-settings": {"method": "hide"},
    }, domain={"uid": "fallback", "name": "Fallback"})

    assert normalize_domain_identity(domain) == ("domain-a", "Domain A")
    assert resolver.object_domain("object-a") == ("domain-a", "Domain A")
    assert resolver.get_automatic_nat_metadata("object-a", domain_uid="domain-a") == {"method": "hide"}
    assert resolver.get_automatic_nat_metadata("object-a", domain_uid="fallback") is None


def test_duplicate_uid_remains_domain_safe_with_structured_domains():
    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": "same", "name": "A", "type": "host",
                              "domain": {"uid": "da", "name": "Domain A"}})
    resolver.register_object({"uid": "same", "name": "B", "type": "host",
                              "domain": {"uid": "db", "name": "Domain B"}})

    domain_a = resolver.resolve_scoped("same", domain_uid="da", domain_name="Domain A")
    domain_b = resolver.resolve_scoped("same", domain_uid="db", domain_name="Domain B")
    assert domain_a.resolved and domain_a.name == "A"
    assert domain_b.resolved and domain_b.name == "B"
    assert not resolver.resolve_scoped("same", domain_uid="dc", domain_name="Domain C").resolved


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
