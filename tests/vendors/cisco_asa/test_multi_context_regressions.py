from fwmigrate.vendors.cisco_asa.relationships.references import ASAReferenceKind, ASAReferenceStatus, build_asa_reference_index
from fwmigrate.vendors.cisco_asa.source_report import extract_cisco_asa_source


def test_duplicate_names_and_nat_references_stay_inside_their_context():
    result = extract_cisco_asa_source(
        "changeto context customer-a\nobject network WEB\n host 10.0.0.1\n"
        "object network ONLY_A\n host 10.0.0.2\n"
        "nat (inside,outside) source static WEB interface\n"
        "changeto context customer-b\nobject network WEB\n host 192.0.2.1\n"
        "object network ONLY_B\n host 192.0.2.2\n"
        "nat (inside,outside) source static WEB interface\n"
        "changeto context customer-a\nnat (inside,outside) source static ONLY_B interface\n"
    )
    refs = build_asa_reference_index(result.config)

    a = refs.resolve("customer-a", ASAReferenceKind.NETWORK_OBJECT, "WEB")
    b = refs.resolve("customer-b", ASAReferenceKind.NETWORK_OBJECT, "WEB")
    assert a.target.value == "10.0.0.1" and b.target.value == "192.0.2.1"
    assert refs.resolve("customer-a", ASAReferenceKind.NETWORK_OBJECT, "ONLY_B").status is ASAReferenceStatus.UNRESOLVED
    contexts = [row.source_context for row in result.derived.nat_relationships.rules]
    assert contexts.count("customer-a") == 2
    assert contexts.count("customer-b") == 1
    assert [(row.source_context, row.effective_order) for row in result.derived.nat.rules] == [
        ("customer-a", 1), ("customer-b", 1), ("customer-a", 2)]
    assert any(issue.source_context == "customer-a" and issue.reference_name == "ONLY_B"
               for issue in result.derived.reference_issues)
