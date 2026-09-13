from fwmigrate.parsers.juniper_srx import JuniperSRXParser


def test_policy_dependencies_resolve_source_and_destination_in_their_own_zones():
    result = JuniperSRXParser("""
    set security zones security-zone trust interfaces ge-0/0/0.0
    set security zones security-zone dmz interfaces ge-0/0/1.0
    set security address-book trust_book attach zone trust
    set security address-book trust_book address shared 10.0.0.1/32
    set security address-book dmz_book attach zone dmz
    set security address-book dmz_book address shared 10.0.0.2/32
    set security policies from-zone trust to-zone dmz policy p match source-address shared
    set security policies from-zone trust to-zone dmz policy p match destination-address shared
    set security policies from-zone trust to-zone dmz policy p match application any
    set security policies from-zone trust to-zone dmz policy p then permit
    """).extract()

    dependencies = {
        dependency.source_field: dependency
        for dependency in result.dependencies
        if dependency.source_object == "p"
        and dependency.source_field in {"source-address", "destination-address"}
    }
    assert dependencies["source-address"].result == "RESOLVED"
    assert dependencies["destination-address"].result == "RESOLVED"
    policy = result.canonical_ir.policies[0]
    assert policy.source == ["trust_book__shared"]
    assert policy.destination == ["dmz_book__shared"]


def test_nat_pool_and_static_prefix_name_dependencies_are_typed():
    result = JuniperSRXParser("""
    set security address-book global address internal_srv 172.16.1.10/32
    set routing-instances RI1 instance-type virtual-router
    set security nat destination pool dst address 10.0.0.10/32
    set security nat destination pool dst routing-instance RI1
    set security nat static rule-set rs from zone untrust
    set security nat static rule-set rs rule r match destination-address 198.51.100.10/32
    set security nat static rule-set rs rule r then static-nat prefix-name internal_srv
    """).extract()

    typed = {
        (dependency.source_field, dependency.reference): dependency
        for dependency in result.dependencies
        if dependency.source_field in {"routing-instance", "static-prefix-name"}
    }
    assert typed[("routing-instance", "RI1")].result == "RESOLVED"
    assert typed[("static-prefix-name", "internal_srv")].result == "RESOLVED"
