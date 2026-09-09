from fwmigrate.parsers.juniper_srx import JuniperSRXParser
from fwmigrate.parsers.juniper_srx.resolver import JuniperReferenceResolver


def test_tenant_address_books_applications_schedulers_and_predefined_apps():
    parser = JuniperSRXParser("""
    set tenants TSYS1 security zones security-zone trust address-book BOOK
    set tenants TSYS1 security address-book global address HOST1 192.0.2.10/32
    set tenants TSYS1 security address-book global address-set SET1 address HOST1
    set tenants TSYS1 applications application APP1 protocol tcp destination-port 80
    set tenants TSYS1 applications application-set APPS application APP1
    set tenants TSYS1 schedulers scheduler S1 start-date 2026-01-01.00:00:00
    """)
    parser.extract()
    context = parser.config.contexts["TSYS1"]
    resolver = JuniperReferenceResolver(context)

    address = resolver.resolve_policy_source("trust", "HOST1")
    assert address.name == "TSYS1__HOST1"
    assert resolver.resolve_application("APP1")[2] == "TSYS1__APP1"
    assert resolver.resolve_application("junos-http")[2] == "junos-http"
    assert resolver.resolve_scheduler("S1").name == "S1"
    assert resolver.resolve_policy_source("trust", "ROOT_ONLY").is_unresolved
