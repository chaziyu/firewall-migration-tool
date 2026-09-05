from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser
from fwmigrate.parsers.juniper_srx.resolver import JuniperReferenceResolver


def test_inactive_scheduler_and_application_do_not_resolve_predefined_still_does():
    cfg = JuniperSRXParser("""
set applications application custom protocol tcp
deactivate applications application custom
set schedulers scheduler inactive start-date 2026-01-01.00:00:00
deactivate schedulers scheduler inactive
""").parse_raw().contexts["root"]
    resolver = JuniperReferenceResolver(cfg)
    assert resolver.resolve_application("custom") == (False, False, None)
    assert resolver.resolve_scheduler("inactive") is None
    assert resolver.resolve_application("junos-https") == (True, False, "junos-https")
