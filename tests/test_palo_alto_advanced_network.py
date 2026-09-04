from fwmigrate.parsers.palo_alto import PANOSSourceParser

def test_pan_dns_proxy_and_monitor_are_typed():
    xml = '<config><devices><entry name="fw"><network><dns-proxy><entry name="p"><cache><cache-enabled>yes</cache-enabled></cache><interface><member>loopback.1</member></interface></entry></dns-proxy><profiles><monitor-profile><entry name="default"><interval>3</interval><threshold>5</threshold><action>wait-recover</action></entry></monitor-profile></profiles></network></entry></devices></config>'
    ir = PANOSSourceParser().parse(xml)
    assert ir.pan_dns_proxies[0].cache_enabled is True
    assert ir.pan_monitor_profiles[0].interval_seconds == 3
