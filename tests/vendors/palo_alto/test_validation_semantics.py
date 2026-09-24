from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter
from fwmigrate.vendors.palo_alto.validation.validator import _validate_ip, _validate_ip_wildcard, _validate_ports


def test_pan_os_wildcard_addresses_use_ipv4_wildcard_masks():
    assert _validate_ip_wildcard("10.5.1.1/0.127.248.2")
    assert _validate_ip_wildcard("10.132.1.2/0.0.2.255")
    assert not _validate_ip_wildcard("10.132.1.999/0.0.2.255")
    assert not _validate_ip_wildcard("2001:db8::1/::ffff")
    assert not _validate_ip_wildcard("10.1.1.1/255.255.255.0/1")
    assert not _validate_ip("10.5.1.1/0.127.248.2")
    assert not _validate_ip("10.1.0.0/not-a-mask")


def test_port_ranges_apply_source_context_limits():
    assert _validate_ports("0", minimum=0)
    assert _validate_ports("0-65535", minimum=0)
    assert _validate_ports("0", minimum=1) is False
    assert _validate_ports("1", minimum=1)
    assert _validate_ports("65535", minimum=1)
    for invalid in ("65536", "3-2", "1,,2", "x"):
        assert not _validate_ports(invalid, minimum=0)


def test_validator_accepts_wildcards_and_service_proxy_zero_but_rejects_nat_zero():
    source = """<config><shared><address><entry name='wildcard'><ip-wildcard>10.5.1.1/0.127.248.2</ip-wildcard></entry></address>
      <service><entry name='zero'><protocol><tcp><port>0-65535</port><source-port>0</source-port></tcp></protocol></entry></service>
      <rulebase><nat><rules><entry name='bad-nat'><destination-translation><translated-port>0</translated-port></destination-translation></entry></rules></nat></rulebase>
      <network><ipsec><entry name='vpn'><auto-key><proxy-id><entry name='proxy'><protocol><tcp><local-port>0</local-port><remote-port>0</remote-port></tcp></protocol></entry></proxy-id></auto-key></entry></ipsec></network>
    </shared></config>"""
    result = PaloAltoSourceReporter().analyze_source(source)
    messages = [issue.message for issue in result.validation.issues]
    assert not any("malformed ip_wildcard" in message for message in messages)
    assert not any("malformed port expression" in message for message in messages)
    assert not any("proxy local-port" in message or "proxy remote-port" in message for message in messages)
    assert any("malformed translated port" in message for message in messages)
