from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter


def _messages(source):
    return [issue.message for issue in PaloAltoSourceReporter().analyze_source(source).validation.issues]


def test_valid_pan_os_wildcard_address_has_no_validation_issue():
    messages = _messages("<config><shared><address><entry name='wildcard'><ip-wildcard>10.5.1.1/0.127.248.2</ip-wildcard></entry></address></shared></config>")
    assert not any("malformed ip_wildcard" in message for message in messages)


def test_invalid_pan_os_wildcard_address_is_reported():
    messages = _messages("<config><shared><address><entry name='wildcard'><ip-wildcard>10.5.1.999/0.127.248.2</ip-wildcard></entry></address></shared></config>")
    assert any("malformed ip_wildcard" in message for message in messages)


def test_service_port_zero_is_allowed_in_source_context():
    messages = _messages("<config><shared><service><entry name='zero'><protocol><tcp><port>0-65535</port><source-port>0</source-port></tcp></protocol></entry></service></shared></config>")
    assert not any("malformed port expression" in message for message in messages)


def test_nat_translated_port_zero_is_rejected():
    messages = _messages("<config><shared><rulebase><nat><rules><entry name='bad-nat'><destination-translation><translated-port>0</translated-port></destination-translation></entry></rules></nat></rulebase></shared></config>")
    assert any("malformed translated port" in message for message in messages)


def test_ipsec_proxy_port_zero_is_allowed():
    messages = _messages("""<config><shared><network><ipsec><entry name='vpn'><auto-key><proxy-id>
      <entry name='proxy'><protocol><tcp><local-port>0</local-port><remote-port>0</remote-port></tcp></protocol></entry>
    </proxy-id></auto-key></entry></ipsec></network></shared></config>""")
    assert not any("proxy local-port" in message or "proxy remote-port" in message for message in messages)
