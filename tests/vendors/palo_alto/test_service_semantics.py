from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_service_override_preserves_explicit_yes_no_presence():
    source = """<config><shared><service>
      <entry name='missing'><protocol><tcp><port>443</port></tcp></protocol></entry>
      <entry name='disabled'><protocol><tcp><override><no/></override></tcp></protocol></entry>
      <entry name='enabled'><protocol><tcp><override><yes/></override></tcp></protocol></entry>
      <entry name='timeout'><protocol><tcp><override><yes><timeout>300</timeout></yes></override></tcp></protocol></entry>
    </service></shared></config>"""
    config = build_panos_config(source)
    values = {item.name: item.tcp.override for item in config.services}
    assert values["missing"] is None
    assert values["disabled"].enabled == "no" and values["disabled"].explicit_fields == {"enabled"}
    assert values["enabled"].enabled == "yes" and "enabled" in values["enabled"].explicit_fields
    assert (values["timeout"].enabled, values["timeout"].timeout) == ("yes", "300")
    assert {"enabled", "timeout"} <= values["timeout"].explicit_fields
