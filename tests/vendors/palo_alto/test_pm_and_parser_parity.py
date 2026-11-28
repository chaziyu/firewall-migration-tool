"""Tests for Phase 2 Palo Alto extraction parity."""

from __future__ import annotations

from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


_PA_PARITY_XML = """<config version="11.1.0" detail-version="11.1.4">
  <devices><entry name="fw">
    <deviceconfig>
      <system>
        <hostname>PA-PARITY</hostname>
        <ip-address>10.1.1.10</ip-address>
        <netmask>255.255.255.0</netmask>
        <speed-duplex>auto</speed-duplex>
        <ipv6-link-local-address>fe80::1/64</ipv6-link-local-address>
        <route>
          <entry name="default"><nexthop><ip-address>10.1.1.1</ip-address></nexthop></entry>
        </route>
      </system>
      <setting>
        <advanced-routing><enable>yes</enable></advanced-routing>
        <management><enable-duplicate-mac-detect>yes</enable-duplicate-mac-detect></management>
      </setting>
      <high-availability>
        <enabled>yes</enabled>
        <group>
          <group-id>5</group-id>
          <peer-ip>169.254.0.2</peer-ip>
          <mode><active-passive/></mode>
        </group>
        <interface><ha1><port>ha1-a</port><ip-address>169.254.0.1</ip-address></ha1></interface>
        <monitoring><link-monitoring><enabled>yes</enabled></link-monitoring></monitoring>
      </high-availability>
    </deviceconfig>
  </entry></devices>
</config>"""


def test_paloalto_phase2_parity_system_ha_and_device_setup_fields():
    cfg = build_panos_config(_PA_PARITY_XML)

    assert len(cfg.system_settings) == 1
    sys_cfg = cfg.system_settings[0]
    assert sys_cfg.speed_duplex == "auto"
    assert sys_cfg.ipv6_link_local_address == "fe80::1/64"
    assert sys_cfg.route is not None

    assert len(cfg.device_setup_settings) == 1
    setup = cfg.device_setup_settings[0]
    assert setup.advanced_routing == {"enable": "yes"}
    assert setup.management is not None

    assert len(cfg.ha_configs) == 1
    ha = cfg.ha_configs[0]
    assert ha.enabled == "yes"
    assert ha.group is not None and ha.group.get("group-id") == "5"
    assert ha.monitoring == {"link-monitoring": {"enabled": "yes"}}
