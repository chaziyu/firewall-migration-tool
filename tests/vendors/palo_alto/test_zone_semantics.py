from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_selected_zone_nested_fields_and_members_are_source_faithful():
    config = build_panos_config("""<config><shared><zone><entry name='trust'>
      <enable-user-identification>yes</enable-user-identification><enable-device-identification>no</enable-device-identification>
      <network><zone-protection-profile>protect</zone-protection-profile><enable-packet-buffer-protection>yes</enable-packet-buffer-protection>
        <net-inspection>no</net-inspection><log-setting>zone-log</log-setting>
        <prenat-identification><enable-prenat-user-identification>yes</enable-prenat-user-identification><enable-prenat-source-policy-lookup>no</enable-prenat-source-policy-lookup><future-prenat>keep-prenat</future-prenat></prenat-identification>
        <layer3><member>ethernet1/1</member><future-member>keep-member</future-member></layer3>
        <other-list><member>not-a-zone-interface</member></other-list><future-network>keep-network</future-network>
      </network>
      <user-acl><include-list><member>alice</member></include-list><exclude-list><member>guest</member></exclude-list><future-acl>keep-acl</future-acl></user-acl>
      <device-acl><include-list><member>managed</member></include-list></device-acl>
    </entry></zone></shared></config>""")
    zone, = config.zones
    assert zone.user_identification == "yes" and zone.device_identification == "no"
    assert zone.network_type == "layer3" and zone.members == ["ethernet1/1"]
    assert zone.zone_protection_profile == "protect" and zone.packet_buffer_protection == "yes"
    assert zone.network_inspection == "no" and zone.log_setting == "zone-log"
    assert zone.pre_nat_user_identification == "yes" and zone.pre_nat_source_policy_lookup == "no"
    assert zone.user_acl_include == ["alice"] and zone.user_acl_exclude == ["guest"]
    assert zone.device_acl_include == ["managed"]
    assert zone.raw_extra["network"]["other-list"]["member"] == "not-a-zone-interface"
    assert zone.raw_extra["network"]["future-network"] == "keep-network"
    assert zone.raw_extra["network"]["prenat-identification"]["future-prenat"] == "keep-prenat"
    assert zone.raw_extra["user-acl"]["future-acl"] == "keep-acl"


def test_selected_zone_without_network_type_does_not_infer_one():
    config = build_panos_config("<config><shared><zone><entry name='empty'><network><zone-protection-profile>protect</zone-protection-profile></network></entry></zone></shared></config>")
    zone, = config.zones
    assert zone.network_type is None and zone.members is None
    assert zone.zone_protection_profile == "protect"
