from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_sdwan_xml_reaches_typed_profiles_and_rules():
    config = build_panos_config("""<config><shared><network><sdwan>
      <interface-profile><entry name='wan-primary'><link-tag>primary</link-tag><link-type>ethernet</link-type></entry></interface-profile>
      <rules><entry name='prefer-primary'><from><member>trust</member></from><to><member>untrust</member></to>
        <path-quality-profile>quality-primary</path-quality-profile><description>keep rule</description>
      </entry></rules>
    </sdwan></network></shared></config>""")

    profile = config.sdwan_interface_profiles[0]
    rule = config.sdwan_rules[0]
    assert profile.name == "wan-primary"
    assert profile.link_tag == "primary"
    assert profile.link_type == "ethernet"
    assert rule.name == "prefer-primary"
    assert {"from_zones", "to_zones"} <= rule.explicit_fields
    assert rule.path_quality_profile == "quality-primary"


def test_sdwan_links_and_interface_bindings_reach_existing_typed_models():
    config = build_panos_config("""<config><shared><network><sdwan>
      <traffic-distribution-profile><entry name='balanced'><distribution-mode>weighted</distribution-mode><link><entry><link-tag>primary</link-tag><weight>80</weight></entry><entry><link-tag>backup</link-tag><weight>20</weight><future-link-field>retain-me</future-link-field></entry></link></entry></traffic-distribution-profile>
    </sdwan></network></shared><devices><entry name='fw'><network><interface><ethernet><entry name='ethernet1/1'><layer3><sdwan-link-settings><enable>yes</enable><ipv6-enable>no</ipv6-enable><sdwan-interface-profile>wan-primary</sdwan-interface-profile><upstream-nat><enable>yes</enable></upstream-nat></sdwan-link-settings><units><entry name='ethernet1/1.10'><sdwan-link-settings><enable>yes</enable><ipv6-enable>yes</ipv6-enable><sdwan-interface-profile>wan-sub</sdwan-interface-profile><upstream-nat>no</upstream-nat></sdwan-link-settings></entry></units></layer3></entry></ethernet></interface></network></entry></devices></config>""")

    profile = config.sdwan_traffic_distribution_profiles[0]
    interface = config.interfaces[0]
    unit = config.interface_units[0]
    assert profile.distribution_mode == "weighted"
    assert [(link.link_tag, link.weight) for link in profile.links] == [("primary", "80"), ("backup", "20")]
    assert profile.links[1].raw_extra["future-link-field"] == "retain-me"
    assert (interface.sdwan_enabled, interface.ipv6_sdwan_enabled, interface.sdwan_interface_profile, interface.upstream_nat) == ("yes", "no", "wan-primary", "yes")
    assert (unit.sdwan_enabled, unit.ipv6_sdwan_enabled, unit.sdwan_interface_profile, unit.upstream_nat) == ("yes", "yes", "wan-sub", "no")


def test_sdwan_missing_and_empty_links_preserve_source_presence():
    config = build_panos_config("""<config><shared><network><sdwan>
      <traffic-distribution-profile><entry name='missing'/><entry name='empty'><link/></entry>
    </traffic-distribution-profile>
    </sdwan></network></shared></config>""")

    missing, empty = config.sdwan_traffic_distribution_profiles
    assert missing.links is None
    assert "links" not in missing.explicit_fields
    assert empty.links == []
    assert "links" in empty.explicit_fields


def test_sdwan_unknown_source_is_retained_separately():
    config = build_panos_config("<config><shared><network><sdwan><rules><entry name='r'><future-setting>retain-me</future-setting></entry></rules></sdwan></network></shared></config>")
    assert config.source_inventory
    assert config.sdwan_rules[0].raw_extra["future-setting"] == "retain-me"
