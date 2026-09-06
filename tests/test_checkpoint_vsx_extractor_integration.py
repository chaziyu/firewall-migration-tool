from fwmigrate.parsers.checkpoint import extract_checkpoint_config


def test_vsx_dns_and_ntp_are_not_merged_into_root_canonical_settings():
    result = extract_checkpoint_config("""
set virtual-system 2
set interface eth0 ipv4-address 10.2.0.1 mask-length 24
set dns primary 10.2.0.53
set dns search vs2.example
set ntp server primary 10.2.0.10 version 4
set virtual-system 5
set interface eth0 ipv4-address 10.5.0.1 mask-length 24
set dns primary 10.5.0.53
set dns search vs5.example
set ntp server primary 10.5.0.10 version 4
""")

    assert result.canonical_ir.dns_settings is None
    assert result.canonical_ir.ntp_settings is None

    interfaces = [item for item in result.canonical_ir.interfaces if item.name == "eth0"]
    assert len(interfaces) == 2
    assert {item.source_attributes["virtual_system_id"] for item in interfaces} == {2, 5}
    assert all(item.requires_manual_review for item in interfaces)

    dns = [item for item in result.inventory_items if item.source_type == "gaia-dns-effective"]
    assert {item.source_attributes["virtual_system_id"] for item in dns} == {2, 5}
    raw_dns = [item for item in result.inventory_items if item.source_type == "gaia-dns-vs"]
    assert raw_dns
    assert all("root-level canonical" in " ".join(item.notes) for item in raw_dns)


def test_global_dns_still_maps_to_root_canonical_settings():
    result = extract_checkpoint_config("""
set dns primary 192.0.2.53
set dns secondary 2001:db8::53
set dns search corp.example
set domainname system.example
""")
    assert result.canonical_ir.dns_settings is not None
    assert result.canonical_ir.dns_settings.primary == "192.0.2.53"
    assert result.canonical_ir.dns_settings.secondary == "2001:db8::53"
    assert result.canonical_ir.dns_settings.search_suffixes == ["corp.example"]
    assert result.canonical_ir.dns_settings.domain_name == "system.example"
