from pathlib import Path

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


FIXTURE = Path(__file__).parent / "fixtures" / "palo_alto" / "management_access.xml"


def test_management_access_is_source_only_and_scope_aware():
    result = PANOSSourceParser().extract(FIXTURE.read_text(encoding="utf-8"))

    records = [item for item in result.inventory_items if item.domain == "management_access"]
    assert records
    assert all(item.status == ExtractionStatus.EXTRACT_ONLY for item in records)

    profile = next(item for item in records if item.name == "mgmt-full")
    assert profile.source_path == (
        "network/profiles/interface-management-profile/entry[@name='mgmt-full']"
    )
    assert profile.source_attributes["pan_management_access_kind"] == "interface-management-profile"
    assert profile.source_attributes["pan_scope_kind"] == "device"
    assert profile.source_attributes["pan_scope_name"] == "pa-fw-01"
    assert profile.source_attributes["pan_device_serial"] == "pa-fw-01"
    assert profile.source_attributes["pan_management_profile_name"] == "mgmt-full"
    assert profile.source_attributes["pan_source_entry"]["entry"]["attributes"]["name"] == "mgmt-full"
    assert "future-management-setting" in profile.source_attributes["pan_management_profile_unknown_fields"]
    assert profile.status == ExtractionStatus.EXTRACT_ONLY

    system_paths = {item.source_path for item in records if item.name is None}
    assert "deviceconfig/system/permitted-ip" in system_paths
    assert "deviceconfig/system/service" in system_paths
    assert {
        item.source_attributes["pan_management_access_kind"]
        for item in records
        if item.source_path.startswith("deviceconfig/system/")
    } == {"system-management-access", "management-interface-access"}


def test_management_access_does_not_create_policy_route_or_nat_objects():
    result = PANOSSourceParser().extract(FIXTURE.read_text(encoding="utf-8"))

    assert result.canonical_ir.policies == []
    assert result.canonical_ir.routes == []
    assert result.canonical_ir.nat_rules == []
    assert not any(item.domain in {"policies", "routes", "nat"} for item in result.inventory_items)
    assert not any(item.domain == "pbf" for item in result.inventory_items)


def test_management_profile_is_not_double_counted_as_generic_network_residual():
    result = PANOSSourceParser().extract(FIXTURE.read_text(encoding="utf-8"))

    assert not any(
        item.domain == "network" and item.source_path.startswith("network/profiles/interface-management-profile")
        for item in result.inventory_items
    )
    assert any(
        section.path == "network/profiles/interface-management-profile"
        and section.status == ExtractionStatus.EXTRACT_ONLY
        for section in result.source_sections
    )


def test_missing_management_profile_name_is_parse_error_with_raw_source():
    xml = """
    <config version="11.1.0">
      <devices><entry name="pa-fw-01"><network><profiles>
        <interface-management-profile>
          <entry><ssh>yes</ssh></entry>
        </interface-management-profile>
      </profiles></network></entry></devices>
    </config>
    """

    result = PANOSSourceParser().extract(xml)
    records = [item for item in result.inventory_items if item.domain == "management_access"]

    assert len(records) == 1
    assert records[0].status == ExtractionStatus.PARSE_ERROR
    assert records[0].name is None
    assert records[0].source_attributes["pan_source_entry"]
    assert "name" not in records[0].source_attributes["pan_source_entry"]["entry"].get("attributes", {})


def test_existing_interface_management_profile_reference_is_unchanged():
    result = PANOSSourceParser().extract(FIXTURE.read_text(encoding="utf-8"))

    interface = result.canonical_ir.interfaces[0]
    assert interface.management_profile == "mgmt-full"
    assert interface.source_attributes["pan_management_profile"] == "mgmt-full"


def test_interface_management_profile_services_are_ordered_and_presence_aware():
    result = PANOSSourceParser().extract(FIXTURE.read_text(encoding="utf-8"))
    profile = next(item for item in result.inventory_items if item.name == "mgmt-full")
    attrs = profile.source_attributes

    assert list(attrs["pan_management_profile_services"]) == [
        "http", "https", "ping", "response-pages", "userid-service",
        "userid-syslog-listener-ssl", "userid-syslog-listener-udp", "ssh",
        "telnet", "snmp", "http-ocsp",
    ]
    assert attrs["pan_management_profile_services"] == {
        "http": True, "https": False, "ping": True, "response-pages": False,
        "userid-service": True, "userid-syslog-listener-ssl": False,
        "userid-syslog-listener-udp": True, "ssh": False, "telnet": True,
        "snmp": False, "http-ocsp": True,
    }
    assert set(attrs["pan_management_profile_service_presence"]) == set(attrs["pan_management_profile_services"])


def test_interface_management_profile_omissions_and_permitted_ips_are_preserved():
    result = PANOSSourceParser().extract(FIXTURE.read_text(encoding="utf-8"))
    full = next(item for item in result.inventory_items if item.name == "mgmt-full")
    minimal = next(item for item in result.inventory_items if item.name == "mgmt-minimal")

    assert full.source_attributes["pan_management_profile_permitted_ips"] == [
        "192.0.2.10", "198.51.100.0/24", "2001:db8:1::/64"
    ]
    assert full.source_attributes["pan_management_profile_permitted_ip_explicit"] is True
    assert minimal.source_attributes["pan_management_profile_services"] == {"https": True}
    assert "ssh" not in minimal.source_attributes["pan_management_profile_services"]
    assert minimal.source_attributes["pan_management_profile_permitted_ips"] == []
    assert minimal.source_attributes["pan_management_profile_permitted_ip_explicit"] is False


def test_interface_management_profile_raw_sources_and_unknown_fields_are_retained():
    result = PANOSSourceParser().extract(FIXTURE.read_text(encoding="utf-8"))
    profile = next(item for item in result.inventory_items if item.name == "mgmt-full")
    attrs = profile.source_attributes

    assert attrs["pan_management_profile_source"]["entry"]["http"]
    assert attrs["pan_management_profile_source"]["entry"]["permitted-ip"]["entry"]
    assert "future-management-setting" in attrs["pan_management_profile_source"]["entry"]
    assert [entry["attributes"]["name"] for entry in attrs["pan_management_profile_permitted_ip_source"]["permitted-ip"]["entry"]] == [
        "192.0.2.10", "198.51.100.0/24", "2001:db8:1::/64"
    ]
    assert profile.requires_manual_review is True
    assert profile.status == ExtractionStatus.EXTRACT_ONLY


def _profile_xml(profile_body: str) -> str:
    return f"""
    <config><devices><entry name="pa-fw-01"><network><profiles>
      <interface-management-profile><entry name="test-profile">{profile_body}</entry>
    </interface-management-profile></profiles></network></entry></devices></config>
    """


def test_malformed_profile_values_are_preserved_in_one_parse_error_record():
    result = PANOSSourceParser().extract(_profile_xml(
        "<ssh>maybe</ssh><https>yes</https><permitted-ip><entry name=\"bad-ip\"/><entry name=\"192.0.2.1\"/></permitted-ip>"
    ))
    records = [item for item in result.inventory_items if item.domain == "management_access"]
    profile = next(item for item in records if item.name == "test-profile")

    assert len(records) == 1
    assert profile.status == ExtractionStatus.PARSE_ERROR
    assert profile.source_attributes["pan_management_profile_services"]["ssh"] == "maybe"
    assert profile.source_attributes["pan_management_profile_invalid_services"] == ["ssh"]
    assert profile.source_attributes["pan_management_profile_invalid_permitted_ips"] == ["bad-ip"]
    assert profile.source_attributes["pan_management_profile_permitted_ips"] == ["bad-ip", "192.0.2.1"]


def test_missing_permitted_ip_name_and_profile_name_are_parse_errors_with_raw_source():
    result = PANOSSourceParser().extract(_profile_xml(
        "<ssh>yes</ssh><permitted-ip><entry/><entry name=\"2001:db8::1\"/></permitted-ip>"
    ))
    profile = next(item for item in result.inventory_items if item.name == "test-profile")
    assert profile.status == ExtractionStatus.PARSE_ERROR
    assert profile.source_attributes["pan_management_profile_permitted_ips"] == ["2001:db8::1"]
    assert profile.source_attributes["pan_management_profile_missing_permitted_ip_names"] == [0]
    assert profile.source_attributes["pan_management_profile_permitted_ip_source"]

    missing_name = PANOSSourceParser().extract(_profile_xml("<ssh>yes</ssh>").replace(
        'entry name="test-profile"', 'entry'
    ))
    records = [item for item in missing_name.inventory_items if item.domain == "management_access"]
    assert len(records) == 1
    assert records[0].status == ExtractionStatus.PARSE_ERROR
    assert records[0].name is None
    assert records[0].source_attributes["pan_management_profile_source"]


def test_duplicate_profile_names_are_not_collapsed():
    xml = _profile_xml("<ssh>yes</ssh>").replace(
        '</interface-management-profile>',
        '<entry name="test-profile"><ssh>no</ssh></entry></interface-management-profile>'
    )
    result = PANOSSourceParser().extract(xml)
    records = [item for item in result.inventory_items if item.domain == "management_access"]
    assert len(records) == 2
    assert all(item.status == ExtractionStatus.PARSE_ERROR for item in records)


def test_management_profile_section_counts_all_source_entries():
    result = PANOSSourceParser().extract(FIXTURE.read_text(encoding="utf-8"))
    section = next(section for section in result.source_sections if section.path == "network/profiles/interface-management-profile")
    assert section.status == ExtractionStatus.EXTRACT_ONLY
    assert section.object_count_source == 2
    assert section.object_count_parsed == 2
    assert section.object_count_normalized == 0
