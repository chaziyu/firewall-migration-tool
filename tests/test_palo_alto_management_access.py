from pathlib import Path

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


FIXTURE = Path(__file__).parent / "fixtures" / "palo_alto" / "management_access.xml"


def test_management_access_is_source_only_and_scope_aware():
    result = PANOSSourceParser().extract(FIXTURE.read_text(encoding="utf-8"))

    records = [item for item in result.inventory_items if item.domain == "management_access"]
    assert records
    assert all(item.status == ExtractionStatus.EXTRACT_ONLY for item in records)

    profile = next(item for item in records if item.name == "allow-admin")
    assert profile.source_path == (
        "network/profiles/interface-management-profile/entry[@name='allow-admin']"
    )
    assert profile.source_attributes["pan_management_access_kind"] == "interface-management-profile"
    assert profile.source_attributes["pan_scope_kind"] == "device"
    assert profile.source_attributes["pan_scope_name"] == "pa-fw-01"
    assert profile.source_attributes["pan_device_serial"] == "pa-fw-01"
    assert profile.source_attributes["pan_source_entry"]["entry"]["attributes"]["name"] == "allow-admin"
    assert "future-management-setting" in profile.source_attributes["pan_unknown_fields"]

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
    assert interface.management_profile == "allow-admin"
    assert interface.source_attributes["pan_management_profile"] == "allow-admin"
