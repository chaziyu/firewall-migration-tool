from fwmigrate.vendors.palo_alto.native import build_derived_views, validate_panos_config
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_failed_typed_extraction_preserves_inventory_and_later_objects():
    config = build_panos_config("""<config><shared><network><sdwan>
      <traffic-distribution-profile>
        <entry name='malformed'><link><entry><weight><member>not-a-scalar</member></weight></entry></link></entry>
        <entry name='valid'><distribution-mode>weighted</distribution-mode></entry>
      </traffic-distribution-profile>
    </sdwan><address><entry name='later-address'><ip-netmask>192.0.2.1</ip-netmask><future-leaf>retain-me</future-leaf></entry></address></network></shared></config>""")

    records = {item.name: item for item in config.source_inventory}
    assert {"malformed", "valid", "later-address"} <= records.keys()
    assert records["malformed"].source_path.endswith("traffic-distribution-profile/entry")
    assert records["malformed"].scope == config.sdwan_traffic_distribution_profiles[0].scope
    assert records["malformed"].source_order is not None
    assert records["malformed"].source_order < records["valid"].source_order < records["later-address"].source_order
    assert config.unknown_paths and any("traffic-distribution-profile/entry" in path for path in config.unknown_paths)
    assert [item.name for item in config.sdwan_traffic_distribution_profiles] == ["valid"]
    assert [item.name for item in config.addresses] == ["later-address"]
    assert config.addresses[0].raw_extra["future-leaf"] == "retain-me"

    issue = next(item for item in config.extraction_issues if item.source_name == "malformed")
    assert (issue.domain, issue.exception_type, issue.scope) == (
        "sdwan_traffic_distribution_profile", "ValidationError", records["malformed"].scope
    )
    assert issue.source_path == records["malformed"].source_path
    assert issue.source_order == records["malformed"].source_order
    assert "not-a-scalar" in issue.message
    validation = validate_panos_config(config, build_derived_views(config))
    assert any(item.severity == "warning" and item.domain == "extraction" and item.source_name == "malformed" for item in validation.issues)


def test_unsupported_source_remains_in_inventory():
    config = build_panos_config("<config><shared><future-domain><entry name='unknown'><future-leaf>keep</future-leaf></entry></future-domain></shared></config>")
    record = next(item for item in config.source_inventory if item.name == "unknown")
    assert record.source_path.endswith("future-domain/entry")
    assert record.values["future-leaf"] == "keep"
