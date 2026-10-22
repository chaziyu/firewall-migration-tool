import io

import pytest
from openpyxl import load_workbook

from fwmigrate.vendors.palo_alto.native import build_derived_views
from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter
from fwmigrate.vendors.palo_alto.validation.validator import validate_panos_config


SOURCE = """<config><shared><address>
 <entry name="interface-address"><ip-netmask>192.0.2.1/24</ip-netmask></entry>
 <entry name="route-network"><ip-netmask>198.51.100.0/24</ip-netmask></entry>
 <entry name="next-hop"><ip-netmask>192.0.2.254/32</ip-netmask></entry>
</address></shared><devices><entry name="fw"><network>
 <interface><tunnel><units><entry name="tunnel.1"><ip><entry name="interface-address"/></ip></entry></units></tunnel></interface>
 <virtual-router><entry name="vr"><routing-table><ip><static-route><entry name="route">
 <destination>route-network</destination><nexthop><ip-address>next-hop</ip-address></nexthop>
 </entry></static-route></ip></routing-table></entry></virtual-router>
</network></entry></devices></config>"""


def test_named_network_addresses_remain_source_only_review_without_mutating_source():
    reporter = PaloAltoSourceReporter()
    analysis = reporter.analyze_source(SOURCE)
    config = analysis.config
    before = config.model_dump(mode="json")
    views = build_derived_views(config)
    validation = validate_panos_config(config, views)
    references = [item for item in views.reference_resolutions if item.owner_field in {
        "ipv4_addresses", "destination", "nexthop_ip_address",
    }]
    assert len(references) == 3
    assert all(item.status == "SOURCE_ONLY" for item in references)
    assert all(item.resolution_reason.startswith("NETWORK_ADDRESS_OBJECT_REVIEW:") for item in references)
    assert not validation.errors
    assert len(validation.warnings) == 3
    assert all("named network address" in item.message for item in validation.warnings)
    assert config.interface_units[0].ipv4_addresses == ["interface-address"]
    assert config.virtual_routers[0].static_routes[0].destination == "route-network"
    preview = reporter.build_preview(analysis)
    assert preview["sections"]["routes"][0]["destination"] == "route-network"
    assert all(item["severity"] == "warning" for item in preview["sections"]["validation"])
    for profile in ("fast", "full"):
        output = io.BytesIO()
        reporter.export_excel(analysis, output, profile=profile)
        workbook = load_workbook(output, read_only=True)
        rows = list(workbook["Virtual Router Routes"].values)
        route = dict(zip(rows[2], rows[3]))
        assert route["Destination"] == "route-network"
        assert "named network address" in route["Review Reasons"]
        workbook.close()
    assert config.model_dump(mode="json") == before


@pytest.mark.parametrize("replacement", ["missing-object", "192.0.2.999/24"])
def test_missing_names_and_invalid_literals_still_report_errors(replacement):
    analysis = PaloAltoSourceReporter().analyze_source(SOURCE.replace('name="interface-address"/>', f'name="{replacement}"/>'))
    assert any(issue.domain == "interface" and issue.field == "ipv4_addresses" for issue in analysis.validation.errors)


def test_literal_network_values_keep_the_existing_validation_path():
    source = SOURCE.replace('name="interface-address"/>', 'name="192.0.2.1/24"/>')
    source = source.replace('<destination>route-network</destination>', '<destination>198.51.100.0/24</destination>')
    source = source.replace('<ip-address>next-hop</ip-address>', '<ip-address>192.0.2.254</ip-address>')
    analysis = PaloAltoSourceReporter().analyze_source(source)
    assert not analysis.validation.issues
    assert not any(item.resolution_reason.startswith("NETWORK_ADDRESS_OBJECT_REVIEW:") for item in analysis.derived.reference_resolutions)


def test_same_device_objects_require_review_and_other_devices_cannot_satisfy_them():
    source = SOURCE.replace('<shared><address>', '<devices><entry name="fw"><vsys><entry name="vsys1"><address>')
    source = source.replace('</address></shared><devices><entry name="fw"><network>', '</address></entry></vsys><network>')
    analysis = PaloAltoSourceReporter().analyze_source(source)
    assert len(analysis.validation.warnings) == 3
    assert not analysis.validation.errors
    source = source.replace('<vsys>', '</entry><entry name="other"><vsys>', 1)
    source = source.replace('</vsys><network>', '</vsys></entry><entry name="fw"><network>', 1)
    analysis = PaloAltoSourceReporter().analyze_source(source)
    assert len([issue for issue in analysis.validation.errors if issue.domain in {"interface", "route"}]) == 3


def test_duplicate_and_wrong_type_objects_are_never_treated_as_valid_network_values():
    source = SOURCE.replace('</address>', '<entry name="interface-address"><fqdn>example.test</fqdn></entry></address>', 1)
    analysis = PaloAltoSourceReporter().analyze_source(source)
    references = [item for item in analysis.derived.reference_resolutions if item.owner_field == "ipv4_addresses"]
    assert len(references) == 1 and references[0].status == "AMBIGUOUS"
    assert any("named network address" in item.message for item in analysis.validation.warnings)
    source = SOURCE.replace('<ip-netmask>192.0.2.1/24</ip-netmask>', '<fqdn>example.test</fqdn>')
    analysis = PaloAltoSourceReporter().analyze_source(source)
    assert any(item.owner_field == "ipv4_addresses" and item.status == "SOURCE_ONLY" for item in analysis.derived.reference_resolutions)
    assert any("address type" in item.message for item in analysis.validation.warnings)
