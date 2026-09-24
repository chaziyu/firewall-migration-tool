import ast
import inspect
import textwrap

import pytest

from fwmigrate.vendors.palo_alto.export.excel_rows import ROW_BUILDERS
from fwmigrate.vendors.palo_alto.export.excel_schema import (
    ACTIVE_SHEET_ORDER,
    SHEET_HEADERS,
    SHEET_IMPLEMENTATION_STATUS,
)
from fwmigrate.vendors.palo_alto.extraction.extractor import registered_typed_collections
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config
from fwmigrate.vendors.palo_alto.model.source import PANOSConfig
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_registered_collections_are_unique_and_initialized():
    names = list(registered_typed_collections())
    assert len(names) == len(set(names))
    config = PANOSConfig()
    assert all(hasattr(config, name) and isinstance(getattr(config, name), list) for name in names)


def test_registered_collections_are_deterministic():
    first = registered_typed_collections()
    second = registered_typed_collections()
    assert first == second
    assert first == tuple(sorted(first))


@pytest.mark.parametrize(
    ("xml", "collection", "object_name"),
    (
        ("<tag><entry name='tag-1'/></tag>", "tags", "tag-1"),
        ("<address><entry name='address-1'><ip-netmask>192.0.2.1</ip-netmask></entry></address>", "addresses", "address-1"),
        ("<schedule><entry name='schedule-1'/></schedule>", "schedules", "schedule-1"),
        ("<network><dhcp><interface><entry name='dhcp-if'><mode>auto</mode></entry></interface></dhcp></network>", "dhcp_servers", "dhcp-if"),
        ("<network><sdwan><rules><entry name='sdwan-rule-1'><description>typed</description></entry></rules></sdwan></network>", "sdwan_rules", "sdwan-rule-1"),
        ("<network><ike><gateway><entry name='ike-gateway-1'><ike-version>ikev2</ike-version></entry></gateway></ike></network>", "ike_gateways", "ike-gateway-1"),
        ("<network><global-protect><portal><entry name='gp-portal-1'/></portal></global-protect></network>", "globalprotect_portals", "gp-portal-1"),
    ),
)
def test_representative_source_paths_reach_typed_collections(xml, collection, object_name):
    config = build_panos_config(f"<config><shared>{xml}</shared></config>")
    assert [item.name for item in getattr(config, collection)] == [object_name]


def test_active_excel_sheets_have_headers_and_row_generation_paths():
    outside_row_writers = {"Summary"}
    for sheet in ACTIVE_SHEET_ORDER:
        assert sheet in SHEET_HEADERS
        assert sheet in outside_row_writers or sheet in ROW_BUILDERS


def test_implemented_source_sheets_do_not_use_empty_placeholder_builders():
    for sheet, status in SHEET_IMPLEMENTATION_STATUS.items():
        if status != "IMPLEMENTED" or sheet == "Summary":
            continue
        assert sheet in ROW_BUILDERS
        source = textwrap.dedent(inspect.getsource(ROW_BUILDERS[sheet])).strip().rstrip(",")
        if not source.startswith(("def ", "async def ")):
            source = f"{{{source}}}"
        tree = ast.parse(source)
        assert not any(
            isinstance(node, ast.Lambda)
            and isinstance(node.body, ast.List)
            and not node.body.elts
            for node in ast.walk(tree)
        )


def test_not_implemented_sheets_need_no_row_builder():
    assert SHEET_IMPLEMENTATION_STATUS["Route Path Monitors"] == "IMPLEMENTED"
    assert "Route Path Monitors" in ROW_BUILDERS


def test_failed_typed_extraction_preserves_inventory_and_later_objects():
    config = build_panos_config("""<config><shared><network><sdwan>
      <traffic-distribution-profile>
        <entry name='malformed'><link><entry><weight><member>not-a-scalar</member></weight></entry></link></entry>
        <entry name='valid'><distribution-mode>weighted</distribution-mode></entry>
      </traffic-distribution-profile>
    </sdwan><address><entry name='later-address'><ip-netmask>192.0.2.1</ip-netmask></entry></address></network></shared></config>""")
    inventory_names = {item.name for item in config.source_inventory}
    assert {"malformed", "valid", "later-address"} <= inventory_names
    assert config.unknown_paths
    assert any("traffic-distribution-profile/entry" in path for path in config.unknown_paths)
    assert [item.name for item in config.sdwan_traffic_distribution_profiles] == ["valid"]
    assert [item.name for item in config.addresses] == ["later-address"]
    issue = config.extraction_issues[0]
    assert (issue.source_name, issue.domain, issue.exception_type) == ("malformed", "sdwan_traffic_distribution_profile", "ValidationError")
    assert issue.source_path.endswith("traffic-distribution-profile/entry")
    assert issue.scope == config.source_inventory[1].scope
    assert "not-a-scalar" in issue.message
    from fwmigrate.vendors.palo_alto.native import build_derived_views, validate_panos_config
    validation = validate_panos_config(config, build_derived_views(config))
    assert any(item.severity == "warning" and item.domain == "extraction" and item.source_name == "malformed" for item in validation.issues)
