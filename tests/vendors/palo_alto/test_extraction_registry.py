from io import BytesIO

from openpyxl import load_workbook
import pytest

from fwmigrate.vendors.palo_alto.export.excel import export_panos_excel
from fwmigrate.vendors.palo_alto.export.excel_rows import ROW_BUILDERS, _PANExcelContext, _TYPED_COUNT_FIELDS, _typed_counts
from fwmigrate.vendors.palo_alto.export.excel_schema import SHEET_ORDER, SHEET_HEADERS
from fwmigrate.vendors.palo_alto.extraction.extractor import _EXTRACTORS, registered_typed_collections
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config
from fwmigrate.vendors.palo_alto.model.source import PANOSConfig
from fwmigrate.vendors.palo_alto.schema_registry import registered_paths
from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter


def test_registered_collections_are_unique_and_initialized():
    names = list(registered_typed_collections())
    assert len(names) == len(set(names))
    config = PANOSConfig()
    assert all(hasattr(config, name) and isinstance(getattr(config, name), list) for name in names)


def test_registered_collections_are_deterministic():
    first = registered_typed_collections()
    second = registered_typed_collections()
    assert first == second


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


def test_registered_typed_collections_are_unique_and_deterministic():
    collections = registered_typed_collections()
    assert collections == tuple(sorted(set(collections)))
    assert collections == tuple(sorted({collection for collection, _ in _EXTRACTORS.values()}))


def test_extractor_destinations_are_list_fields_on_panos_config():
    config = PANOSConfig()
    assert all(isinstance(getattr(config, collection), list) for collection in registered_typed_collections())


def test_registered_paths_are_represented_in_coverage_counts():
    assert set(registered_paths()) <= set(_TYPED_COUNT_FIELDS)
    assert set(registered_typed_collections()) <= set(_TYPED_COUNT_FIELDS.values())


def test_coverage_counts_include_new_typed_domains():
    analysis = PaloAltoSourceReporter().analyze_source("""<config><shared><network>
      <dhcp><entry name='dhcp-main'/></dhcp>
      <sdwan><rules><entry name='rule-main'/></rules></sdwan>
      <global-protect><portal><entry name='portal-main'/></portal></global-protect>
    </network></shared></config>""")

    counts = _typed_counts(_PANExcelContext(analysis))
    assert counts["dhcp_server"] == 1
    assert counts["sdwan_rule"] == 1
    assert counts["globalprotect_portal"] == 1


def test_crypto_profiles_are_counted_in_registered_source_domains():
    analysis = PaloAltoSourceReporter().analyze_source("""<config><shared><network><ike><crypto-profiles>
      <ike-crypto-profiles><entry name='ike'/></ike-crypto-profiles>
      <ipsec-crypto-profiles><entry name='ipsec'/></ipsec-crypto-profiles>
    </crypto-profiles></ike></network></shared></config>""")
    context = _PANExcelContext(analysis)
    for domain in ("ike_crypto_profile", "ipsec_crypto_profile"):
        assert (context.source_domains[domain], context.extracted_domains[domain]) == (1, 1)
        assert _typed_counts(context)[domain] == 1


def test_source_builder_initializes_all_registered_collections():
    config = build_panos_config("<config />")
    assert all(isinstance(getattr(config, collection), list) for collection in registered_typed_collections())


def test_registered_source_path_reaches_expected_collection():
    config = build_panos_config(
        "<config><shared><tag><entry name='production'><color>red</color><comments>keep</comments></entry></tag></shared></config>"
    )
    assert config.tags[0].name == "production"
    assert config.tags[0].color == "red"


def test_active_excel_sheets_have_headers_and_row_generation_paths():
    assert set(SHEET_ORDER) <= set(SHEET_HEADERS)
    assert set(SHEET_ORDER) - {"Summary"} <= set(ROW_BUILDERS)


def test_tags_sheet_is_active_and_exports_rows():
    reporter = PaloAltoSourceReporter()
    analysis = reporter.analyze_source(
        "<config><shared><tag><entry name='production'><color>red</color><comments>keep</comments></entry></tag></shared></config>"
    )
    output = BytesIO()
    export_panos_excel(analysis, output)
    workbook = load_workbook(BytesIO(output.getvalue()), data_only=True)
    sheet = workbook["Tags"]
    headers = {cell.value: cell.column for cell in sheet[3]}
    assert sheet.cell(4, headers["Name"]).value == "production"
    assert sheet.cell(4, headers["Color"]).value == "red"
    assert sheet.cell(4, headers["Comments"]).value == "keep"


