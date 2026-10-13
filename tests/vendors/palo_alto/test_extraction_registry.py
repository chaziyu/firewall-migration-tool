import pytest

from fwmigrate.vendors.palo_alto.extraction.extractor import registered_typed_collections
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config
from fwmigrate.vendors.palo_alto.model.source import PANOSConfig


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


