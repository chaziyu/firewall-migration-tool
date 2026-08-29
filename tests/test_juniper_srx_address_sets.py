from fwmigrate.core.registry import PluginRegistry
from tests.fixture_paths import JUNIPER_FIXTURES_DIR

def test_nested_address_sets_expansion():
    fixture_path = JUNIPER_FIXTURES_DIR / "address_books.set"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("juniper_srx")
    ir = parser.parse(content)

    grp_dict = {g.name: g for g in ir.address_groups}

    assert "grp_hosts" in grp_dict
    assert "host_ipv4" in grp_dict["grp_hosts"].members
    assert "host_desc" in grp_dict["grp_hosts"].members

    # Nested set expansion
    assert "grp_nested" in grp_dict
    assert "host_ipv4" in grp_dict["grp_nested"].members
    assert "host_desc" in grp_dict["grp_nested"].members
    assert "net_corp" in grp_dict["grp_nested"].members
