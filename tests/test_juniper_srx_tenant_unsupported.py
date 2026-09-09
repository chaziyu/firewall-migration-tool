from fwmigrate.parsers.juniper_srx import JuniperSRXParser


def test_unsupported_tenant_hierarchy_keeps_tenant_ownership():
    parser = JuniperSRXParser("deactivate tenants TSYS1 services unsupported-service foo\nset tenants TSYS1 services another-unsupported foo\n")
    result = parser.extract()

    assert any(item.source_context == "TSYS1" for item in result.unsupported_items)
    assert all(item.source_context != "root" for item in result.unsupported_items)
    assert any("tenants TSYS1 services" in section.path for section in result.source_sections)
    assert any(command.source_context == "TSYS1" for item in result.inventory_items for command in item.commands)
