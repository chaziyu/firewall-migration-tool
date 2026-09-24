from fwmigrate.vendors.juniper_srx.source_report import extract_juniper_source


def test_deactivated_value_is_retained_in_source_but_marked_inactive():
    result = extract_juniper_source("""set interfaces ge-0/0/0 description WAN
deactivate interfaces ge-0/0/0 description
""")

    interface = result.config.get_context().interfaces["ge-0/0/0"]
    assert interface.description == "WAN"
    assert any(item.operation == "deactivate" and item.hierarchy_path == (
        "interfaces", "ge-0/0/0", "description"
    ) for item in result.config.activation_directives)
    assert not any(item.get("origin") == "local" and item.get("value") == "WAN"
                   and item.get("status") == "EFFECTIVE"
                   for item in result.derived.inheritance_view["effective_statements"])


def test_explicit_disable_is_not_treated_as_deactivation():
    result = extract_juniper_source("set interfaces ge-0/0/0 disable")

    interface = result.config.get_context().interfaces["ge-0/0/0"]
    assert interface.disabled is True
    assert result.config.activation_directives == []
