from fwmigrate.vendors.cisco_asa.source_report import extract_cisco_asa_source


def test_safe_unknown_source_survives_preview_without_becoming_a_model_field():
    result = extract_cisco_asa_source(
        "interface Ethernet0/0\n future-interface-option alpha beta\n"
        "object network WEB\n host 10.0.0.1\n future-object-option one two\n"
    )
    before = result.config.interfaces[0].raw_extra["unmodeled_lines"][:]
    assert "future-interface-option alpha beta" in before
    assert result.config.network_objects[0].raw_lines[-1] == "future-object-option one two"
    assert not hasattr(result.config.interfaces[0], "future_interface_option")
