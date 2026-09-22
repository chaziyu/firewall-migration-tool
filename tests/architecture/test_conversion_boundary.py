from fwmigrate.conversion import ConversionRegistry


class _Converter:
    source_vendor = "cisco_asa"
    target_vendor = "fortigate"


def test_future_conversion_registry_is_directional_and_empty_by_default():
    registry = ConversionRegistry()
    converter = _Converter()

    registry.register(converter)

    assert registry.get("CISCO_ASA", "FortiGate") is converter


def test_unimplemented_conversion_pair_fails_closed():
    try:
        ConversionRegistry().get("cisco_asa", "fortigate")
    except KeyError as exc:
        assert "cisco_asa_to_fortigate" in str(exc)
    else:
        raise AssertionError("unimplemented conversion pair must not be available")
