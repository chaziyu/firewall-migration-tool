from fwmigrate.ir.address import IRAddress, IRAddressGroup
from fwmigrate.ir.enums import AddressType


def test_address_models_live_in_the_address_domain():
    address = IRAddress(name="web", type=AddressType.HOST, value="10.0.0.1/32")
    group = IRAddressGroup(name="web-group", members=["web"])

    assert address.name == "web"
    assert group.members == ["web"]
    assert IRAddress.__module__ == "fwmigrate.ir.address"

