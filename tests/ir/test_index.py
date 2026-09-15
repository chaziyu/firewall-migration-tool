from fwmigrate.ir import IRAddress, IRAddressGroup, IRConfig, IRIndex, IRMetadata
from fwmigrate.ir.enums import AddressType


def test_index_keeps_duplicate_names_and_supports_ids():
    ir = IRConfig(
        metadata=IRMetadata(hostname="index-test"),
        addresses=[
            IRAddress(name="web", type=AddressType.HOST, subnet="192.0.2.1/32", source_uuid="a"),
            IRAddress(name="web", type=AddressType.HOST, subnet="192.0.2.2/32", source_uuid="b"),
        ],
        address_groups=[IRAddressGroup(name="group", members=["web"])],
    )

    index = IRIndex.build(ir)

    assert len(index.get_by_name("addresses", "web")) == 2
    assert index.get_by_id("addresses", "a")[0].subnet == "192.0.2.1/32"
    assert index.lookup("address_groups", "group")[0].members == ["web"]
