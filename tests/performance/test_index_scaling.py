from fwmigrate.ir import IRAddress, IRConfig, IRIndex, IRMetadata
from fwmigrate.ir.enums import AddressType


def test_index_builds_linearly_for_deterministic_fixture():
    ir = IRConfig(
        metadata=IRMetadata(hostname="scale-test"),
        addresses=[
            IRAddress(name=f"address-{i}", type=AddressType.HOST, subnet=f"192.0.2.{i % 254 + 1}/32")
            for i in range(200)
        ],
    )

    index = IRIndex.build(ir)

    assert len(index.by_name["addresses"]) == 200
