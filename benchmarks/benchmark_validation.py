import argparse

from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir import IRAddress, IRConfig, IRMetadata
from fwmigrate.ir.enums import AddressType
from fwmigrate.validation.validators import DependencyValidator, SemanticValidator

from benchmarks.utils import fixture_path, measure, print_result


def build_validation_ir(scale: int) -> IRConfig:
    addresses = []
    for index in range(scale):
        if index % 2:
            value = f"2001:db8::{index}/128"
        else:
            ipv4_index = index // 2
            value = f"198.18.{ipv4_index // 254}.{ipv4_index % 254 + 1}/32"
        if index and index % 1000 == 0:
            value = addresses[index - 2].value
        addresses.append(IRAddress(
            name=f"benchmark-address-{index}",
            type=AddressType.NETWORK,
            value=value,
        ))
    return IRConfig(metadata=IRMetadata(hostname=f"validation-{scale}"), addresses=addresses)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=5)
    args = parser.parse_args()
    content = fixture_path("example_cisco_asa.cfg").read_text(encoding="utf-8")
    ir = PluginRegistry.get_parser("cisco_asa").extract(content).canonical_ir
    for name, validator in (
        ("dependency_validation", DependencyValidator()),
        ("semantic_validation", SemanticValidator()),
    ):
        print_result(measure(name, lambda validator=validator: validator.validate(ir), args.iterations))

    for scale in (1000, 5000, 10000):
        validation_ir = build_validation_ir(scale)
        print_result(measure(
            f"semantic_validation_{scale}_addresses",
            lambda validation_ir=validation_ir: SemanticValidator().validate(validation_ir),
            args.iterations,
        ))


if __name__ == "__main__":
    main()
