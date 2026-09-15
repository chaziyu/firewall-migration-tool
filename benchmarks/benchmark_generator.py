import argparse

from fwmigrate.core.registry import PluginRegistry

from benchmarks.utils import fixture_path, measure, print_result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=5)
    args = parser.parse_args()
    content = fixture_path("example_cisco_asa.cfg").read_text(encoding="utf-8")
    ir = PluginRegistry.get_parser("cisco_asa").extract(content).canonical_ir
    generator = PluginRegistry.get_generator("palo_alto")
    result = measure("palo_alto_xml_generation", lambda: generator.generate(ir, format="xml"), args.iterations)
    print_result(result)


if __name__ == "__main__":
    main()
