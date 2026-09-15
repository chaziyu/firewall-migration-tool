import argparse

from fwmigrate.core.registry import PluginRegistry

from benchmarks.utils import fixture_path, measure, print_result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=5)
    args = parser.parse_args()
    content = fixture_path("example_cisco_asa.cfg").read_text(encoding="utf-8")
    source_parser = PluginRegistry.get_parser("cisco_asa")
    result = measure("cisco_asa_extraction", lambda: source_parser.extract(content), args.iterations)
    print_result(result)


if __name__ == "__main__":
    main()
