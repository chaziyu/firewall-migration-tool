import argparse

from fwmigrate.core.optimizer import RuleOptimizer
from fwmigrate.ir.dependency import DependencyGraph
from fwmigrate.ir.index import IRIndex

from benchmarks.fixtures import build_ir
from benchmarks.utils import measure, print_result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scale", type=int, default=1000)
    parser.add_argument("--iterations", type=int, default=5)
    args = parser.parse_args()
    ir = build_ir(args.scale)
    for name, operation in (
        ("index_build", lambda: IRIndex.build(ir)),
        ("dependency_build", lambda: DependencyGraph(ir).build()),
        ("optimizer_unused_objects", lambda: RuleOptimizer(ir).find_unused_objects()),
        ("optimizer_prune", lambda: RuleOptimizer(ir).prune_unused_objects()),
    ):
        print_result(measure(name, operation, args.iterations))


if __name__ == "__main__":
    main()
