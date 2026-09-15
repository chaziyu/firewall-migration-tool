import argparse

from fwmigrate.application import MigrationPipeline, MigrationRequest

from benchmarks.utils import fixture_path, measure, print_result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--optimize", action="store_true")
    args = parser.parse_args()
    content = fixture_path("example_cisco_asa.cfg").read_text(encoding="utf-8")
    request = MigrationRequest(
        source_vendor="cisco_asa",
        target_vendor="palo_alto",
        source_content=content,
        target_format="xml",
        optimize=args.optimize,
        prune_unused=args.optimize,
        collect_metrics=True,
    )
    result = measure("pipeline", lambda: MigrationPipeline().run(request), args.iterations)
    print_result(result)
    if result.value.metrics:
        for stage in result.value.metrics.stages:
            print(f"  {stage.stage}: {stage.duration_ms:.3f} ms")


if __name__ == "__main__":
    main()
