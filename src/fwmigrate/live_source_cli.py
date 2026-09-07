from __future__ import annotations

from pathlib import Path

import click

from fwmigrate.collectors.fortigate import FortiGateSSHCollector
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.report.excel_exporter import IRExcelExporter

# Ensure built-in parsers are registered when this entry point is invoked directly.
import fwmigrate.parsers  # noqa: F401,E402


@click.command()
@click.option("--host", required=True, help="FortiGate management hostname or IP.")
@click.option("--port", default=22, show_default=True, type=int)
@click.option("--username", required=True)
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=False)
@click.option("--verify-host-key/--no-verify-host-key", default=False, show_default=True)
@click.option("--output", "output_path", default="fortigate_source_inventory.xlsx", show_default=True, type=click.Path(path_type=Path))
def main(host: str, port: int, username: str, password: str, verify_host_key: bool, output_path: Path) -> None:
    """Pull a FortiGate full configuration over SSH and write source inventory Excel."""
    collector = FortiGateSSHCollector(
        host=host,
        port=port,
        username=username,
        password=password,
        verify_host_key=verify_host_key,
    )
    snapshot = collector.collect()
    if not snapshot.complete:
        details = "; ".join(snapshot.errors or snapshot.warnings) or "unknown collection failure"
        raise click.ClickException(f"Source collection incomplete: {details}")

    extraction = PluginRegistry.get_parser("fortigate").extract(snapshot.raw_config)
    ir_config = extraction.canonical_ir
    ir_config.metadata.input_type = "Live SSH Collection"
    metadata = dict(ir_config.metadata.source_attributes or {})
    metadata["live_collection"] = {
        "vendor": snapshot.vendor,
        "hostname": snapshot.hostname,
        "software_version": snapshot.software_version,
        "collection_method": snapshot.collection_method,
        "commands_executed": snapshot.commands_executed,
        "collected_at": snapshot.collected_at.isoformat(),
        "complete": snapshot.complete,
        "warnings": snapshot.warnings,
        "sha256": snapshot.sha256,
        "raw_config_bytes": len(snapshot.raw_config.encode("utf-8")),
    }
    ir_config.metadata.source_attributes = metadata

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(IRExcelExporter(ir_config, extraction_result=extraction).generate())
    click.echo(f"Inventory written: {output_path}")
    click.echo(f"Source SHA-256: {snapshot.sha256}")
    click.echo(f"Collection complete: {snapshot.complete}")


if __name__ == "__main__":
    main()
