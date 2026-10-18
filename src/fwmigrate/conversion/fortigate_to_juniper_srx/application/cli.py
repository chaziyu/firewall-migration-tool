"""Offline FortiGate to Juniper SRX CLI export."""

from pathlib import Path
import hashlib

import click
import yaml

from fwmigrate.collection.snapshot import sanitize_source
from fwmigrate.source_reporting import source_reporters

from .workflow import build_review, run_migration_pipeline, write_files
from ..rendering.renderer import JunosSetRenderer


def run_cli(*, input_path, output_path, format, mapping_path, target_config_path):
    if format != "set":
        raise click.ClickException("Use --format set for FortiGate to Juniper SRX")
    mapping = {}
    if mapping_path:
        try:
            mapping = yaml.safe_load(Path(mapping_path).read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise click.ClickException("Target mapping YAML is invalid") from exc
        if not isinstance(mapping, dict):
            raise click.ClickException("Target mapping YAML must contain an object")
    target_metadata = mapping.pop("target_evidence", None)
    if target_config_path and not isinstance(target_metadata, dict):
        raise click.ClickException(
            "--target-config requires target_evidence metadata in --zone-map with context, version, mode and complete_families"
        )
    if not target_config_path and target_metadata is not None:
        raise click.ClickException("target_evidence metadata requires --target-config")

    source_text = sanitize_source("fortigate", Path(input_path).read_text(encoding="utf-8"))
    analysis = source_reporters.get("fortigate").analyze_source(source_text)
    source_digest = hashlib.sha256(source_text.encode("utf-8") + b"\0fortigate").hexdigest()
    try:
        if target_config_path:
            target_text = sanitize_source(
                "juniper_srx", Path(target_config_path).read_text(encoding="utf-8"),
            )
            target = source_reporters.get("juniper_srx").analyze_source(target_text)
            review = build_review(
                analysis, mapping, source_digest, target=target,
                target_source_text=target_text, target_metadata=target_metadata,
            )
            plan = review["plan"]
            options = review["options"]
            rendered = JunosSetRenderer().render(plan)
            report = write_files(
                plan, rendered, output_path, source_digest, options,
                destination_report=review["report"], target_digest=review["draft"]["target_digest"],
                analysis=analysis,
            )
        else:
            plan, rendered, options = run_migration_pipeline(analysis, mapping)
            report = write_files(plan, rendered, output_path, source_digest, options, analysis=analysis)
    except (TypeError, ValueError, KeyError) as exc:
        raise click.ClickException("Invalid FortiGate to Juniper SRX migration input or mappings") from exc
    click.echo(f"Generated {rendered.command_count} Junos set lines in {output_path}")
    click.echo(f"Plan status: {report['plan_status']}")
    click.echo("SRX output is an offline reviewed export; live deployment is disabled")
