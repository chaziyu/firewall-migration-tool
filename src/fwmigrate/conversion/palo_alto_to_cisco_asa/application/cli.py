"""Offline PAN-OS to Cisco ASA CLI export."""

import hashlib
import json
from pathlib import Path

import click
import yaml

from fwmigrate.collection.snapshot import sanitize_source
from fwmigrate.source_reporting import source_reporters

from ..options import ASAMigrationOptions
from .workflow import build_review
from ..rendering.renderer import ASACLIRenderer
from ..review.coverage import build_coverage
from ..review.workflow import build_review_report


def run_cli(*, input_path, output_path, format, mapping_path, target_config_path):
    if format != "cfg":
        raise click.ClickException("Use --format cfg for PAN-OS to Cisco ASA")
    try:
        options_data = yaml.safe_load(Path(mapping_path).read_text(encoding="utf-8")) if mapping_path else {}
    except yaml.YAMLError as exc:
        raise click.ClickException("Target mapping YAML is invalid") from exc
    if not isinstance(options_data, dict):
        raise click.ClickException("Target mapping YAML must contain an object")
    target_metadata = options_data.pop("target_evidence", None)
    if target_config_path and not isinstance(target_metadata, dict):
        raise click.ClickException("--target-config requires target_evidence metadata in the mapping YAML")
    if not target_config_path and target_metadata is not None:
        raise click.ClickException("target_evidence metadata requires --target-config")
    source_text = sanitize_source("palo_alto", Path(input_path).read_text(encoding="utf-8"))
    analysis = source_reporters.get("palo_alto").analyze_source(source_text)
    source_digest = hashlib.sha256(source_text.encode("utf-8") + b"\0palo_alto").hexdigest()
    try:
        options = ASAMigrationOptions(**options_data)
        target = None
        target_text = None
        if target_config_path:
            target_text = sanitize_source("cisco_asa", Path(target_config_path).read_text(encoding="utf-8"))
            target = source_reporters.get("cisco_asa").analyze_source(target_text)
        review = build_review(analysis, options, source_digest, target=target,
                              target_source_text=target_text, target_metadata=target_metadata)
        plan = review["plan"]
        target_digest = review["draft"].get("target_digest")
        rendered = ASACLIRenderer().render(plan)
    except (TypeError, ValueError, KeyError) as exc:
        raise click.ClickException("Invalid PAN-OS to Cisco ASA mapping") from exc
    folder = Path(output_path)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "asa_config.cfg").write_bytes(rendered.command_text.encode("utf-8"))
    report = {**build_review_report(plan), "source_digest": source_digest, "target_digest": target_digest,
              "command_count": rendered.command_count, "command_sha256": rendered.command_sha256,
              "coverage": build_coverage(plan, analysis.config.source_inventory),
              "offline_export": True, "deployment_available": False}
    (folder / "migration_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    click.echo(f"Generated {rendered.command_count} ASA CLI lines in {folder}")
    click.echo(f"Plan status: {report['plan_status']}")
    click.echo("ASA output is an offline export; live deployment is disabled")
