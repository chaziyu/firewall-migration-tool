"""Offline PAN-OS to Juniper SRX CLI export."""

import hashlib
import json
from pathlib import Path

import click
import yaml

from fwmigrate.collection.snapshot import sanitize_source
from fwmigrate.source_reporting import source_reporters

from ..options import SRXMigrationOptions
from ..planner import PaloAltoToJuniperSRXPlanner
from ..rendering.renderer import JunosSetRenderer
from ..review.coverage import build_coverage
from ..review.workflow import build_review_report
from ..target.evidence import build_target_evidence
from ..target.comparison import classify_target_reuse


def run_cli(*, input_path, output_path, format, mapping_path, target_config_path):
    if format != "set":
        raise click.ClickException("Use --format set for PAN-OS to Juniper SRX")
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
        options = SRXMigrationOptions(**options_data)
        plan = PaloAltoToJuniperSRXPlanner().plan(analysis.config, analysis.derived, options)
        target_digest = None
        if target_config_path:
            target_text = sanitize_source("juniper_srx", Path(target_config_path).read_text(encoding="utf-8"))
            target = source_reporters.get("juniper_srx").analyze_source(target_text)
            evidence = build_target_evidence(target, target_text, target_metadata, options)
            plan = type(plan)(plan.source_scope, plan.target_context, plan.target_version,
                              classify_target_reuse(plan, evidence), plan.findings)
            target_digest = evidence.digest
        rendered = JunosSetRenderer().render(plan)
    except (TypeError, ValueError, KeyError) as exc:
        raise click.ClickException("Invalid PAN-OS to Juniper SRX mapping") from exc
    folder = Path(output_path)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "juniper_config.set").write_bytes(rendered.command_text.encode("utf-8"))
    report = {**build_review_report(plan), "source_digest": source_digest, "target_digest": target_digest,
              "command_count": rendered.command_count, "command_sha256": rendered.command_sha256,
              "coverage": build_coverage(plan, analysis.config.source_inventory),
              "offline_export": True, "deployment_available": False}
    (folder / "migration_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    click.echo(f"Generated {rendered.command_count} Junos set lines in {folder}")
    click.echo(f"Plan status: {report['plan_status']}")
    click.echo("SRX output is an offline export; live deployment is disabled")
