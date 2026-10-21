"""Offline PAN-OS to Check Point review-file generation."""

import hashlib
import json
from pathlib import Path

import click
import yaml

from fwmigrate.collection.snapshot import sanitize_source
from fwmigrate.source_reporting import source_reporters

from .workflow import build_review, export_decisions
from ..rendering.management import CPManagementRenderer


def run_cli(*, input_path, output_path, format, mapping_path, target_config_path):
    if format != "json":
        raise click.ClickException("Use --format json for PAN-OS to Check Point")
    mappings = {}
    if mapping_path:
        try:
            mappings = yaml.safe_load(Path(mapping_path).read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise click.ClickException("Check Point target mapping YAML is invalid") from exc
        if not isinstance(mappings, dict):
            raise click.ClickException("Check Point target mapping YAML must contain an object")
    metadata = mappings.pop("target_evidence", None)
    target = target_text = None
    if target_config_path:
        try:
            target_text = sanitize_source("checkpoint", Path(target_config_path).read_text(encoding="utf-8"))
            target = source_reporters.get("checkpoint").analyze_source(target_text)
        except (ValueError, TypeError, KeyError) as exc:
            raise click.ClickException("Invalid Check Point destination snapshot") from exc
        if not isinstance(metadata, dict):
            raise click.ClickException("--target-config requires target_evidence in the mapping document")
    elif metadata is not None:
        raise click.ClickException("target_evidence requires --target-config")
    source_text = sanitize_source("palo_alto", Path(input_path).read_text(encoding="utf-8"))
    source_digest = hashlib.sha256(source_text.encode("utf-8") + b"\0palo_alto").hexdigest()
    analysis = source_reporters.get("palo_alto").analyze_source(source_text)
    try:
        review = build_review(analysis, mappings, source_digest, target=target,
                              target_source_text=target_text, target_metadata=metadata)
    except (KeyError, TypeError, ValueError) as exc:
        raise click.ClickException("Invalid PAN-OS to Check Point source or mappings") from exc
    rendered = CPManagementRenderer().render(review["plan"])
    folder = Path(output_path)
    CPManagementRenderer().write_files(rendered, folder)
    (folder / "migration_decisions.json").write_text(
        json.dumps(export_decisions(source_digest, review["options"].to_dict()),
                   ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8")
    report = {**review["report"], **rendered.report, "coverage": review["report"]["coverage"],
              "destination_snapshot_compared": target is not None, "target_digest": review["draft"].get("target_digest"),
              "source_digest": source_digest,
              "approval_required_for_web_download": True,
              "cli_output_is_unapproved_review_material": True}
    (folder / "migration_report.json").write_text(
        json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    click.echo(f"Generated {rendered.operation_count} Management API request templates and {rendered.gaia_command_count} Gaia commands in {output_path}")
    click.echo(f"Plan status: {report['plan_status']}; Check Point requests are not executed")
