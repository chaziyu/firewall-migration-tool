"""Offline FortiGate to Cisco ASA CLI export."""

import hashlib
import json
from io import BytesIO
from pathlib import Path

import click
import yaml

from fwmigrate.collection.snapshot import sanitize_source
from fwmigrate.source_reporting import source_reporters

from ..rendering.renderer import ASACLIRenderer
from .workflow import build_review


def run_cli(*, input_path, output_path, format, mapping_path, target_config_path):
    if format != "cfg":
        raise click.ClickException("Use --format cfg for FortiGate to Cisco ASA")
    mapping = {}
    if mapping_path:
        try:
            mapping = yaml.safe_load(Path(mapping_path).read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise click.ClickException("Target mapping YAML is invalid") from exc
        if not isinstance(mapping, dict):
            raise click.ClickException("Target mapping YAML must contain an object")
    target_metadata = mapping.pop("target_evidence", None)
    source_text = sanitize_source("fortigate", Path(input_path).read_text(encoding="utf-8"))
    analysis = source_reporters.get("fortigate").analyze_source(source_text)
    source_digest = hashlib.sha256(source_text.encode("utf-8") + b"\0fortigate").hexdigest()
    target = target_text = None
    if target_config_path:
        target_text = sanitize_source("cisco_asa", Path(target_config_path).read_text(encoding="utf-8"))
        target = source_reporters.get("cisco_asa").analyze_source(target_text)
        if not isinstance(target_metadata, dict):
            raise click.ClickException("--target-config requires target_evidence context, version, mode, and complete_families in --zone-map")
    elif target_metadata is not None:
        raise click.ClickException("target_evidence metadata requires --target-config")
    try:
        review = build_review(analysis, mapping, source_digest, target=target,
                              target_source_text=target_text, target_metadata=target_metadata)
    except (TypeError, ValueError, KeyError) as exc:
        raise click.ClickException("Invalid FortiGate to Cisco ASA migration input or mappings") from exc
    rendered = ASACLIRenderer().render(review["plan"])
    folder = Path(output_path)
    ASACLIRenderer().write_files(rendered, folder)
    (folder / "migration_decisions.json").write_text(
        json.dumps({"envelope_type": "fortigate_to_cisco_asa_mapping_v1",
                    "source_vendor": "fortigate", "target_vendor": "cisco_asa",
                    "source_digest": source_digest, "options": review["options"].to_dict()}, indent=2),
        encoding="utf-8")
    (folder / "target_mapping.yaml").write_text(yaml.safe_dump(review["options"].to_dict(), sort_keys=False), encoding="utf-8")
    workbook = BytesIO()
    source_reporters.get("fortigate").export_excel(analysis, workbook, source_name=Path(input_path).name)
    (folder / "source_inventory.xlsx").write_bytes(workbook.getvalue())
    report = {**rendered.report, **{key: value for key, value in review["report"].items()
                                    if key in {"destination_snapshot_compared", "snapshot_evidence_complete", "coverage"}}}
    (folder / "migration_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    click.echo(f"Generated {rendered.command_count} ASA configuration lines in {output_path}")
    click.echo(f"Plan status: {report['plan_status']}; ASA device execution is disabled")
