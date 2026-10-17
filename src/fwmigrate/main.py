import hashlib
import click
import yaml

from fwmigrate.source_reporting.builtin import register_builtin_source_reporters
from fwmigrate.source_reporting import source_reporters
from fwmigrate.conversion.builtin import register_builtin_migration_planners, register_builtin_migration_workflows
from fwmigrate.conversion.workflow_registry import migration_workflows
from fwmigrate.conversion.fortigate_to_palo_alto import (
    PANAutomationMode,
    PANMigrationOptions,
    run_migration_pipeline,
)
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_suggestions import target_devices
from fwmigrate.conversion.palo_alto_to_fortigate.application import run_migration_pipeline as run_reverse_pipeline, write_files as write_reverse_files
from fwmigrate.collection.snapshot import sanitize_source

register_builtin_source_reporters()
register_builtin_migration_planners()
register_builtin_migration_workflows()

@click.group()
def cli():
    """Universal Multi-Vendor Firewall Migration Platform."""
    pass

@cli.command()
def vendors():
    """List all registered source-reporting vendor plugins."""
    click.echo("\n--- Supported Source Vendors ---")
    for s in source_reporters.list():
        click.echo(
            f"  • {s.vendor_id:<15} : {s.display_name} "
            f"(Ext: {', '.join(s.supported_extensions)})"
        )

    click.echo("\nMigration planning: FortiGate -> Palo Alto PAN-OS / Juniper SRX / Cisco ASA / Check Point; Palo Alto PAN-OS -> FortiGate (CLI export)")

@cli.command()
@click.option('--input', '-i', required=True, type=click.Path(exists=True), help='Vendor-native source configuration file')
@click.option('--output', '-o', required=True, type=click.Path(), help='Output directory')
@click.option('--source-vendor', type=str, default='fortigate', help='Registered source vendor identifier')
@click.option('--target-vendor', type=str, default='palo_alto', help='Registered target vendor identifier')
@click.option('--zone-map', type=click.Path(exists=True), help='YAML file with explicit pair-specific target mappings')
@click.option('--target-config', type=click.Path(exists=True, dir_okay=False), help='Vendor-native target configuration evidence')
@click.option('--target-device', type=str, help='Target PAN-OS device/serial when XML contains more than one device')
@click.option('--target-intent', type=click.Path(exists=True, dir_okay=False), help='Engineer target-intent YAML')
@click.option(
    '--automation-mode',
    type=click.Choice([item.value for item in PANAutomationMode], case_sensitive=False),
    default=PANAutomationMode.VERIFIED_AND_DERIVED.value,
    show_default=True,
    help='Deterministic mapping automation policy',
)
@click.option('--format', type=click.Choice(['xml', 'set', 'cli', 'cfg', 'bundle', 'json']), default='set', show_default=True, help='Output format')
@click.pass_context
def migrate(ctx, input, output, source_vendor, target_vendor, zone_map, target_config,
            target_device, target_intent, automation_mode, format):
    """Plan and render a supported directional migration pair."""
    pair = (source_vendor.casefold(), target_vendor.casefold())
    if pair not in {("fortigate", "palo_alto"), ("palo_alto", "fortigate")}:
        try:
            workflow = migration_workflows.get(source_vendor, target_vendor)
        except KeyError as exc:
            raise click.ClickException("Migration pair is not implemented") from exc
        explicit_pan_options = any(
            ctx.get_parameter_source(name).name != "DEFAULT"
            for name in ("target_device", "target_intent", "automation_mode")
        )
        if explicit_pan_options:
            raise click.ClickException("--target-device, --target-intent and --automation-mode are PAN-OS-specific options")
        if not workflow.export_available or workflow.cli_application is None:
            raise click.ClickException("Migration pair is registered but its CLI export is not available")
        if format not in workflow.supported_formats:
            raise click.ClickException(
                f"Use --format {' or '.join(workflow.supported_formats)} for {workflow.source_vendor} -> {workflow.target_vendor}"
            )
        workflow.cli_application(
            input_path=input,
            output_path=output,
            format=format,
            mapping_path=zone_map,
            target_config_path=target_config,
        )
        return
    if format != ("cli" if pair[0] == "palo_alto" else "set"):
        raise click.ClickException("Use --format cli for FortiGate output or --format set for PAN-OS output")

    mapping = {}
    if zone_map:
        with open(zone_map, encoding="utf-8") as stream:
            mapping = yaml.safe_load(stream) or {}
        if not isinstance(mapping, dict):
            raise click.ClickException("Target mapping YAML must contain an object")

    if pair == ("palo_alto", "fortigate"):
        if target_device or target_intent:
            raise click.ClickException("Reverse-pair target choices belong in --zone-map; target-device and target-intent are PAN-OS target options")
        try:
            with open(input, encoding="utf-8") as stream:
                reverse_source = source_reporters.get("palo_alto").analyze_source(sanitize_source("palo_alto", stream.read()))
            reverse_target = None
            target_digest = None
            if target_config:
                with open(target_config, encoding="utf-8") as stream:
                    text = sanitize_source("fortigate", stream.read())
                reverse_target = source_reporters.get("fortigate").analyze_source(text)
                target_digest = hashlib.sha256(text.encode() + b"\0fortigate").hexdigest()
            _, rendered, _ = run_reverse_pipeline(reverse_source, mapping, target=reverse_target, target_digest=target_digest)
            write_reverse_files(rendered, output)
        except (ValueError, TypeError, KeyError) as exc:
            raise click.ClickException("Invalid PAN-OS to FortiGate migration input or mappings") from exc
        click.echo(f"Generated {len(rendered.commands)} CLI lines in {output}")
        click.echo(f"Plan status: {rendered.report['plan_status']}; FortiGate live deployment is disabled")
        return

    intent = None
    if target_intent:
        with open(target_intent, encoding="utf-8") as stream:
            intent = stream.read()

    with open(input, encoding="utf-8") as stream:
        analysis = source_reporters.get("fortigate").analyze_source(stream.read())

    target = None
    selected_device = None
    target_evidence = None
    if target_config:
        with open(target_config, encoding="utf-8") as stream:
            target_text = stream.read()
        target = source_reporters.get("palo_alto").analyze_source(target_text)
        target_digest = hashlib.sha256()
        target_digest.update(target_text.encode("utf-8"))
        target_digest.update(b"\0")
        target_digest.update(b"palo_alto")
        devices = target_devices(target)
        selected_device = target_device or (devices[0] if len(devices) == 1 else None)
        if target_device and target_device not in devices:
            raise click.ClickException("Selected target device is not present in the PAN-OS XML")
        if len(devices) > 1 and not selected_device:
            raise click.ClickException(
                "PAN-OS XML contains multiple devices; specify --target-device explicitly"
            )
        target_evidence = {
            "vendor": "palo_alto",
            "config_digest": target_digest.hexdigest(),
            "device": selected_device,
        }
    elif target_device:
        raise click.ClickException("--target-device requires --target-config")

    result = run_migration_pipeline(
        analysis.extracted.config,
        analysis.derived,
        options=PANMigrationOptions(**mapping),
        target=target,
        target_device=selected_device,
        target_evidence=target_evidence,
        target_intent=intent,
        automation_mode=PANAutomationMode(automation_mode.upper()),
    )
    PANSetRenderer().write_files(result.rendered, output)
    click.echo(f"Generated {len(result.rendered.commands)} commands in {output}")
    click.echo(f"Plan status: {result.artifact_status}")
    click.echo(f"Validation findings: {len(result.validation.issues)}")
    click.echo(f"Unresolved required mappings: {len(result.unresolved_decisions)}")

@cli.command()
@click.argument('commands_file', type=click.Path(exists=True, dir_okay=False))
@click.option('--host', required=True)
@click.option('--port', default=22, show_default=True, type=click.IntRange(1, 65535))
@click.option('--username', required=True)
@click.option('--password', hide_input=True, help='Ignored; CLI deployment is disabled.')
def deploy(commands_file, host, port, username, password):
    """Disabled: use the reviewed web candidate workflow."""
    raise click.ClickException('CLI deployment is disabled. Use the web workflow to approve the design, prepare and validate the candidate, then explicitly commit.')

@cli.command()
@click.option('--host', required=True)
@click.option('--port', default=22, show_default=True, type=click.IntRange(1, 65535))
@click.option('--username', required=True)
@click.option('--password', hide_input=True, help='Ignored; CLI commit is disabled.')
def commit(host, port, username, password):
    """Disabled: use the reviewed web candidate workflow."""
    raise click.ClickException('CLI commit is disabled. Use the web workflow to commit an artifact-bound validated candidate.')

@cli.command()
@click.option('--port', default=5000, help='Port to run the web server on')
@click.option('--host', default='127.0.0.1', show_default=True,
              help='Interface to bind. Live device access is available only on loopback.')
def serve(port, host):
    """Start the migration web interface."""
    from fwmigrate.web import create_app

    app = create_app({'WEB_MODE': 'local' if host in {'127.0.0.1', '::1', 'localhost'} else 'public'})
    click.echo(f"Starting web server on http://{host}:{port}")
    app.run(host=host, port=port, debug=False)

if __name__ == '__main__':
    cli()
