import hashlib
import click
import yaml

from fwmigrate.source_reporting.builtin import register_builtin_source_reporters
from fwmigrate.source_reporting import source_reporters
from fwmigrate.conversion.builtin import register_builtin_migration_planners
from fwmigrate.conversion.fortigate_to_palo_alto import (
    PANAutomationMode,
    PANMigrationOptions,
    run_migration_pipeline,
)
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_suggestions import target_devices

register_builtin_source_reporters()
register_builtin_migration_planners()

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

    click.echo("\nMigration planning: FortiGate -> Palo Alto PAN-OS")

@cli.command()
@click.option('--input', '-i', required=True, type=click.Path(exists=True), help='Input FortiGate configuration file')
@click.option('--output', '-o', required=True, type=click.Path(), help='Output directory')
@click.option('--source-vendor', type=str, default='fortigate', help='Registered source vendor identifier')
@click.option('--target-vendor', type=str, default='palo_alto', help='Registered target vendor identifier')
@click.option('--zone-map', type=click.Path(exists=True), help='YAML file with explicit pair-specific target mappings')
@click.option('--target-config', type=click.Path(exists=True, dir_okay=False), help='PAN-OS XML used as target evidence')
@click.option('--target-device', type=str, help='Target PAN-OS device/serial when XML contains more than one device')
@click.option('--target-intent', type=click.Path(exists=True, dir_okay=False), help='Engineer target-intent YAML')
@click.option(
    '--automation-mode',
    type=click.Choice([item.value for item in PANAutomationMode], case_sensitive=False),
    default=PANAutomationMode.VERIFIED_AND_DERIVED.value,
    show_default=True,
    help='Deterministic mapping automation policy',
)
@click.option('--format', type=click.Choice(['xml', 'set', 'cli']), default='set', show_default=True, help='Output format')
def migrate(input, output, source_vendor, target_vendor, zone_map, target_config,
            target_device, target_intent, automation_mode, format):
    """Plan and render the supported FortiGate -> PAN-OS migration."""
    if (source_vendor.casefold(), target_vendor.casefold()) != ("fortigate", "palo_alto"):
        raise click.ClickException("Only fortigate -> palo_alto is supported")
    if format != "set":
        raise click.ClickException("The MVP supports only --format set")

    mapping = {}
    if zone_map:
        with open(zone_map, encoding="utf-8") as stream:
            mapping = yaml.safe_load(stream) or {}
        if not isinstance(mapping, dict):
            raise click.ClickException("Target mapping YAML must contain an object")

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
    """Disabled: use the reviewed web or desktop candidate workflow."""
    raise click.ClickException('CLI deployment is disabled. Use the web or desktop workflow to approve the design, prepare and validate the candidate, then explicitly commit.')

@cli.command()
@click.option('--host', required=True)
@click.option('--port', default=22, show_default=True, type=click.IntRange(1, 65535))
@click.option('--username', required=True)
@click.option('--password', hide_input=True, help='Ignored; CLI commit is disabled.')
def commit(host, port, username, password):
    """Disabled: use the reviewed web or desktop candidate workflow."""
    raise click.ClickException('CLI commit is disabled. Use the web or desktop workflow to commit an artifact-bound validated candidate.')

@cli.command()
@click.option('--port', default=5000, help='Port to run the web server on')
@click.option('--host', default='127.0.0.1', show_default=True,
              help='Interface to bind. Remote live collection remains disabled unless explicitly enabled.')
def serve(port, host):
    """Start the migration web interface."""
    from fwmigrate.web import create_app

    app = create_app()
    click.echo(f"Starting web server on http://{host}:{port}")
    app.run(host=host, port=port, debug=False)

if __name__ == '__main__':
    cli()
