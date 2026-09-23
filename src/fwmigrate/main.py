import os
import sys
import io
import json
import click
import yaml

# Safe stdout/stderr fallback in windowed (GUI) mode
if sys.stdout is None:
    sys.stdout = io.StringIO()
if sys.stderr is None:
    sys.stderr = io.StringIO()

from fwmigrate.source_reporting.builtin import register_builtin_source_reporters
from fwmigrate.source_reporting import source_reporters
from fwmigrate.conversion.builtin import register_builtin_migration_planners
from fwmigrate.conversion import migration_planners
from fwmigrate.conversion.fortigate_to_palo_alto import PANMigrationOptions
from fwmigrate.conversion.fortigate_to_palo_alto.renderer import PANSetRenderer, RenderedMigration
from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan
from fwmigrate.deployment import PANDeploymentOptions, PANSSHDeployer

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

    click.echo("\nMigration planning is temporarily unavailable.")

@cli.command()
@click.option('--input', '-i', required=True, type=click.Path(exists=True), help='Input configuration file (.conf, .cfg, .json, .set)')
@click.option('--output', '-o', required=True, type=click.Path(), help='Output directory')
@click.option('--source-vendor', type=str, default='fortigate', help='Registered source vendor identifier')
@click.option('--target-vendor', type=str, default='palo_alto', help='Registered target vendor identifier')
@click.option('--zone-map', type=click.Path(exists=True), help='YAML file with interface to zone mappings')
@click.option('--format', type=click.Choice(['xml', 'set', 'cli']), default='xml', help='Output format')
@click.option('--optimize', is_flag=True, default=False, help='Prune unused objects and optimize rules')
def migrate(input, output, source_vendor, target_vendor, zone_map, format, optimize):
    """Plan the supported portion of a source configuration."""
    del optimize
    if (source_vendor.casefold(), target_vendor.casefold()) != ("fortigate", "palo_alto"):
        raise click.ClickException("Only fortigate -> palo_alto is supported")
    if format != "set":
        raise click.ClickException("The MVP supports only --format set")
    mapping = {}
    if zone_map:
        with open(zone_map, encoding="utf-8") as stream:
            mapping = yaml.safe_load(stream) or {}
    with open(input, encoding="utf-8") as stream:
        analysis = source_reporters.get("fortigate").analyze_source(stream.read())
    plan = migration_planners.get(source_vendor, target_vendor).plan(
        analysis.extracted.config, analysis.derived, options=PANMigrationOptions(**mapping)
    )
    validation = validate_plan(plan)
    rendered = PANSetRenderer().render(plan, validation)
    PANSetRenderer().write_files(rendered, output)
    click.echo(f"Generated {len(rendered.commands)} commands in {output}")
    click.echo(f"Validation findings: {len(validation.issues)}")

@cli.command()
@click.argument('commands_file', type=click.Path(exists=True, dir_okay=False))
@click.option('--host', required=True)
@click.option('--port', default=22, show_default=True, type=click.IntRange(1, 65535))
@click.option('--username', required=True)
@click.option('--password', prompt=True, hide_input=True)
def deploy(commands_file, host, port, username, password):
    """Push a .set file as a candidate and validate it. Does not commit."""
    artifact_path = os.path.join(os.path.dirname(commands_file), 'conversion_report.json')
    with open(commands_file, encoding='utf-8') as stream:
        commands = tuple(line.strip() for line in stream if line.strip())
    with open(artifact_path, encoding='utf-8') as stream:
        report = json.load(stream)
    if not isinstance(report, dict) or report.get('commands') != len(commands):
        raise click.ClickException('The .set file does not match its rendered migration report')
    rendered = RenderedMigration(commands, report)
    result = PANSSHDeployer(PANDeploymentOptions(host, username, password, port=port)).deploy(rendered)
    if result.failure_message or result.validation.status == 'FAILED':
        raise click.ClickException(result.failure_message or result.validation.response or 'Candidate validation failed')
    click.echo(f"Pushed {result.commands_succeeded} candidate commands; validation {result.validation.status}")

@cli.command()
@click.option('--host', required=True)
@click.option('--port', default=22, show_default=True, type=click.IntRange(1, 65535))
@click.option('--username', required=True)
@click.option('--password', prompt=True, hide_input=True)
def commit(host, port, username, password):
    """Explicitly commit the current Palo Alto candidate configuration."""
    result = PANSSHDeployer(PANDeploymentOptions(host, username, password, port=port)).commit()
    if result.status != 'SUCCESS':
        raise click.ClickException(result.response or 'Commit failed')
    click.echo(f"Commit submitted (job {result.job_id or 'unknown'})")

@cli.command()
@click.option('--port', default=5000, help='Port to run the web server on')
def serve(port):
    """Start the migration web interface."""
    try:
        from fwmigrate.web_live import create_app
        app = create_app()
        click.echo(f"Starting web server on http://localhost:{port}")
        app.run(host='0.0.0.0', port=port, debug=False)
    except ImportError:
        click.echo("Flask is required to run the web server. Install with: pip install flask", err=True)
        sys.exit(1)

@cli.command()
@click.option('--port', default=5000, help='Port to run the desktop app on')
def app(port):
    """Launch as a native desktop application."""
    from fwmigrate.web_live import run_desktop
    run_desktop(port=port)

if __name__ == '__main__':
    # If double-clicked in Windows Explorer (no arguments provided)
    if len(sys.argv) == 1:
        from fwmigrate.web_live import run_desktop
        run_desktop()
    else:
        cli()
