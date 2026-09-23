import os
import sys
import io
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
from fwmigrate.conversion.fortigate_to_palo_alto.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan

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
    rendered = PANSetRenderer().render_files(plan, output)
    click.echo(f"Generated {len(rendered.commands)} commands in {output}")
    click.echo(f"Validation findings: {len(validation.issues)}")

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
