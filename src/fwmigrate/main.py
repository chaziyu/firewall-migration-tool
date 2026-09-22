import os
import sys
import io
import click

# Safe stdout/stderr fallback in windowed (GUI) mode
if sys.stdout is None:
    sys.stdout = io.StringIO()
if sys.stderr is None:
    sys.stderr = io.StringIO()

from fwmigrate.builtin_plugins import register_builtin_plugins
from fwmigrate.source_reporting import source_reporters

register_builtin_plugins()

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

    click.echo("\nConfiguration conversion is temporarily unavailable.")

@cli.command()
@click.option('--input', '-i', required=True, type=click.Path(exists=True), help='Input configuration file (.conf, .cfg, .json, .set)')
@click.option('--output', '-o', required=True, type=click.Path(), help='Output directory')
@click.option('--source-vendor', type=str, default='fortigate', help='Registered source vendor identifier')
@click.option('--target-vendor', type=str, default='palo_alto', help='Registered target vendor identifier')
@click.option('--zone-map', type=click.Path(exists=True), help='YAML file with interface to zone mappings')
@click.option('--format', type=click.Choice(['xml', 'set', 'terraform', 'cli']), default='xml', help='Output format')
@click.option('--optimize', is_flag=True, default=False, help='Prune unused objects and optimize rules')
def migrate(input, output, source_vendor, target_vendor, zone_map, format, optimize):
    """Reserved compatibility command; pair-specific conversion is unavailable."""
    del input, output, source_vendor, target_vendor, zone_map, format, optimize
    click.echo(
        'Configuration conversion is temporarily unavailable while the '
        'pair-specific conversion architecture is being implemented.',
        err=True,
    )
    raise click.exceptions.Exit(1)

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
