import click
import sys
from pathlib import Path

# Auto-register all plugin modules
import fg2pan.parsers
import fg2pan.generators

from fg2pan.core.registry import PluginRegistry
from fg2pan.core.optimizer import RuleOptimizer
from fg2pan.report.migration_report import MigrationReporter
from fg2pan.config import MigrationConfig

@click.group()
def cli():
    """Universal Multi-Vendor Firewall Migration Platform."""
    pass

@cli.command()
def vendors():
    """List all registered source and target vendor plugins."""
    click.echo("\n--- Supported Source Vendors ---")
    for s in PluginRegistry.list_source_vendors():
        exts = s.get('file_extensions') or s.get('supported_extensions') or []
        click.echo(f"  • {s['vendor_id']:<15} : {s['display_name']} (Ext: {', '.join(exts)})")

    click.echo("\n--- Supported Target Platforms ---")
    for t in PluginRegistry.list_target_vendors():
        click.echo(f"  • {t['vendor_id']:<15} : {t['display_name']} (Formats: {', '.join(t['supported_formats'])})")
    click.echo("")

@cli.command()
@click.option('--input', '-i', type=click.Path(exists=True), help='Input configuration file (.conf, .cfg, .json, .set)')
@click.option('--output', '-o', required=True, type=click.Path(), help='Output directory')
@click.option('--source-vendor', type=str, default='fortigate', help='Source vendor (fortigate, cisco_asa, checkpoint, juniper_srx)')
@click.option('--target-vendor', type=str, default='palo_alto', help='Target vendor (palo_alto, fortigate)')
@click.option('--fortigate-host', type=str, help='Live FortiGate IP or hostname')
@click.option('--fortigate-port', type=int, default=443, help='Live FortiGate HTTPS port (default: 443)')
@click.option('--fortigate-api-key', type=str, help='FortiGate REST API token')
@click.option('--fortigate-user', type=str, help='FortiGate admin username')
@click.option('--fortigate-password', type=str, help='FortiGate admin password')
@click.option('--vdom', type=str, default='root', help='FortiGate VDOM (default: root)')
@click.option('--insecure', is_flag=True, default=False, help='Disable SSL verification for self-signed certificates')
@click.option('--zone-map', type=click.Path(exists=True), help='YAML file with interface to zone mappings')
@click.option('--format', type=click.Choice(['xml', 'set', 'terraform', 'cli']), default='xml', help='Output format')
@click.option('--optimize', is_flag=True, default=False, help='Prune unused objects and optimize rules')
@click.option('--report', type=click.Path(), help='Output path for the unified migration & configuration report markdown file')
@click.option('--txt-report', type=click.Path(), hidden=True, help='Deprecated: Configuration summary is now part of the unified Markdown report')
def migrate(input, output, source_vendor, target_vendor, fortigate_host, fortigate_port, fortigate_api_key, fortigate_user, fortigate_password, vdom, insecure, zone_map, format, optimize, report, txt_report):
    """Migrate a firewall configuration between vendors."""
    try:
        # 1. Load config
        migration_config = MigrationConfig()
        if zone_map:
            migration_config = MigrationConfig.from_yaml(zone_map)

        # 2. Ingest Configuration (File or Live REST API)
        if fortigate_host:
            from fg2pan.parser.fortigate_api import FortiGateAPIClient
            from fg2pan.transformer.fg_to_ir import FGToIRTransformer
            click.echo(f"Connecting to live {source_vendor} at {fortigate_host}:{fortigate_port} (VDOM: {vdom})...")
            client = FortiGateAPIClient(
                host=fortigate_host,
                port=fortigate_port,
                api_key=fortigate_api_key,
                username=fortigate_user,
                password=fortigate_password,
                vdom=vdom,
                verify_ssl=not insecure
            )
            fg_config = client.extract_config()
            transformer = FGToIRTransformer(fg_config, zone_mapping=migration_config.zone_mapping)
            ir_config = transformer.transform()
            click.echo(f"  Extracted {len(ir_config.interfaces)} interfaces, {len(ir_config.policies)} policies from live API.")
        elif input:
            click.echo(f"Parsing {source_vendor} config: {input}")
            with open(input, 'r', encoding='utf-8') as f:
                content = f.read()

            parser = PluginRegistry.get_parser(source_vendor)
            ir_config = parser.parse(content, zone_mapping=migration_config.zone_mapping)
            click.echo(f"  Parsed {len(ir_config.interfaces)} interfaces, {len(ir_config.policies)} policies.")
        else:
            click.echo("Error: Please provide either --input (-i) or --fortigate-host.", err=True)
            sys.exit(1)

        # 3. Optional Optimization
        if optimize:
            click.echo("Running rule & object optimizer...")
            optimizer = RuleOptimizer(ir_config)
            unused = optimizer.find_unused_objects()
            click.echo(f"  Found {len(unused['unused_addresses'])} unused addresses, {len(unused['unused_services'])} unused services. Pruning...")
            ir_config = optimizer.prune_unused_objects()

        # 4. Generate Target Artifacts
        click.echo(f"Generating {target_vendor.upper()} ({format.upper()}) configuration...")
        out_dir = Path(output)
        out_dir.mkdir(parents=True, exist_ok=True)

        generator = PluginRegistry.get_generator(target_vendor)
        artifacts = generator.generate(ir_config, format=format)

        for artifact in artifacts:
            out_path = out_dir / artifact.filename
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(artifact.content)
            click.echo(f"  Saved {out_path}")

        # 5. Generate Unified Migration & Configuration Report
        if report:
            click.echo(f"Generating unified migration & configuration report: {report}")
            reporter = MigrationReporter(ir_config, target_vendor=generator.display_name)
            report_content = reporter.generate_report()

            report_path = Path(report)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            click.echo(f"  Saved {report_path}")

        if txt_report:
            click.echo("Note: --txt-report is deprecated. Configuration summary is now included in the unified Markdown report (--report).")

        click.echo("Migration complete!")

    except Exception as e:
        click.echo(f"Error during migration: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.option('--port', default=5000, help='Port to run the web server on')
def serve(port):
    """Start the migration web interface."""
    try:
        from fg2pan.web import create_app
        app = create_app()
        click.echo(f"Starting web server on http://localhost:{port}")
        app.run(host='0.0.0.0', port=port, debug=False)
    except ImportError:
        click.echo("Flask is required to run the web server. Install with: pip install flask", err=True)
        sys.exit(1)

if __name__ == '__main__':
    cli()
