import click
import sys
from pathlib import Path

from fg2pan.parser.fortigate_parser import parse_fortigate_config
from fg2pan.parser.fortigate_api import FortiGateAPIClient
from fg2pan.transformer.fg_to_ir import FGToIRTransformer
from fg2pan.generator.panos_xml import PANOSXMLGenerator
from fg2pan.generator.panos_terraform import PANOSTerraformGenerator
from fg2pan.report.migration_report import MigrationReporter
from fg2pan.config import MigrationConfig
from fg2pan.generator.base import MigrationArtifact

@click.group()
def cli():
    """FortiGate to Palo Alto Migration Engine."""
    pass

@cli.command()
@click.option('--input', '-i', type=click.Path(exists=True), help='Input FortiGate .conf file')
@click.option('--output', '-o', required=True, type=click.Path(), help='Output directory')
@click.option('--fortigate-host', type=str, help='Live FortiGate IP or hostname')
@click.option('--fortigate-port', type=int, default=443, help='Live FortiGate HTTPS port (default: 443)')
@click.option('--fortigate-api-key', type=str, help='FortiGate REST API token')
@click.option('--fortigate-user', type=str, help='FortiGate admin username')
@click.option('--fortigate-password', type=str, help='FortiGate admin password')
@click.option('--vdom', type=str, default='root', help='FortiGate VDOM (default: root)')
@click.option('--insecure', is_flag=True, default=False, help='Disable SSL verification for self-signed certificates')
@click.option('--zone-map', type=click.Path(exists=True), help='YAML file with interface to zone mappings')
@click.option('--format', type=click.Choice(['xml', 'set', 'terraform']), default='xml', help='Output format')
@click.option('--report', type=click.Path(), help='Output path for the unified migration & configuration report markdown file')
@click.option('--txt-report', type=click.Path(), hidden=True, help='Deprecated: Configuration summary is now part of the unified Markdown report')
def migrate(input, output, fortigate_host, fortigate_port, fortigate_api_key, fortigate_user, fortigate_password, vdom, insecure, zone_map, format, report, txt_report):
    """Migrate a FortiGate configuration to Palo Alto."""
    try:
        # 1. Load config
        migration_config = MigrationConfig()
        if zone_map:
            migration_config = MigrationConfig.from_yaml(zone_map)
            
        # 2. Ingest FortiGate Configuration (File or Live REST API)
        if fortigate_host:
            click.echo(f"Connecting to live FortiGate at {fortigate_host}:{fortigate_port} (VDOM: {vdom})...")
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
            click.echo(f"  Extracted {len(fg_config.interfaces)} interfaces, {len(fg_config.policies)} policies from live API.")
        elif input:
            click.echo(f"Parsing FortiGate config: {input}")
            with open(input, 'r', encoding='utf-8') as f:
                fg_text = f.read()
                
            fg_config = parse_fortigate_config(fg_text)
            click.echo(f"  Parsed {len(fg_config.interfaces)} interfaces, {len(fg_config.policies)} policies.")
        else:
            click.echo("Error: Please provide either --input (-i) or --fortigate-host.", err=True)
            sys.exit(1)
        
        # 3. Transform to IR
        click.echo("Transforming to Vendor-Neutral IR...")
        transformer = FGToIRTransformer(fg_config, zone_mapping=migration_config.zone_mapping)
        ir_config = transformer.transform()
        click.echo(f"  Created {len(ir_config.zones)} zones, {len(ir_config.addresses)} addresses.")
        
        # 4. Generate Target Artifacts
        click.echo(f"Generating PAN-OS {format.upper()} configuration...")
        out_dir = Path(output)
        out_dir.mkdir(parents=True, exist_ok=True)
        
        if format == 'xml':
            generator = PANOSXMLGenerator()
            artifacts = generator.generate(ir_config)
            
            for artifact in artifacts:
                out_path = out_dir / artifact.filename
                with open(out_path, 'w', encoding='utf-8') as f:
                    f.write(artifact.content)
                click.echo(f"  Saved {out_path}")
        elif format == 'terraform':
            generator = PANOSTerraformGenerator()
            artifacts = generator.generate(ir_config)
            
            for artifact in artifacts:
                out_path = out_dir / artifact.filename
                with open(out_path, 'w', encoding='utf-8') as f:
                    f.write(artifact.content)
                click.echo(f"  Saved {out_path}")
        else:
            click.echo(f"Format {format} is not yet supported in this MVP.", err=True)
            sys.exit(1)
            
        # 5. Generate Unified Migration & Configuration Report
        if report:
            click.echo(f"Generating unified migration & configuration report: {report}")
            reporter = MigrationReporter(ir_config)
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
