import click
import sys
from pathlib import Path

from fg2pan.parser.fortigate_parser import parse_fortigate_config
from fg2pan.transformer.fg_to_ir import FGToIRTransformer
from fg2pan.generator.panos_xml import PANOSXMLGenerator
from fg2pan.report.migration_report import MigrationReporter
from fg2pan.config import MigrationConfig
from fg2pan.generator.base import MigrationArtifact

@click.group()
def cli():
    """FortiGate to Palo Alto Migration Engine."""
    pass

@cli.command()
@click.option('--input', '-i', required=True, type=click.Path(exists=True), help='Input FortiGate .conf file')
@click.option('--output', '-o', required=True, type=click.Path(), help='Output directory')
@click.option('--zone-map', type=click.Path(exists=True), help='YAML file with interface to zone mappings')
@click.option('--format', type=click.Choice(['xml', 'set', 'terraform']), default='xml', help='Output format')
@click.option('--report', type=click.Path(), help='Output path for the migration report markdown file')
@click.option('--txt-report', type=click.Path(), help='Output path for the plain text configuration summary')
def migrate(input, output, zone_map, format, report, txt_report):
    """Migrate a FortiGate configuration to Palo Alto."""
    try:
        # 1. Load config
        migration_config = MigrationConfig()
        if zone_map:
            migration_config = MigrationConfig.from_yaml(zone_map)
            
        # 2. Parse FortiGate
        click.echo(f"Parsing FortiGate config: {input}")
        with open(input, 'r', encoding='utf-8') as f:
            fg_text = f.read()
            
        fg_config = parse_fortigate_config(fg_text)
        click.echo(f"  Parsed {len(fg_config.interfaces)} interfaces, {len(fg_config.policies)} policies.")
        
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
        else:
            click.echo(f"Format {format} is not yet supported in this MVP.", err=True)
            sys.exit(1)
            
        # 5. Generate Report
        if report:
            click.echo(f"Generating migration report: {report}")
            reporter = MigrationReporter(ir_config)
            report_content = reporter.generate_report()
            
            report_path = Path(report)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
                
        # 6. Generate TXT Summary Report
        if txt_report:
            from fg2pan.generator.txt_report import TXTReportGenerator
            click.echo(f"Generating TXT configuration summary: {txt_report}")
            txt_generator = TXTReportGenerator()
            txt_artifacts = txt_generator.generate(ir_config)
            
            txt_path = Path(txt_report)
            txt_path.parent.mkdir(parents=True, exist_ok=True)
            with open(txt_path, 'w', encoding='utf-8') as f:
                f.write(txt_artifacts[0].content)
                
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
