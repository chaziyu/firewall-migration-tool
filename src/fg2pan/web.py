import os
import io
import json
import uuid
import zipfile
from pathlib import Path
from flask import Flask, render_template, request, send_file, jsonify, Response, stream_with_context

from fg2pan.parser.fortigate_parser import parse_fortigate_config
from fg2pan.parser.fortigate_api import FortiGateAPIClient
from fg2pan.transformer.fg_to_ir import FGToIRTransformer
from fg2pan.generator.panos_xml import PANOSXMLGenerator
from fg2pan.generator.panos_terraform import PANOSTerraformGenerator
from fg2pan.report.migration_report import MigrationReporter
from fg2pan.engine.diagnostics import PaloAltoDiagnostics
from fg2pan.engine.binary_manager import TerraformBinaryManager
from fg2pan.engine.runner import TerraformSandbox, TerraformRunner


# In-memory session registry (session_id -> metadata/sandbox)
ACTIVE_SESSIONS = {}


def create_app(test_config=None):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    app = Flask(
        __name__,
        static_folder=os.path.join(base_dir, 'static'),
        template_folder=os.path.join(base_dir, 'templates')
    )

    if test_config:
        app.config.update(test_config)

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/favicon.ico')
    def favicon():
        return ('', 204)

    @app.route('/api/migrate', methods=['POST'])
    def migrate():
        """Offline / Live Ingestion Migration Handler: Generates XML, Terraform, and Report in a downloadable ZIP."""
        try:
            fg_config = None
            if 'file' in request.files and request.files['file'].filename != '':
                file = request.files['file']
                fg_text = file.read().decode('utf-8', errors='ignore')
                fg_config = parse_fortigate_config(fg_text)
            else:
                # Check for session_id from API ingestion
                session_id = request.form.get('session_id') or (request.get_json() or {}).get('session_id')
                if session_id and session_id in ACTIVE_SESSIONS and 'fg_config' in ACTIVE_SESSIONS[session_id]:
                    fg_config = ACTIVE_SESSIONS[session_id]['fg_config']

            if not fg_config:
                return jsonify({'error': 'No file uploaded or live API configuration found'}), 400

            # 2. Transform to IR
            transformer = FGToIRTransformer(fg_config)
            ir_config = transformer.transform()

            # 3. Generate Artifacts
            xml_gen = PANOSXMLGenerator()
            xml_artifacts = xml_gen.generate(ir_config)

            tf_gen = PANOSTerraformGenerator()
            tf_artifacts = tf_gen.generate(ir_config)

            reporter = MigrationReporter(ir_config)
            report_content = reporter.generate_report()

            # 4. Package into ZIP
            memory_file = io.BytesIO()
            with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
                for art in xml_artifacts:
                    zf.writestr(art.filename, art.content)
                for art in tf_artifacts:
                    zf.writestr(f"terraform/{art.filename}", art.content)
                zf.writestr("migration_report.md", report_content)

            memory_file.seek(0)

            return send_file(
                memory_file,
                mimetype='application/zip',
                as_attachment=True,
                download_name='migration_results.zip'
            )

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/ingest/fortigate-api', methods=['POST'])
    def ingest_fortigate_api():
        """Live FortiGate REST API Ingestion Handler."""
        data = request.get_json() or {}
        host = data.get('host', '').strip()
        port = int(data.get('port', 443))
        api_key = data.get('api_key', '').strip() or None
        username = data.get('username', '').strip() or None
        password = data.get('password', '').strip() or None
        vdom = data.get('vdom', 'root').strip()
        verify_ssl = bool(data.get('verify_ssl', False))

        if not host:
            return jsonify({'success': False, 'error': 'FortiGate host is required'}), 400

        if not api_key and not (username and password):
            return jsonify({'success': False, 'error': 'Please provide either a REST API Token or Admin Username & Password'}), 400

        try:
            client = FortiGateAPIClient(
                host=host,
                port=port,
                api_key=api_key,
                username=username,
                password=password,
                vdom=vdom,
                verify_ssl=verify_ssl
            )
            fg_config = client.extract_config()
            transformer = FGToIRTransformer(fg_config)
            ir_config = transformer.transform()

            # Cache in ACTIVE_SESSIONS
            session_id = str(uuid.uuid4())[:8]
            ACTIVE_SESSIONS[session_id] = {
                'fg_config': fg_config,
                'ir_config': ir_config,
                'host': host,
                'stats': {
                    'interfaces': len(fg_config.interfaces),
                    'addresses': len(ir_config.addresses),
                    'address_groups': len(ir_config.address_groups),
                    'services': len(ir_config.services),
                    'policies': len(ir_config.policies),
                    'nat_rules': len(ir_config.nat_rules),
                    'routes': len(ir_config.routes)
                }
            }

            return jsonify({
                'success': True,
                'session_id': session_id,
                'hostname': fg_config.system_global.hostname if fg_config.system_global else 'fortigate',
                'stats': ACTIVE_SESSIONS[session_id]['stats']
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/diagnostics', methods=['POST'])
    def run_diagnostics():
        """Pre-flight diagnostic probe for Terraform CLI, Registry, and Palo Alto firewall."""
        data = request.get_json() or {}
        host = data.get('host', '').strip()
        port = int(data.get('port', 443))
        api_key = data.get('api_key', '').strip() or None
        username = data.get('username', '').strip() or None
        password = data.get('password', '').strip() or None
        verify_ssl = bool(data.get('verify_ssl', False))
        auto_download_tf = bool(data.get('auto_download_tf', False))

        try:
            diag = PaloAltoDiagnostics()
            results = diag.run_all(
                host=host if host else None,
                port=port,
                api_key=api_key,
                username=username,
                password=password,
                verify_ssl=verify_ssl,
                auto_download_tf=auto_download_tf
            )
            return jsonify({
                'success': True,
                'results': [r.model_dump() for r in results]
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/terraform/prepare', methods=['POST'])
    def terraform_prepare():
        """Parses FortiGate config (from file upload or live API session), generates Terraform artifacts, and creates sandbox."""
        try:
            fg_config = None
            if 'file' in request.files and request.files['file'].filename != '':
                file = request.files['file']
                fg_text = file.read().decode('utf-8', errors='ignore')
                fg_config = parse_fortigate_config(fg_text)
            else:
                session_id_input = request.form.get('session_id') or (request.get_json() or {}).get('session_id')
                if session_id_input and session_id_input in ACTIVE_SESSIONS and 'fg_config' in ACTIVE_SESSIONS[session_id_input]:
                    fg_config = ACTIVE_SESSIONS[session_id_input]['fg_config']

            if not fg_config:
                return jsonify({'error': 'No file uploaded or live API configuration found'}), 400

            # Parse target parameters
            host = request.form.get('host', '192.168.1.1').strip()
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            api_key = request.form.get('api_key', '').strip()
            vsys = request.form.get('vsys', 'vsys1').strip()
            device_group = request.form.get('device_group', 'shared').strip()

            # 1. Transform
            transformer = FGToIRTransformer(fg_config)
            ir_config = transformer.transform()

            # 2. Generate Terraform files
            tf_gen = PANOSTerraformGenerator(vsys=vsys, device_group=device_group)
            tf_artifacts = tf_gen.generate(ir_config)

            # Generate Report
            reporter = MigrationReporter(ir_config)
            report_content = reporter.generate_report()

            # 3. Create Sandbox
            session_id = str(uuid.uuid4())[:8]
            sandbox = TerraformSandbox(session_id=session_id)

            tfvars = {
                'panos_hostname': host,
                'panos_username': username,
                'panos_password': password,
                'panos_api_key': api_key,
                'panos_vsys': vsys,
                'panos_device_group': device_group,
            }

            sandbox_dir = sandbox.create(tf_artifacts, tfvars=tfvars)

            # Save report in sandbox
            with open(sandbox_dir / "migration_report.md", "w", encoding="utf-8") as f:
                f.write(report_content)

            # Store active session info
            secrets = [s for s in [password, api_key] if s]
            ACTIVE_SESSIONS[session_id] = {
                'sandbox': sandbox,
                'sandbox_dir': sandbox_dir,
                'secrets': secrets,
                'host': host,
                'stats': {
                    'interfaces': len(fg_config.interfaces),
                    'addresses': len(ir_config.addresses),
                    'address_groups': len(ir_config.address_groups),
                    'services': len(ir_config.services),
                    'policies': len(ir_config.policies),
                    'nat_rules': len(ir_config.nat_rules),
                }
            }

            return jsonify({
                'success': True,
                'session_id': session_id,
                'stats': ACTIVE_SESSIONS[session_id]['stats'],
                'message': f'Prepared session {session_id} with {len(tf_artifacts)} Terraform files.'
            })

        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/terraform/plan', methods=['POST'])
    def terraform_plan():
        """Executes `terraform init` and `terraform plan` in the session sandbox."""
        data = request.get_json() or {}
        session_id = data.get('session_id')

        if not session_id or session_id not in ACTIVE_SESSIONS:
            return jsonify({'success': False, 'error': f'Session {session_id} not found or expired'}), 404

        session = ACTIVE_SESSIONS[session_id]
        sandbox_dir = session['sandbox_dir']
        secrets = session['secrets']

        try:
            runner = TerraformRunner(sandbox_dir=sandbox_dir, secrets=secrets)

            # 1. Terraform Init
            init_ok, init_log = runner.run_init()
            if not init_ok:
                return jsonify({
                    'success': False,
                    'stage': 'init',
                    'init_log': init_log,
                    'error': 'Terraform init failed. Review provider configuration.'
                })

            # 2. Terraform Plan
            plan_ok, plan_log, plan_summary = runner.run_plan()
            if not plan_ok:
                return jsonify({
                    'success': False,
                    'stage': 'plan',
                    'init_log': init_log,
                    'plan_log': plan_log,
                    'error': 'Terraform plan failed. Review firewall connectivity or schema constraints.'
                })

            return jsonify({
                'success': True,
                'stage': 'ready_to_apply',
                'init_log': init_log,
                'plan_log': plan_log,
                'summary': plan_summary
            })

        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/terraform/apply/stream')
    def terraform_apply_stream():
        """Server-Sent Events (SSE) streaming endpoint for live `terraform apply`."""
        session_id = request.args.get('session_id')

        if not session_id or session_id not in ACTIVE_SESSIONS:
            def error_gen():
                yield f"data: {json.dumps({'event': 'error', 'message': f'Session {session_id} not found'})}\n\n"
            return Response(error_gen(), mimetype='text/event-stream')

        session = ACTIVE_SESSIONS[session_id]
        sandbox_dir = session['sandbox_dir']
        secrets = session['secrets']

        def generate_sse():
            runner = TerraformRunner(sandbox_dir=sandbox_dir, secrets=secrets)
            for event in runner.run_apply_stream():
                yield f"data: {json.dumps(event)}\n\n"

        return Response(
            stream_with_context(generate_sse()),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no',
                'Connection': 'keep-alive'
            }
        )

    @app.route('/api/terraform/destroy/stream')
    def terraform_destroy_stream():
        """Server-Sent Events (SSE) streaming endpoint for live `terraform destroy` (rollback)."""
        session_id = request.args.get('session_id')

        if not session_id or session_id not in ACTIVE_SESSIONS:
            def error_gen():
                yield f"data: {json.dumps({'event': 'error', 'message': f'Session {session_id} not found'})}\n\n"
            return Response(error_gen(), mimetype='text/event-stream')

        session = ACTIVE_SESSIONS[session_id]
        sandbox_dir = session['sandbox_dir']
        secrets = session['secrets']

        def generate_sse():
            runner = TerraformRunner(sandbox_dir=sandbox_dir, secrets=secrets)
            for event in runner.run_destroy_stream():
                yield f"data: {json.dumps(event)}\n\n"

        return Response(
            stream_with_context(generate_sse()),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no',
                'Connection': 'keep-alive'
            }
        )

    @app.route('/api/download/state')
    def download_state():
        """Downloads the current `terraform.tfstate` for the session."""
        session_id = request.args.get('session_id')
        if not session_id or session_id not in ACTIVE_SESSIONS:
            return jsonify({'error': 'Session not found'}), 404

        session = ACTIVE_SESSIONS[session_id]
        state_file = session['sandbox_dir'] / 'terraform.tfstate'

        if not state_file.exists():
            return jsonify({'error': 'No terraform.tfstate file exists for this session'}), 404

        return send_file(
            state_file,
            mimetype='application/json',
            as_attachment=True,
            download_name=f'terraform_{session_id}.tfstate'
        )

    @app.route('/api/download/package')
    def download_package():
        """Downloads the complete session directory as a ZIP archive."""
        session_id = request.args.get('session_id')
        if not session_id or session_id not in ACTIVE_SESSIONS:
            return jsonify({'error': 'Session not found'}), 404

        session = ACTIVE_SESSIONS[session_id]
        sandbox_dir = session['sandbox_dir']

        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            for file_path in sandbox_dir.rglob('*'):
                if file_path.is_file() and not file_path.name.startswith('.'):
                    rel_path = file_path.relative_to(sandbox_dir)
                    zf.write(file_path, arcname=str(rel_path))

        memory_file.seek(0)
        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'terraform_package_{session_id}.zip'
        )

    return app
