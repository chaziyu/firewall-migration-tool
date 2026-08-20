import os
import sys
import io
import json
import uuid
import zipfile
from pathlib import Path
from flask import Flask, render_template, request, send_file, jsonify, Response, stream_with_context

# Auto-register plugins
import fwmigrate.parsers
import fwmigrate.generators

from fwmigrate.core.registry import PluginRegistry
from fwmigrate.core.optimizer import RuleOptimizer
from fwmigrate.parsers.fortigate.api_client import FortiGateAPIClient
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer
from fwmigrate.generators.palo_alto.terraform_generator import PANOSTerraformGenerator
from fwmigrate.report.migration_report import MigrationReporter
from fwmigrate.engine.diagnostics import PaloAltoDiagnostics
from fwmigrate.engine.runner import TerraformSandbox, TerraformRunner

# In-memory session registry (session_id -> metadata/sandbox)
ACTIVE_SESSIONS = {}

def create_app(test_config=None):
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        base_dir = os.path.join(sys._MEIPASS, 'fwmigrate')
        if not os.path.exists(os.path.join(base_dir, 'templates')):
            base_dir = sys._MEIPASS
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))

    app = Flask(
        __name__,
        static_folder=os.path.join(base_dir, 'static'),
        template_folder=os.path.join(base_dir, 'templates')
    )

    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
    app.jinja_env.auto_reload = True

    if test_config:
        app.config.update(test_config)

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/favicon.ico')
    def favicon():
        return send_file(os.path.join(app.static_folder, 'app_icon.ico'), mimetype='image/vnd.microsoft.icon')

    @app.route('/api/vendors', methods=['GET'])
    def list_vendors():
        """Returns lists of supported source vendors and target platforms."""
        sources = PluginRegistry.list_source_vendors()
        for s in sources:
            vid = s.get('vendor_id')
            if vid in PluginRegistry._api_clients:
                s['api_fields'] = PluginRegistry._api_clients[vid].get_field_definitions()
        return jsonify({
            'success': True,
            'sources': sources,
            'targets': PluginRegistry.list_target_vendors()
        })

    @app.route('/api/preview', methods=['POST'])
    def preview_migration():
        """Returns transformation analysis, rule mapping preview, and optimization stats."""
        try:
            source_vendor = request.form.get('source_vendor', 'fortigate')
            ir_config = None

            if 'file' in request.files and request.files['file'].filename != '':
                file = request.files['file']
                content = file.read().decode('utf-8', errors='ignore')
                parser = PluginRegistry.get_parser(source_vendor)
                ir_config = parser.parse(content)
            else:
                session_id = request.form.get('session_id') or (request.get_json() or {}).get('session_id')
                if session_id and session_id in ACTIVE_SESSIONS:
                    if 'ir_config' in ACTIVE_SESSIONS[session_id]:
                        ir_config = ACTIVE_SESSIONS[session_id]['ir_config']
                    elif 'fg_config' in ACTIVE_SESSIONS[session_id]:
                        transformer = FGToIRTransformer(ACTIVE_SESSIONS[session_id]['fg_config'])
                        ir_config = transformer.transform()

            if not ir_config:
                return jsonify({'success': False, 'error': 'No file uploaded or live session found'}), 400

            # Run optimizer analysis and logic fixes
            optimizer = RuleOptimizer(ir_config)
            optimizer.fix_outbound_threat_source_anomalies()
            unused = optimizer.find_unused_objects()
            duplicates = optimizer.find_duplicate_objects()
            shadowed = optimizer.find_shadowed_rules()

            policies_preview = []
            for idx, p in enumerate(ir_config.policies[:50], 1):
                policies_preview.append({
                    "id": p.name,
                    "index": idx,
                    "from_zone": p.from_zone,
                    "to_zone": p.to_zone,
                    "source": p.source,
                    "destination": p.destination,
                    "service": p.service,
                    "action": p.action.value,
                    "disabled": p.disabled,
                    "description": p.description or ""
                })

            return jsonify({
                'success': True,
                'hostname': ir_config.metadata.hostname,
                'source_vendor': ir_config.metadata.source_vendor,
                'stats': {
                    'zones': len(ir_config.zones),
                    'interfaces': len(ir_config.interfaces),
                    'addresses': len(ir_config.addresses),
                    'address_groups': len(ir_config.address_groups),
                    'services': len(ir_config.services),
                    'service_groups': len(ir_config.service_groups),
                    'policies': len(ir_config.policies),
                    'nat_rules': len(ir_config.nat_rules),
                    'routes': len(ir_config.routes)
                },
                'optimization': {
                    'unused_addresses_count': len(unused['unused_addresses']),
                    'unused_services_count': len(unused['unused_services']),
                    'duplicate_address_groups_count': len(duplicates['duplicate_addresses']),
                    'shadowed_rules_count': len(shadowed),
                    'shadowed_rules': shadowed
                },
                'policies': policies_preview
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/migrate', methods=['POST'])
    def migrate():
        """Multi-vendor migration handler: Generates configuration artifacts and Markdown audit report in a ZIP."""
        try:
            source_vendor = request.form.get('source_vendor', 'fortigate')
            target_vendor = request.form.get('target_vendor', 'palo_alto')
            optimize = request.form.get('optimize', 'false').lower() == 'true'

            ir_config = None
            if 'file' in request.files and request.files['file'].filename != '':
                file = request.files['file']
                content = file.read().decode('utf-8', errors='ignore')
                parser = PluginRegistry.get_parser(source_vendor)
                ir_config = parser.parse(content)
            else:
                session_id = request.form.get('session_id') or (request.get_json() or {}).get('session_id')
                if session_id and session_id in ACTIVE_SESSIONS:
                    if 'ir_config' in ACTIVE_SESSIONS[session_id]:
                        ir_config = ACTIVE_SESSIONS[session_id]['ir_config']
                    elif 'fg_config' in ACTIVE_SESSIONS[session_id]:
                        transformer = FGToIRTransformer(ACTIVE_SESSIONS[session_id]['fg_config'])
                        ir_config = transformer.transform()

            if not ir_config:
                return jsonify({'error': 'No file uploaded or live API configuration found'}), 400

            # Always run structural logic fixes (Vendor Free)
            optimizer = RuleOptimizer(ir_config)
            optimizer.fix_outbound_threat_source_anomalies()

            # Optional optimization
            if optimize:
                ir_config = optimizer.prune_unused_objects()

            # Generate target artifacts
            generator = PluginRegistry.get_generator(target_vendor)
            artifacts = generator.generate(ir_config)

            reporter = MigrationReporter(ir_config, target_vendor=generator.display_name)
            report_content = reporter.generate_report()
            html_report_content = reporter.generate_html_report()

            # Package into ZIP
            memory_file = io.BytesIO()
            with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
                written_names = set()
                for art in artifacts:
                    fname = f"terraform/{art.filename}" if art.format == "terraform" else art.filename
                    zf.writestr(fname, art.content)
                    written_names.add(fname)
                if "migration_report.md" not in written_names:
                    zf.writestr("migration_report.md", report_content)
                if "migration_report.html" not in written_names:
                    zf.writestr("migration_report.html", html_report_content)

            memory_file.seek(0)
            return send_file(
                memory_file,
                mimetype='application/zip',
                as_attachment=True,
                download_name=f'migration_{source_vendor}_to_{target_vendor}.zip'
            )

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/ingest/<vendor_id>', methods=['POST'])
    @app.route('/api/ingest/fortigate-api', methods=['POST'])
    def ingest_live_api(vendor_id='fortigate'):
        """Live device REST/NETCONF API Ingestion Handler."""
        data = request.get_json() or {}
        host = data.get('host', '').strip()
        port = int(data.get('port', 443))
        api_key = data.get('api_key', '').strip() or None
        username = data.get('username', '').strip() or None
        password = data.get('password', '').strip() or None
        vdom = data.get('vdom', 'root').strip()
        verify_ssl = bool(data.get('verify_ssl', False))

        if not host:
            return jsonify({'success': False, 'error': f'{vendor_id.replace("_", " ").title()} host is required'}), 400

        if vendor_id in ('fortigate', 'fortigate-api') and not api_key and not (username and password):
            return jsonify({'success': False, 'error': 'Please provide either a REST API Token or Admin Username & Password'}), 400

        try:
            if vendor_id in PluginRegistry._api_clients:
                client_cls = PluginRegistry.get_api_client_cls(vendor_id)
                client = client_cls(**data)
                ir_config = client.extract_config()
                hostname = ir_config.metadata.hostname or host
            elif vendor_id == 'fortigate' or vendor_id == 'fortigate-api':
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
                hostname = fg_config.system_global.hostname if fg_config.system_global else host
            else:
                return jsonify({'success': False, 'error': f'Unsupported API vendor: {vendor_id}'}), 400

            # Cache in ACTIVE_SESSIONS
            session_id = str(uuid.uuid4())[:8]
            ACTIVE_SESSIONS[session_id] = {
                'ir_config': ir_config,
                'host': host,
                'source_vendor': vendor_id,
                'stats': {
                    'interfaces': len(ir_config.interfaces),
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
                'hostname': hostname,
                'stats': ACTIVE_SESSIONS[session_id]['stats']
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/diagnostics', methods=['POST'])
    def run_diagnostics():
        """Pre-flight diagnostic probe for Terraform CLI, Registry, and firewall target."""
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
        """Prepares Terraform deployment sandbox for target platform."""
        try:
            source_vendor = request.form.get('source_vendor', 'fortigate')
            target_vendor = request.form.get('target_vendor', 'palo_alto')
            ir_config = None
            fg_config = None

            if 'file' in request.files and request.files['file'].filename != '':
                file = request.files['file']
                content = file.read().decode('utf-8', errors='ignore')
                parser = PluginRegistry.get_parser(source_vendor)
                ir_config = parser.parse(content)
            else:
                session_id_input = request.form.get('session_id') or (request.get_json() or {}).get('session_id')
                if session_id_input and session_id_input in ACTIVE_SESSIONS:
                    if 'ir_config' in ACTIVE_SESSIONS[session_id_input]:
                        ir_config = ACTIVE_SESSIONS[session_id_input]['ir_config']
                    if 'fg_config' in ACTIVE_SESSIONS[session_id_input]:
                        fg_config = ACTIVE_SESSIONS[session_id_input]['fg_config']
                        if not ir_config:
                            transformer = FGToIRTransformer(fg_config)
                            ir_config = transformer.transform()

            if not ir_config:
                return jsonify({'error': 'No file uploaded or live API configuration found'}), 400

            # Target connection parameters
            host = request.form.get('host', '192.168.1.1').strip()
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            api_key = request.form.get('api_key', '').strip()
            vsys = request.form.get('vsys', 'vsys1').strip()
            device_group = request.form.get('device_group', 'shared').strip()

            # Generate target terraform artifacts
            tf_gen = PANOSTerraformGenerator(vsys=vsys, device_group=device_group)
            tf_artifacts = tf_gen.generate(ir_config)

            reporter = MigrationReporter(ir_config)
            report_content = reporter.generate_report()
            html_report_content = reporter.generate_html_report()

            # Create Sandbox
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

            with open(sandbox_dir / "migration_report.md", "w", encoding="utf-8") as f:
                f.write(report_content)
            with open(sandbox_dir / "migration_report.html", "w", encoding="utf-8") as f:
                f.write(html_report_content)

            secrets = [s for s in [password, api_key] if s]
            ACTIVE_SESSIONS[session_id] = {
                'sandbox': sandbox,
                'sandbox_dir': sandbox_dir,
                'secrets': secrets,
                'host': host,
                'stats': {
                    'interfaces': len(ir_config.interfaces),
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
        """Downloads current `terraform.tfstate`."""
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
        """Downloads session directory as ZIP."""
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


class DesktopAPI:
    """JS bridge API exposed to the pywebview desktop frontend."""
    def __init__(self, window=None):
        self._window = window

    def set_window(self, window):
        self._window = window

    def save_file_dialog(self, filename: str, base64_data: str) -> dict:
        """Prompts the user with a native Windows Save File dialog and writes the file."""
        import base64
        import os
        from pathlib import Path
        try:
            import webview
            raw_bytes = base64.b64decode(base64_data)
            ext = Path(filename).suffix.lower()
            if ext == '.zip':
                file_types = ('Zip Archive (*.zip)', 'All files (*.*)')
            elif ext in ('.json', '.tfstate'):
                file_types = ('JSON/State (*.json;*.tfstate)', 'All files (*.*)')
            elif ext == '.md':
                file_types = ('Markdown (*.md)', 'All files (*.*)')
            else:
                file_types = ('All files (*.*)',)

            default_dir = str(Path.home() / "Downloads")
            if not os.path.exists(default_dir):
                default_dir = str(Path.home() / "Desktop")

            save_path = None
            if self._window:
                dialog_type = getattr(webview, 'FileDialog', None)
                save_enum = webview.FileDialog.SAVE if (dialog_type and hasattr(dialog_type, 'SAVE')) else getattr(webview, 'SAVE_DIALOG', 30)
                res = self._window.create_file_dialog(
                    dialog_type=save_enum,
                    directory=default_dir,
                    save_filename=filename,
                    file_types=file_types
                )
                if res:
                    save_path = res[0] if isinstance(res, (list, tuple)) else res

            if not save_path:
                return {'success': False, 'cancelled': True}

            with open(save_path, 'wb') as f:
                f.write(raw_bytes)

            return {'success': True, 'path': str(save_path)}
        except Exception as e:
            return {'success': False, 'error': str(e)}


def run_desktop(port: int = 5000):
    """Launch the app inside a dedicated native desktop window via pywebview."""
    app = create_app()
    try:
        import webview
        api = DesktopAPI()
        window = webview.create_window(
            title="Firewall Migration Tool",
            url=app,
            width=1360,
            height=880,
            min_size=(960, 640),
            text_select=True,
            js_api=api
        )
        api.set_window(window)
        webview.start(gui='edgechromium')
    except ImportError:
        import webbrowser
        print(f"pywebview is not installed. Opening in default browser at http://localhost:{port}")
        webbrowser.open(f"http://localhost:{port}")
        app.run(host='127.0.0.1', port=port, debug=False)
