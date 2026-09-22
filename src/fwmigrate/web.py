import os
import sys
import io
import json
import uuid
import zipfile
import re
import hashlib
import logging
import threading
import time
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from flask import Flask, render_template, request, send_file, jsonify, Response, stream_with_context

from fwmigrate.builtin_plugins import register_builtin_plugins

register_builtin_plugins()

from fwmigrate.application.metrics import PipelineMetrics
from fwmigrate.report import (
    ExcelExportUnavailableError,
    ExcelExportProfile,
    XLSX_MIMETYPE,
)
from fwmigrate.source_reporting import source_reporters
from fwmigrate.engine.diagnostics import PaloAltoDiagnostics
from fwmigrate.engine.runner import TerraformSandbox, TerraformRunner

# In-memory session registry (session_id -> metadata/sandbox)
ACTIVE_SESSIONS = {}
_LOGGER = logging.getLogger(__name__)
@dataclass(frozen=True)
class _PreviewCacheEntry:
    preview_id: str
    source_vendor: str
    source_digest: str
    created_at: float
    analysis: object


_PREVIEW_CACHE: dict[str, _PreviewCacheEntry] = {}
_PREVIEW_CACHE_LOCK = threading.RLock()
_PREVIEW_CACHE_MAX_ENTRIES = 16
_PREVIEW_CACHE_TTL_SECONDS = 15 * 60


class ConfigurationDecodeError(ValueError):
    """Raised when an uploaded configuration cannot be decoded losslessly."""


def _conversion_unavailable():
    return jsonify({
        'error': (
            'Configuration conversion is temporarily unavailable while the '
            'pair-specific conversion architecture is being implemented.'
        ),
    }), 503


def _decode_configuration(raw: bytes) -> str:
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise ConfigurationDecodeError(
            "Configuration file is not valid UTF-8 near byte offset "
            f"{exc.start}. Extraction was stopped to avoid silent configuration loss."
        ) from exc


def _extract_source_result(source_vendor: str, content: str):
    reporter = source_reporters.get(source_vendor)
    return reporter.analyze_source(content)


def _extract_source_config(source_vendor: str, content: str):
    """Compatibility name for source-report analysis extraction."""
    return _extract_source_result(source_vendor, content)


def _source_digest(source_vendor: str, raw: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(raw)
    digest.update(b"\0")
    digest.update(source_vendor.encode("utf-8"))
    return digest.hexdigest()


def _cleanup_preview_cache(now: float | None = None) -> None:
    now = time.monotonic() if now is None else now
    expired = [
        preview_id
        for preview_id, entry in _PREVIEW_CACHE.items()
        if now - entry.created_at >= _PREVIEW_CACHE_TTL_SECONDS
    ]
    for preview_id in expired:
        _PREVIEW_CACHE.pop(preview_id, None)


def _cache_preview(source_vendor: str, raw: bytes, analysis) -> _PreviewCacheEntry:
    now = time.monotonic()
    source_digest = _source_digest(source_vendor, raw)
    with _PREVIEW_CACHE_LOCK:
        _cleanup_preview_cache(now)
        for entry in _PREVIEW_CACHE.values():
            if entry.source_vendor == source_vendor and entry.source_digest == source_digest:
                return entry
        while len(_PREVIEW_CACHE) >= _PREVIEW_CACHE_MAX_ENTRIES:
            oldest_id = min(_PREVIEW_CACHE, key=lambda key: _PREVIEW_CACHE[key].created_at)
            _PREVIEW_CACHE.pop(oldest_id, None)
        entry = _PreviewCacheEntry(
            preview_id=uuid.uuid4().hex,
            source_vendor=source_vendor,
            source_digest=source_digest,
            created_at=now,
            analysis=analysis,
        )
        _PREVIEW_CACHE[entry.preview_id] = entry
        return entry


def _lookup_preview(
    preview_id: str,
    source_vendor: str,
    raw: bytes | None = None,
) -> _PreviewCacheEntry | None:
    with _PREVIEW_CACHE_LOCK:
        _cleanup_preview_cache()
        entry = _PREVIEW_CACHE.get(str(preview_id or "").strip())
        if entry is None or entry.source_vendor != source_vendor:
            return None
        if raw is not None and entry.source_digest != _source_digest(source_vendor, raw):
            return None
        return entry


def _clone_preview(entry: _PreviewCacheEntry):
    return deepcopy(entry.analysis)


def _parse_bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _timed(metrics, stage, operation):
    if metrics is None:
        return operation()
    started = perf_counter()
    try:
        return operation()
    finally:
        metrics.add(stage, (perf_counter() - started) * 1000)


def _safe_vendor_filename(vendor_id: str) -> str:
    """Return a deterministic, filesystem-safe vendor identifier."""
    return re.sub(r'[^A-Za-z0-9_.-]+', '_', vendor_id).strip('._') or 'source'

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
        """Return registered source-reporting vendors."""
        sources = [
            {
                'vendor_id': reporter.vendor_id,
                'display_name': getattr(reporter, 'display_name', reporter.vendor_id),
                'file_extensions': list(reporter.supported_extensions),
            }
            for reporter in source_reporters.list()
        ]
        return jsonify({
            'success': True,
            'sources': sources,
            'targets': [],
        })

    @app.route('/api/preview', methods=['POST'])
    def preview_migration():
        """Read a source configuration and return a cheap, source-only preview."""
        try:
            source_vendor = request.form.get('source_vendor', 'fortigate')
            if 'file' not in request.files or request.files['file'].filename == '':
                return jsonify({'success': False, 'error': 'A configuration file is required'}), 400

            metrics = PipelineMetrics() if _parse_bool(request.form.get('collect_metrics')) else None
            started = perf_counter()
            file = request.files['file']
            raw_content = file.read()
            file_content = _timed(metrics, 'decode', lambda: _decode_configuration(raw_content))
            reporter = source_reporters.get(source_vendor)
            source_vendor = reporter.vendor_id
            analysis = _timed(
                metrics,
                'extraction',
                lambda: reporter.analyze_source(file_content),
            )
            preview_entry = _cache_preview(source_vendor, raw_content, analysis)
            report = _timed(metrics, 'preview', lambda: reporter.build_preview(analysis))
            response = {
                'success': True,
                'preview_id': preview_entry.preview_id,
                **report,
            }
            if metrics is not None:
                metrics.add('preview_total', (perf_counter() - started) * 1000)
                response['diagnostics'] = {'metrics': metrics.as_dict()}
            return jsonify(response)
        except ConfigurationDecodeError as e:
            return jsonify({'success': False, 'error': str(e), 'stage': 'decode'}), 400
        except KeyError as e:
            return jsonify({'success': False, 'error': str(e)}), 400
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/migrate', methods=['POST'])
    def migrate():
        """Conversion is disabled while pair-specific pipelines are rebuilt."""
        return _conversion_unavailable()

    @app.route('/api/extract/excel', methods=['POST'])
    def extract_excel():
        """Parse a source configuration and download its vendor-native report."""
        try:
            payload = request.get_json(silent=True) or {}
            source_vendor = request.form.get('source_vendor') or payload.get('source_vendor') or 'fortigate'
            preview_id = request.form.get('preview_id') or payload.get('preview_id') or ''
            metrics = (
                PipelineMetrics()
                if _parse_bool(request.form.get('collect_metrics') or payload.get('collect_metrics'))
                or _LOGGER.isEnabledFor(logging.DEBUG)
                else None
            )
            total_started = perf_counter()
            profile_value = request.form.get('excel_profile') or payload.get('excel_profile') or ExcelExportProfile.FAST.value
            try:
                profile = ExcelExportProfile(profile_value)
            except (TypeError, ValueError):
                return jsonify({'error': 'excel_profile must be one of: fast, full, data_only'}), 400
            reporter = source_reporters.get(source_vendor)
            source_vendor = reporter.vendor_id

            uploaded_file = request.files.get('file')
            raw_content = (
                _timed(metrics, 'request decode', uploaded_file.read)
                if uploaded_file is not None and uploaded_file.filename != ''
                else None
            )
            preview_entry = (
                _timed(
                    metrics,
                    'cache lookup',
                    lambda: _lookup_preview(preview_id, source_vendor, raw_content),
                )
                if preview_id
                else None
            )
            if preview_entry is not None:
                analysis = _clone_preview(preview_entry)
            else:
                if raw_content is None:
                    return jsonify({'error': 'A configuration file or valid preview_id is required for Excel extraction'}), 400
                file_content = _timed(
                    metrics,
                    'decode',
                    lambda: _decode_configuration(raw_content),
                )
                analysis = _timed(
                    metrics,
                    'extraction/fallback extraction',
                    lambda: _extract_source_config(source_vendor, file_content),
                )

            workbook = io.BytesIO()
            export_started = perf_counter()
            reporter.export_excel(analysis, workbook, profile=profile)
            export_elapsed = perf_counter() - export_started
            if metrics is not None:
                metrics.add('workbook construction', export_elapsed * 1000)
            workbook.seek(0)
            response = send_file(
                workbook,
                mimetype=XLSX_MIMETYPE,
                as_attachment=True,
                download_name=f'firewall_inventory_{_safe_vendor_filename(source_vendor)}.xlsx',
            )
            if metrics is not None:
                metrics.add('response preparation', (perf_counter() - export_started - export_elapsed) * 1000)
                metrics.total_duration_ms = (perf_counter() - total_started) * 1000
                _LOGGER.debug(
                    "Excel endpoint metrics: cache_hit=%s profile=%s %s",
                    bool(preview_entry),
                    profile.value,
                    metrics.as_dict(),
                )
            return response
        except ExcelExportUnavailableError as e:
            return jsonify({'error': str(e)}), 503
        except ConfigurationDecodeError as e:
            return jsonify({'error': str(e), 'stage': 'decode'}), 400
        except KeyError as e:
            return jsonify({'error': f'Vendor-native Excel is not available: {e}'}), 422
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/diagnostics', methods=['POST'])
    def run_diagnostics():
        """Pre-flight diagnostic probe for Terraform CLI, Registry, and firewall target."""
        data = request.get_json() or {}
        host = data.get('host', '').strip()
        port = int(data.get('port', 443))
        api_key = data.get('api_key', '').strip() or None
        username = data.get('username', '').strip() or None
        password = data.get('password', '').strip() or None
        verify_ssl = bool(data.get('verify_ssl', True))
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
        """Terraform preparation is disabled with legacy conversion."""
        return _conversion_unavailable()

    @app.route('/api/terraform/plan', methods=['POST'])
    def terraform_plan():
        """Executes `terraform init` and `terraform plan` in the session sandbox."""
        return _conversion_unavailable()

        data = request.get_json() or {}
        session_id = data.get('session_id')

        if not session_id or session_id not in ACTIVE_SESSIONS:
            return jsonify({'success': False, 'error': f'Session {session_id} not found or expired'}), 404

        session = ACTIVE_SESSIONS[session_id]
        sandbox_dir = session['sandbox_dir']
        secret_env = session.get('secret_env')
        secrets = session.get('secrets', [])

        try:
            runner = TerraformRunner(sandbox_dir=sandbox_dir, secrets=secrets, secret_env=secret_env)

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
        return _conversion_unavailable()

        session_id = request.args.get('session_id')

        if not session_id or session_id not in ACTIVE_SESSIONS:
            def error_gen():
                yield f"data: {json.dumps({'event': 'error', 'message': f'Session {session_id} not found'})}\n\n"
            return Response(error_gen(), mimetype='text/event-stream')

        session = ACTIVE_SESSIONS[session_id]
        
        # Security Boundary: Server-side apply gate
        status = session.get('status', 'CREATED')
        if status != 'APPROVED':
            def error_gen():
                yield f"data: {json.dumps({'event': 'error', 'message': f'Server-side rejection: Job is not APPROVED (current status: {status})'})}\n\n"
            return Response(error_gen(), mimetype='text/event-stream')

        sandbox_dir = session['sandbox_dir']
        secrets = session['secrets']
        secret_env = session.get('secret_env')

        def generate_sse():
            runner = TerraformRunner(sandbox_dir=sandbox_dir, secrets=secrets, secret_env=secret_env)
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
        return _conversion_unavailable()

        session_id = request.args.get('session_id')

        if not session_id or session_id not in ACTIVE_SESSIONS:
            def error_gen():
                yield f"data: {json.dumps({'event': 'error', 'message': f'Session {session_id} not found'})}\n\n"
            return Response(error_gen(), mimetype='text/event-stream')

        session = ACTIVE_SESSIONS[session_id]
        
        # Security Boundary: Server-side destroy gate
        status = session.get('status', 'CREATED')
        if status != 'APPROVED':
            def error_gen():
                yield f"data: {json.dumps({'event': 'error', 'message': f'Server-side rejection: Job is not APPROVED (current status: {status})'})}\n\n"
            return Response(error_gen(), mimetype='text/event-stream')
            
        sandbox_dir = session['sandbox_dir']
        secrets = session.get('secrets', [])
        secret_env = session.get('secret_env')

        def generate_sse():
            runner = TerraformRunner(sandbox_dir=sandbox_dir, secrets=secrets, secret_env=secret_env)
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

    @app.route('/api/terraform/approve', methods=['POST'])
    def terraform_approve():
        return _conversion_unavailable()

        data = request.get_json() or {}
        session_id = data.get('session_id')
        if not session_id or session_id not in ACTIVE_SESSIONS:
            return jsonify({'success': False, 'error': f'Session {session_id} not found'}), 404
            
        session = ACTIVE_SESSIONS[session_id]
        if session.get('status') == 'REVIEW_REQUIRED':
            session['status'] = 'APPROVED'
            return jsonify({'success': True, 'message': 'Session approved for deployment.'})
        return jsonify({'success': False, 'error': f'Invalid status: {session.get("status")}'}), 400

    @app.route('/api/download/state')
    def download_state():
        """Downloads current `terraform.tfstate`."""
        return _conversion_unavailable()

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
        return _conversion_unavailable()

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
            elif ext == '.xlsx':
                file_types = ('Excel Workbook (*.xlsx)', 'All files (*.*)')
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
