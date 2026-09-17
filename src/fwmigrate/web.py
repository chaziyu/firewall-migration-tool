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
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from flask import Flask, render_template, request, send_file, jsonify, Response, stream_with_context

from fwmigrate.builtin_plugins import register_builtin_plugins

register_builtin_plugins()

from fwmigrate.core.registry import PluginRegistry
from fwmigrate.core.optimizer import RuleOptimizer
from fwmigrate.application import MigrationPipeline, MigrationRequest
from fwmigrate.application.metrics import PipelineMetrics
from fwmigrate.report import (
    ExcelExportUnavailableError,
    ExcelExportOptions,
    ExcelExportProfile,
    IRExcelExporter,
    StreamingFastExcelExporter,
    XLSX_MIMETYPE,
)
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
    ir_config: object
    extraction_result: object


_PREVIEW_CACHE: dict[str, _PreviewCacheEntry] = {}
_PREVIEW_CACHE_LOCK = threading.RLock()
_PREVIEW_CACHE_MAX_ENTRIES = 16
_PREVIEW_CACHE_TTL_SECONDS = 15 * 60


class ConfigurationDecodeError(ValueError):
    """Raised when an uploaded configuration cannot be decoded losslessly."""


def _decode_configuration(raw: bytes) -> str:
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise ConfigurationDecodeError(
            "Configuration file is not valid UTF-8 near byte offset "
            f"{exc.start}. Extraction was stopped to avoid silent configuration loss."
        ) from exc


def _extract_source_result(source_vendor: str, content: str):
    return PluginRegistry.get_parser(source_vendor).extract(content)


def _extract_source_config(source_vendor: str, content: str):
    """Return canonical IR and optional authoritative source accounting."""
    extraction_result = _extract_source_result(source_vendor, content)
    has_accounting = bool(
        extraction_result.source_sections
        or extraction_result.inventory_items
        or extraction_result.unsupported_items
    )
    return extraction_result.canonical_ir, (extraction_result if has_accounting else None)


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


def _cache_preview(source_vendor: str, raw: bytes, extraction_result) -> _PreviewCacheEntry:
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
            ir_config=extraction_result.canonical_ir,
            extraction_result=extraction_result,
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
    return deepcopy(entry.ir_config), deepcopy(entry.extraction_result)


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


def _ir_stats(ir_config):
    return {
        "zones": len(ir_config.zones),
        "interfaces": len(ir_config.interfaces),
        "addresses": len(ir_config.addresses),
        "address_groups": len(ir_config.address_groups),
        "services": len(ir_config.services),
        "service_groups": len(ir_config.service_groups),
        "policies": len(ir_config.policies),
        "nat_rules": len(ir_config.nat_rules),
        "routes": len(ir_config.routes),
    }


def _policy_preview(ir_config):
    return [
        {
            "id": policy.name,
            "index": index,
            "from_zone": policy.from_zone,
            "to_zone": policy.to_zone,
            "source": policy.source,
            "destination": policy.destination,
            "service": policy.service,
            "action": policy.action.value if policy.action else None,
            "disabled": policy.disabled,
            "description": policy.description or "",
        }
        for index, policy in enumerate(ir_config.policies[:50], 1)
    ]


def _extraction_summary(extraction):
    statuses = Counter(
        getattr(item.status, "value", item.status)
        for item in extraction.inventory_items
    )
    return {
        "generation_safe": extraction.generation_safe,
        "requires_manual_review": extraction.requires_manual_review,
        "migration_complete": extraction.migration_complete,
        "blocking_reasons": extraction.blocking_reasons,
        "accounting": {
            "source_sections": len(extraction.source_sections),
            "coverage_sections": len(extraction.coverage),
            "inventory_items": len(extraction.inventory_items),
            "unsupported_items": len(extraction.unsupported_items),
            "dependencies": len(extraction.dependencies),
            "inventory_status": dict(statuses),
        },
    }


def _ir_preview_fields(ir_config):
    return {
        "hostname": ir_config.metadata.hostname,
        "source_vendor": ir_config.metadata.source_vendor,
        "stats": _ir_stats(ir_config),
        "policies": _policy_preview(ir_config),
    }


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
        """Returns lists of supported source vendors and target platforms."""
        return jsonify({
            'success': True,
            'sources': PluginRegistry.list_source_vendors(),
            'targets': PluginRegistry.list_target_vendors()
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
            extraction = _timed(
                metrics,
                'extraction',
                lambda: _extract_source_result(source_vendor, file_content),
            )
            ir_config = extraction.canonical_ir

            if not ir_config:
                return jsonify({'success': False, 'error': 'Failed to extract configuration from file'}), 400

            preview_entry = _cache_preview(source_vendor, raw_content, extraction)
            response = {
                'success': True,
                'preview_id': preview_entry.preview_id,
                **_ir_preview_fields(ir_config),
                'extraction': _extraction_summary(extraction),
                'optimization': {'status': 'not_analyzed'},
                'generation_allowed': 'not_evaluated',
                'blocking_reasons': extraction.blocking_reasons,
                'requires_manual_review': extraction.requires_manual_review,
            }
            if metrics is not None:
                metrics.add('preview_total', (perf_counter() - started) * 1000)
                response['diagnostics'] = {'metrics': metrics.as_dict()}
            return jsonify(response)
        except ConfigurationDecodeError as e:
            return jsonify({'success': False, 'error': str(e), 'stage': 'decode'}), 400
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/analyze', methods=['POST'])
    def analyze_migration():
        """Run full migration and optional optimizer analysis on explicit request."""
        try:
            source_vendor = request.form.get('source_vendor', 'fortigate')
            if 'file' not in request.files or request.files['file'].filename == '':
                return jsonify({'success': False, 'error': 'A configuration file is required'}), 400

            analyze_unused = _parse_bool(request.form.get('analyze_unused'))
            analyze_duplicates = _parse_bool(request.form.get('analyze_duplicates'))
            analyze_shadowing = _parse_bool(request.form.get('analyze_shadowing'))
            target_vendor = request.form.get('target_vendor') or None
            analyze_capabilities = _parse_bool(
                request.form.get('analyze_capabilities'),
                default=bool(target_vendor),
            )
            analysis_started = perf_counter()
            file = request.files['file']
            file_content = _decode_configuration(file.read())
            analysis = MigrationPipeline().analyze(MigrationRequest(
                source_vendor=source_vendor,
                target_vendor=target_vendor if analyze_capabilities else None,
                target_version=request.form.get('target_version') or None,
                source_content=file_content,
                target_format='all',
                source_name=file.filename,
                collect_metrics=True,
            ))
            ir_config = analysis.final_ir or analysis.source_ir
            if not ir_config:
                return jsonify({'success': False, 'error': 'Failed to analyze configuration'}), 400

            optimization = {'status': 'not_analyzed'}
            if any((
                analyze_unused,
                analyze_duplicates,
                analyze_shadowing,
            )):
                optimizer = RuleOptimizer(
                    ir_config,
                    ir_index=analysis._ir_index,
                    dependency_graph=analysis._dependency_graph,
                )
                optimizer_started = perf_counter()

                def run_optimizer(stage, operation):
                    started = perf_counter()
                    try:
                        return operation()
                    finally:
                        analysis.metrics.add(stage, (perf_counter() - started) * 1000)

                unused = run_optimizer(
                    'preview_unused', optimizer.find_unused_objects,
                ) if analyze_unused else {}
                duplicates = run_optimizer(
                    'preview_duplicates', optimizer.find_duplicate_objects,
                ) if analyze_duplicates else {}
                shadowed = run_optimizer(
                    'preview_shadowed', optimizer.find_shadowed_rules,
                ) if analyze_shadowing else []
                optimizer_ms = (perf_counter() - optimizer_started) * 1000
                analysis.metrics.add('preview_total', optimizer_ms)
                analysis.metrics.total_duration_ms += optimizer_ms
                optimization = {
                    'status': 'analyzed',
                    'unused_addresses_count': len(unused.get('unused_addresses', [])),
                    'unused_services_count': len(unused.get('unused_services', [])),
                    'duplicate_address_groups_count': len(duplicates.get('duplicate_addresses', [])),
                    'shadowed_rules_count': len(shadowed),
                    'shadowed_rules': shadowed,
                }

            analysis_total_ms = (perf_counter() - analysis_started) * 1000
            analysis.metrics.add('analysis_total', analysis_total_ms)
            analysis.metrics.total_duration_ms = analysis_total_ms
            response = {
                'success': True,
                **_ir_preview_fields(ir_config),
                'extraction': _extraction_summary(analysis.extraction),
                'optimization': optimization,
                'generation_allowed': analysis.generation_allowed,
                'blocking_reasons': analysis.blocking_reasons,
                'requires_manual_review': analysis.requires_manual_review,
                'diagnostics': {'metrics': analysis.metrics.as_dict()},
            }
            if analysis.capability_analysis is not None:
                response['capability_analysis'] = analysis.capability_analysis.to_dict()
            return jsonify(response)
        except ConfigurationDecodeError as e:
            return jsonify({'success': False, 'error': str(e), 'stage': 'decode'}), 400
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/migrate', methods=['POST'])
    def migrate():
        """Generate a multi-vendor migration bundle."""
        try:
            source_vendor = request.form.get('source_vendor', 'fortigate')
            target_vendor = request.form.get('target_vendor', 'palo_alto')
            optimize = request.form.get('optimize', 'false').lower() == 'true'
            include_inventory = request.form.get('include_inventory', 'true').lower() == 'true'

            if 'file' not in request.files or request.files['file'].filename == '':
                return jsonify({'error': 'A configuration file is required'}), 400

            file = request.files['file']
            file_content = _decode_configuration(file.read())
            result = MigrationPipeline().run(MigrationRequest(
                source_vendor=source_vendor,
                target_vendor=target_vendor,
                source_content=file_content,
                target_format='all',
                optimize=optimize,
                source_name=file.filename,
            ))

            if not result.generation_allowed:
                return jsonify({
                    'error': 'Migration blocked: generation safety checks failed.',
                    'blocking_reasons': result.blocking_reasons,
                    'requires_manual_review': result.requires_manual_review,
                    'capability_analysis': (
                        result.capability_analysis.to_dict()
                        if result.capability_analysis else None
                    ),
                }), 422

            ir_config = result.final_ir
            if ir_config is None or result.source_ir is None:
                return jsonify({'error': 'Failed to extract configuration from file'}), 400

            artifacts = result.artifacts
            source_inventory = None
            if include_inventory:
                # The inventory must represent parser output, before normalization or pruning.
                source_inventory = IRExcelExporter(
                    result.source_ir,
                    extraction_result=result.extraction,
                ).generate()

            # Package into ZIP
            memory_file = io.BytesIO()
            with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
                for art in artifacts:
                    fname = f"terraform/{art.filename}" if art.format == "terraform" else art.filename
                    zf.writestr(fname, art.content)
                if include_inventory:
                    inventory_name = f"source_inventory_{_safe_vendor_filename(source_vendor)}.xlsx"
                    zf.writestr(inventory_name, source_inventory)

            memory_file.seek(0)
            return send_file(
                memory_file,
                mimetype='application/zip',
                as_attachment=True,
                download_name=f'migration_{source_vendor}_to_{target_vendor}.zip'
            )

        except ExcelExportUnavailableError as e:
            return jsonify({'error': str(e)}), 503
        except ConfigurationDecodeError as e:
            return jsonify({'error': str(e), 'stage': 'decode'}), 400
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/extract/excel', methods=['POST'])
    def extract_excel():
        """Parse a source configuration and download its vendor-neutral IR inventory."""
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
                ir_config, extraction_result = _clone_preview(preview_entry)
            else:
                if raw_content is None:
                    return jsonify({'error': 'A configuration file or valid preview_id is required for Excel extraction'}), 400
                file_content = _timed(
                    metrics,
                    'decode',
                    lambda: _decode_configuration(raw_content),
                )
                ir_config, extraction_result = _timed(
                    metrics,
                    'extraction/fallback extraction',
                    lambda: _extract_source_config(source_vendor, file_content),
                )

            if not ir_config:
                return jsonify({'error': 'Failed to extract configuration from file'}), 400
                
            ir_config.metadata.input_type = "Configuration File"

            workbook = io.BytesIO()
            exporter_type = (
                StreamingFastExcelExporter
                if profile is ExcelExportProfile.FAST
                else IRExcelExporter
            )
            exporter = exporter_type(
                ir_config,
                extraction_result=extraction_result,
                options=ExcelExportOptions(profile=profile),
            )
            generate_to = getattr(exporter, 'generate_to', None)
            export_started = perf_counter()
            if generate_to is None:
                workbook.write(exporter.generate())
            else:
                generate_to(workbook)
            export_elapsed = perf_counter() - export_started
            exporter_metrics = getattr(exporter, '_last_export_metrics', None)
            if metrics is not None:
                if exporter_metrics is None:
                    metrics.add('workbook construction', export_elapsed * 1000)
                else:
                    for stage, elapsed in exporter_metrics.timings.items():
                        metrics.add(stage, elapsed * 1000)
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
        """Prepares Terraform deployment sandbox for target platform."""
        try:
            source_vendor = request.form.get('source_vendor', 'fortigate')
            target_vendor = request.form.get('target_vendor', 'palo_alto')
            if 'file' not in request.files or request.files['file'].filename == '':
                return jsonify({'error': 'A configuration file is required'}), 400

            file = request.files['file']
            file_content = _decode_configuration(file.read())
            # Target connection parameters
            host = request.form.get('host', '192.168.1.1').strip()
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            api_key = request.form.get('api_key', '').strip()
            vsys = request.form.get('vsys', 'vsys1').strip()
            device_group = request.form.get('device_group', 'shared').strip()

            # Generate target terraform artifacts through the shared migration pipeline.
            result = MigrationPipeline().run(MigrationRequest(
                source_vendor=source_vendor,
                target_vendor='palo_alto',
                source_content=file_content,
                target_format='terraform',
                source_name=file.filename,
                target_options={'vsys': vsys, 'device_group': device_group},
            ))
            if not result.generation_allowed:
                return jsonify({
                    'error': 'Migration blocked: generation safety checks failed.',
                    'blocking_reasons': result.blocking_reasons,
                    'requires_manual_review': result.requires_manual_review,
                }), 422

            ir_config = result.final_ir
            if ir_config is None:
                return jsonify({'error': 'Failed to extract configuration from file'}), 400
            tf_artifacts = result.artifacts

            # Create Sandbox
            session_id = str(uuid.uuid4())
            sandbox = TerraformSandbox(session_id=session_id)

            tfvars = {
                'panos_hostname': host,
                'panos_username': username,
                'panos_vsys': vsys,
                'panos_device_group': device_group,
            }

            sandbox_dir = sandbox.create(tf_artifacts, tfvars=tfvars)

            secrets = [s for s in [password, api_key] if s]
            secret_env = {}
            if password:
                secret_env['TF_VAR_panos_password'] = password
            if api_key:
                secret_env['TF_VAR_panos_api_key'] = api_key

            ACTIVE_SESSIONS[session_id] = {
                'status': 'REVIEW_REQUIRED',
                'sandbox': sandbox,
                'sandbox_dir': sandbox_dir,
                'secrets': secrets,
                'secret_env': secret_env,
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

        except ConfigurationDecodeError as e:
            return jsonify({'success': False, 'error': str(e), 'stage': 'decode'}), 400
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
