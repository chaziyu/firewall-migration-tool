import atexit
import os
import sys
import io
import uuid
import re
import hashlib
import logging
import threading
import time
import json
import zipfile
import yaml
from dataclasses import asdict, replace
from copy import deepcopy
from dataclasses import dataclass
from time import perf_counter
from flask import Flask, render_template, request, send_file, jsonify

from fwmigrate.source_reporting.builtin import register_builtin_source_reporters
from fwmigrate.conversion.builtin import register_builtin_migration_planners
from fwmigrate.conversion import migration_planners
from fwmigrate.conversion.fortigate_to_palo_alto import (
    PANDecisionMode,
    PANDecisionReviewState,
    PANMigrationDecision,
    PANMigrationDecisionSet,
    PANMigrationOptions,
    build_decision_set,
    make_decision_key,
    build_recommendations,
)
from fwmigrate.conversion.fortigate_to_palo_alto.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.requirements import build_mapping_requirements
from fwmigrate.conversion.fortigate_to_palo_alto.target_suggestions import (
    discover_target_candidates, suggest_from_target, target_devices, target_device_metadata,
)
from fwmigrate.conversion.fortigate_to_palo_alto.target_validation import validate_against_target
from fwmigrate.conversion.fortigate_to_palo_alto.review_context import build_review_context
from fwmigrate.conversion.fortigate_to_palo_alto.review_workflow import build_review_workflow
from fwmigrate.conversion.fortigate_to_palo_alto.decision_propagation import (
    MigrationRuleType, apply_repeated_zone_action, apply_zone_to_members,
    rule_affected_decision_keys,
)
from fwmigrate.conversion.fortigate_to_palo_alto.auto_decisions import classify_auto_decisions
from fwmigrate.conversion.fortigate_to_palo_alto.automation import AutomationPolicy, run_automation_until_stable
from fwmigrate.conversion.fortigate_to_palo_alto.target_intent import apply_target_intent, export_target_intent
from fwmigrate.conversion.fortigate_to_palo_alto.target_object_reuse import (
    classify_target_object_reuse,
)
from fwmigrate.conversion.fortigate_to_palo_alto.artifact_status import classify_artifact_status
from fwmigrate.conversion.fortigate_to_palo_alto.plan_dependencies import build_plan_dependency_index, item_key
from fwmigrate.conversion.fortigate_to_palo_alto.target_plan_validation import (
    assess_target_plan, validate_target_plan,
)
from fwmigrate.conversion.fortigate_to_palo_alto.support_guidance import build_support_guidance
from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan
from fwmigrate.deployment import PANDeploymentOptions, PANSSHDeployer
from fwmigrate.collection import CollectionStatus, source_collectors
from fwmigrate.collection.builtin import register_builtin_collectors
from fwmigrate.collection.snapshot import make_snapshot, parse_snapshot, MAX_BYTES
from fwmigrate.ai.config import get_ai_settings
from fwmigrate.ai.errors import AIError
from fwmigrate.conversion.fortigate_to_palo_alto.ai import (
    explain_review_group, generate_architecture_questions, proposal_cache,
)

register_builtin_source_reporters()
register_builtin_migration_planners()

from fwmigrate.source_reporting import (
    ExcelExportUnavailableError,
    ExcelExportProfile,
    SourceReportMetrics,
    ExcelExportMetrics,
    XLSX_MIMETYPE,
    source_reporters,
)
from fwmigrate.source_reporting.web_report import normalize_web_report
_LOGGER = logging.getLogger(__name__)
_DECISION_FORMAT_VERSION = 2


def _decision_document(source_digest, decision_set, target_evidence=None):
    document = {
        "format_version": _DECISION_FORMAT_VERSION,
        "source_vendor": "fortigate",
        "target_vendor": "palo_alto",
        "source_digest": source_digest,
        "decisions": [item.to_dict() for item in decision_set.decisions],
    }
    if target_evidence:
        document["target_evidence"] = target_evidence
    return document


def _deployment_validation_feedback(rendered, decision_document, validation):
    if getattr(validation, 'status', None) != 'FAILED':
        return None
    response = str(getattr(validation, 'response', '') or '')
    decisions = decision_document.get('decisions', ()) if isinstance(decision_document, dict) else ()
    items = rendered.report.get('items', ())
    matches = [item for item in items if item.get('target_name') and
               re.search(rf'(?<![A-Za-z0-9_.-]){re.escape(item["target_name"])}(?![A-Za-z0-9_.-])', response, re.I)]
    candidates = []
    known_decisions = {decision.get('key') for decision in decisions if isinstance(decision, dict)}
    for item in matches:
        item_decisions = [key for key in item.get('decision_keys', ()) if key in known_decisions]
        candidates.append({**{key: item.get(key) for key in
            ('source_vdom', 'source_kind', 'source_name', 'target_name')},
            'decision_keys': item_decisions, 'generated_commands': list(item.get('commands', ()))})
    return {'status': 'FAILED', 'message': response,
            'mapping_status': 'MAPPED' if len(candidates) == 1 else 'AMBIGUOUS' if candidates else 'UNMAPPED',
            'migration_items': candidates}


def _decision_evidence(decision_set, target_findings):
    conflicts = {item.decision_key for item in target_findings}
    return {
        item.key: (
            "CONFLICT" if item.key in conflicts else
            "ENGINEER" if item.review_state is PANDecisionReviewState.CONFIRMED else
            item.evidence_source or "SOURCE"
        )
        for item in decision_set.decisions
    }


def _auto_review_results(config, derived, decisions, target, device):
    results = classify_auto_decisions(config, derived, decisions, target, device)
    for finding in validate_against_target(config, decisions, target, device):
        result = results.setdefault(finding.decision_key, {})
        result.update(status="CONFLICT", reason=finding.message)
    return results


def _evidence_summary(decision_set, evidence):
    values = [evidence[item.key] for item in decision_set.decisions]
    return {
        "target_backed": values.count("TARGET"),
        "source_only": values.count("SOURCE"),
        "conflicts": values.count("CONFLICT"),
        "required": sum(item.mode == PANDecisionMode.REQUIRED and item.review_state != PANDecisionReviewState.CONFIRMED
                         for item in decision_set.decisions),
        "confirmed": sum(item.review_state == PANDecisionReviewState.CONFIRMED for item in decision_set.decisions),
    }


def _load_decision_document(document, source_digest):
    if not isinstance(document, dict) or document.get("format_version") not in {1, _DECISION_FORMAT_VERSION}:
        raise ValueError("Unsupported migration decision document")
    if document.get("source_vendor") != "fortigate" or document.get("target_vendor") != "palo_alto":
        raise ValueError("Migration decision document must be fortigate -> palo_alto")
    if document.get("source_digest") != source_digest:
        raise ValueError("Migration decisions belong to a different source configuration")
    return PANMigrationDecisionSet.from_dict({"decisions": document.get("decisions")})


def _target_evidence_changed(document, target_context):
    previous = document.get("target_evidence") if isinstance(document, dict) else None
    return bool(
        isinstance(previous, dict)
        and previous.get("config_digest")
        and target_context
        and previous["config_digest"] != target_context.source_digest
    )


def _options_mapping(options):
    return {
        "vdoms": {name: {key: value for key, value in asdict(item).items() if value is not None}
                   for name, item in options.vdoms.items()},
        "interfaces": {vdom: {name: {key: value for key, value in asdict(item).items() if value is not None}
                              for name, item in mappings.items()}
                       for vdom, mappings in options.interfaces.items()},
    }


def _confirm_mapping_decisions(decision_set, options, config):
    decisions = {item.key: item for item in decision_set.decisions}
    zone_names = {(item.vdom or "root", item.name) for item in getattr(config, "zones", ())}

    def confirm(vdom, kind, name, field, value):
        if value is None:
            return
        key = make_decision_key(vdom, kind, name, field)
        old = decisions.get(key)
        if old is None:
            old = PANMigrationDecision(vdom, kind, name, field, mode=PANDecisionMode.REQUIRED)
        decisions[key] = replace(old, value=value, review_state=PANDecisionReviewState.CONFIRMED)

    for vdom, mapping in options.vdoms.items():
        for field, value in asdict(mapping).items():
            confirm(vdom, "vdom", vdom, field, value)
    for vdom, mappings in options.interfaces.items():
        for name, mapping in mappings.items():
            for field, value in asdict(mapping).items():
                kinds = ({"interface"} if field == "target_interface" else
                         {kind for kind in ("interface", "zone") if make_decision_key(vdom, kind, name, field) in decisions})
                if not kinds:
                    kinds = {"zone" if (vdom, name) in zone_names and field == "target_zone" else "interface"}
                for kind in kinds:
                    confirm(vdom, kind, name, field, value)
    return PANMigrationDecisionSet(tuple(sorted(decisions.values(), key=lambda item: item.key)))
@dataclass(frozen=True)
class _PreviewCacheEntry:
    preview_id: str
    source_vendor: str
    source_digest: str
    created_at: float
    analysis: object
    source_name: str | None = None


_PREVIEW_CACHE: dict[str, _PreviewCacheEntry] = {}
_PREVIEW_CACHE_LOCK = threading.RLock()
_PREVIEW_CACHE_MAX_ENTRIES = 16
_PREVIEW_CACHE_TTL_SECONDS = 15 * 60


class ConfigurationDecodeError(ValueError):
    """Raised when an uploaded configuration cannot be decoded losslessly."""


def _conversion_unavailable():
    return jsonify({
        'error': (
            'Migration planning is temporarily unavailable while the '
            'pair-specific planning architecture is being implemented.'
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


def _cache_preview(source_vendor: str, raw: bytes, analysis, source_name: str | None = None) -> _PreviewCacheEntry:
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
            source_name=source_name,
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


@dataclass(frozen=True)
class _TargetEvidenceContext:
    analysis: object
    source_digest: str
    devices: tuple[str, ...]
    selected_device: str | None

    @property
    def metadata(self):
        return {"vendor": "palo_alto", "config_digest": self.source_digest, "device": self.selected_device}


def _target_evidence(payload):
    preview_id = payload.get('target_preview_id')
    if not preview_id:
        return None
    entry = _lookup_preview(preview_id, 'palo_alto')
    if entry is None:
        raise ValueError('A valid PAN-OS target preview_id is required')
    analysis = _clone_preview(entry)
    devices = target_devices(analysis)
    selected = payload.get('target_device') or (devices[0] if len(devices) == 1 else None)
    if selected and selected not in devices:
        raise ValueError('Selected target device is not in the uploaded PAN-OS configuration')
    return _TargetEvidenceContext(analysis, entry.source_digest, tuple(devices), selected)


def _build_migration_review_state(entry, payload):
    """Build the deterministic migration review from a cached source preview."""
    analysis = _clone_preview(entry)
    requirements = build_mapping_requirements(analysis.extracted.config, analysis.derived)
    prior = payload.get('decision_document')
    previous = _load_decision_document(prior, entry.source_digest) if prior is not None else None
    decisions = build_decision_set(analysis.extracted.config, analysis.derived, requirements, previous)
    target_context = _target_evidence(payload)
    target = target_context.analysis if target_context else None
    device = target_context.selected_device if target_context else None
    candidates = discover_target_candidates(analysis.extracted.config, decisions, target, device) if target and device else {}
    target_warnings = {}
    if target and device:
        decisions, target_warnings = suggest_from_target(analysis.extracted.config, decisions, target, device)
    findings = validate_against_target(analysis.extracted.config, decisions, target, device)
    auto = _auto_review_results(analysis.extracted.config, analysis.derived, decisions, target, device)
    evidence = _decision_evidence(decisions, findings)
    context = build_review_context(analysis.extracted.config, decisions, candidates=candidates,
        target_available=target is not None, target_selected=bool(device),
        target_device_count=len(target_context.devices) if target_context else 0)
    workflow = build_review_workflow(analysis.extracted.config, decisions, candidates=candidates,
        context=context, decision_evidence=evidence, target_warnings=target_warnings)
    recommendations = build_recommendations(analysis.extracted.config, analysis.derived, decisions, target, device)
    return {
        'analysis': analysis,
        'requirements': requirements,
        'target_context': target_context,
        'source_digest': entry.source_digest,
        'target_digest': target_context.source_digest if target_context else None,
        'target_device': device,
        'decisions': decisions,
        'decision_candidates': candidates,
        'review_workflow': workflow,
        'review_context': context,
        'auto_decisions': auto,
        'target_findings': findings,
        'decision_evidence': evidence,
        'target_warnings': target_warnings,
        'recommendations': recommendations,
        'target_evidence_changed': _target_evidence_changed(prior, target_context),
    }


def _build_ai_review_state(payload):
    """Rebuild AI inputs from server-held previews and the current decision document."""
    entry = _lookup_preview(payload.get('preview_id'), 'fortigate')
    if entry is None:
        raise ValueError('A valid FortiGate preview_id is required')
    return _build_migration_review_state(entry, payload)


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
    register_builtin_collectors()
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

    rendered_artifacts = {}
    artifact_sources = {}

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
                'web_report': True,
                'live_collection': reporter.vendor_id in {collector.vendor_id for collector in source_collectors.list()},
                'collection': ({'method': source_collectors.get(reporter.vendor_id).method,
                                'connection_fields': source_collectors.get(reporter.vendor_id).fields}
                               if reporter.vendor_id in {collector.vendor_id for collector in source_collectors.list()} else None),
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

            metrics = SourceReportMetrics() if _parse_bool(request.form.get('collect_metrics')) else None
            started = perf_counter()
            file = request.files['file']
            raw_content = file.read()
            file_content = _timed(metrics, 'decode', lambda: _decode_configuration(raw_content))
            reporter = source_reporters.get(source_vendor)
            source_vendor = reporter.vendor_id
            analysis = _timed(
                metrics,
                'extraction',
                lambda: reporter.analyze_source(file_content, metrics=metrics),
            )
            preview_entry = _cache_preview(source_vendor, raw_content, analysis, os.path.basename(file.filename))
            report = _timed(metrics, 'web_preview_construction', lambda: normalize_web_report(reporter.build_preview(analysis), source_vendor))
            response = {
                'success': True,
                'preview_id': preview_entry.preview_id,
                **report,
            }
            if metrics is not None:
                metrics.total_duration_ms = (perf_counter() - started) * 1000
                metrics.add('preview_total', metrics.total_duration_ms)
                response['diagnostics'] = {'metrics': metrics.as_dict()}
            return jsonify(response)
        except ConfigurationDecodeError as e:
            return jsonify({'success': False, 'error': str(e), 'stage': 'decode'}), 400
        except KeyError as e:
            return jsonify({'success': False, 'error': str(e)}), 400
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    def collection_options():
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            raise ValueError('Collection request must be a JSON object.')
        collector = source_collectors.get(payload.get('vendor'))
        return collector, collector.validate_options(payload.get('connection'))

    @app.route('/api/collection/test', methods=['POST'])
    def test_collection_connection():
        try:
            collector, options = collection_options()
        except ValueError as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400
        try:
            collector.test_connection(options)
            return jsonify({'success': True, 'status': 'CONNECTED'})
        except Exception:
            return jsonify({'success': False, 'error': 'Connection failed. Check the device and credentials.'}), 502

    @app.route('/api/collection/collect', methods=['POST'])
    def collect_configuration():
        try:
            collector, options = collection_options()
        except ValueError as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400
        try:
            source = collector.collect(options)
            if source.status == CollectionStatus.FAILED or not source.source_text.strip():
                return jsonify({'success': False, 'error': 'Collection returned no usable source.'}), 502
            snapshot = make_snapshot(source)
            raw = snapshot['source_text'].encode('utf-8')
            reporter = source_reporters.get(source.vendor_id)
            analysis = reporter.analyze_source(snapshot['source_text'])
            entry = _cache_preview(source.vendor_id, raw, analysis, source.source_name)
            return jsonify({
                'success': True,
                'preview_id': entry.preview_id,
                'collection': {'vendor': source.vendor_id, 'method': source.method, 'status': source.status.value,
                               'parts': snapshot['parts'], 'warnings': snapshot['warnings']},
                'preview': normalize_web_report(reporter.build_preview(analysis), source.vendor_id),
                'snapshot': snapshot,
            })
        except Exception:
            return jsonify({'success': False, 'error': 'Collection or extraction failed. Check the device configuration and connection.'}), 502

    @app.route('/api/collection/snapshot/import', methods=['POST'])
    def import_collection_snapshot():
        try:
            uploaded = request.files.get('file')
            raw = uploaded.read(MAX_BYTES + 1) if uploaded else request.stream.read(MAX_BYTES + 1)
            source = parse_snapshot(raw)
            reporter = source_reporters.get(source.vendor_id)
            analysis = reporter.analyze_source(source.source_text)
            entry = _cache_preview(source.vendor_id, source.source_text.encode('utf-8'), analysis, source.source_name)
            return jsonify({'success': True, 'vendor_id': source.vendor_id, 'preview_id': entry.preview_id,
                            'collection': {'status': source.status.value, 'parts': [asdict(part) for part in source.parts],
                                           'warnings': source.warnings}, 'preview': normalize_web_report(reporter.build_preview(analysis), source.vendor_id)})
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid or unsupported collection snapshot.'}), 400
        except Exception:
            return jsonify({'success': False, 'error': 'Snapshot import failed.'}), 400

    @app.route('/api/migration/requirements', methods=['POST'])
    def migration_requirements():
        payload = request.get_json(silent=True) or request.form
        try:
            preview_id = payload.get('preview_id')
            entry = _lookup_preview(preview_id, 'fortigate') if preview_id else None
            if entry is None:
                uploaded = request.files.get('file')
                if uploaded is None or not uploaded.filename:
                    return jsonify({'success': False, 'error': 'A valid preview_id or configuration file is required'}), 400
                raw = uploaded.read()
                analysis = source_reporters.get('fortigate').analyze_source(_decode_configuration(raw))
                entry = _cache_preview('fortigate', raw, analysis, os.path.basename(uploaded.filename))
            state = _build_migration_review_state(entry, payload)
            target_context = state['target_context']
            target = target_context.analysis if target_context else None
            decisions = state['decisions']
            return jsonify({'success': True, 'preview_id': entry.preview_id, 'requirements': state['requirements'],
                            'decisions': decisions.to_dict(),
                            'decision_document': _decision_document(entry.source_digest, decisions,
                                                                     target_context.metadata if target_context else None),
                            'target_devices': list(target_context.devices) if target_context else [],
                            'target_device': state['target_device'],
                            'target_device_metadata': target_device_metadata(target) if target else [],
                            'decision_context': state['review_context'],
                            'decision_candidates': state['decision_candidates'],
                            **state['review_workflow'],
                            'target_warnings': state['target_warnings'],
                            'target_findings': [item.to_dict() for item in state['target_findings']],
                            'decision_evidence': state['decision_evidence'],
                            'auto_decisions': state['auto_decisions'],
                            'evidence_summary': _evidence_summary(decisions, state['decision_evidence']),
                            'target_evidence': target_context.metadata if target_context else None,
                            'target_evidence_changed': state['target_evidence_changed'],
                            'recommendations': [item.to_dict() for item in state['recommendations']]})
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400
        except Exception as exc:
            return jsonify({'success': False, 'error': str(exc)}), 500

    def ai_runtime():
        try:
            settings = get_ai_settings()
        except ValueError:
            return None, None, False
        if not settings.enabled:
            return settings, None, False
        provider = app.config.get('AI_PROVIDER_INSTANCE')
        if provider is not None:
            return settings, provider, True
        if settings.provider == 'local':
            try:
                from fwmigrate.ai.llama_cpp import LlamaCppProvider
            except ImportError:
                return settings, None, False
            manager = local_ai_runtime_manager()
            return settings, LlamaCppProvider(settings, runtime_manager=manager), manager.is_available_or_installable()
        api_key = os.environ.get('GROQ_API_KEY', '').strip()
        if not api_key:
            return settings, None, False
        if provider is None:
            try:
                from fwmigrate.ai.groq import GroqProvider
            except ImportError:
                return settings, None, False
            provider = GroqProvider(settings, api_key=api_key)
        return settings, provider, True

    def local_ai_runtime_manager():
        from fwmigrate.ai.local_runtime import LocalAIRuntimeManager
        settings = get_ai_settings()
        manager = app.extensions.setdefault('local_ai_runtime_manager', LocalAIRuntimeManager(settings))
        if not app.extensions.get('local_ai_cleanup_registered'):
            atexit.register(manager.stop)
            app.extensions['local_ai_cleanup_registered'] = True
        return manager

    def ai_review_payload(payload):
        settings, provider, available = ai_runtime()
        if not settings or not settings.enabled or not available:
            return None, (jsonify({'success': False, 'error': 'AI assistance is not configured.'}), 503)
        try:
            state = _build_ai_review_state(payload)
            return (settings, provider, state), None
        except (ValueError, KeyError, TypeError) as exc:
            return None, (jsonify({'success': False, 'error': str(exc)}), 400)

    def ai_error_response(error):
        from fwmigrate.ai.errors import AIRateLimitError, AITimeoutError
        status = 429 if isinstance(error, AIRateLimitError) else 504 if isinstance(error, AITimeoutError) else 502
        return jsonify({'success': False, 'error': 'AI assistance is temporarily unavailable. Deterministic migration review is unchanged.'}), status

    @app.route('/api/migration/ai/status', methods=['GET'])
    def migration_ai_status():
        settings, _, available = ai_runtime()
        if not settings:
            return jsonify({'enabled': False, 'available': False})
        result = {'enabled': settings.enabled, 'available': bool(settings.enabled and available)}
        if settings.enabled:
            result.update(provider=settings.provider, model=settings.model)
            if settings.provider == 'local':
                result['local'] = local_ai_runtime_manager().status()
        return jsonify(result)

    @app.route('/api/ai/local/status', methods=['GET'])
    def local_ai_status():
        try:
            return jsonify(local_ai_runtime_manager().status())
        except ValueError:
            return jsonify({'state': 'FAILED', 'installed': False, 'runtime_available': False}), 503

    @app.route('/api/ai/local/install', methods=['POST'])
    def install_local_ai():
        try:
            return jsonify(local_ai_runtime_manager().start_install())
        except ValueError:
            return jsonify({'success': False, 'error': 'Local AI settings are invalid.'}), 503

    @app.route('/api/ai/local/remove', methods=['POST'])
    def remove_local_ai():
        try:
            manager = local_ai_runtime_manager()
            manager.remove_model()
            return jsonify(manager.status())
        except (ValueError, RuntimeError):
            return jsonify({'success': False, 'error': 'The local AI model could not be removed while it is in use.'}), 409

    @app.route('/api/migration/ai/questions', methods=['POST'])
    def migration_ai_questions():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({'success': False, 'error': 'A JSON request is required.'}), 400
        prepared, error = ai_review_payload(payload)
        if error:
            return error
        settings, provider, state = prepared
        try:
            built, proposals = generate_architecture_questions(ai_provider=provider, settings=settings,
                state=state, cache=proposal_cache)
            return jsonify({'success': True, 'proposals': [item.to_dict() for item in proposals],
                'analyzed_groups': built['analyzed_groups'], 'total_groups': built['total_groups']})
        except AIError as exc:
            _LOGGER.warning('AI architecture question generation failed provider=%s model=%s',
                            settings.provider, settings.model)
            return ai_error_response(exc)
        except Exception:
            _LOGGER.error('AI architecture question operation failed provider=%s model=%s',
                          settings.provider, settings.model)
            return jsonify({'success': False, 'error': 'AI assistance is temporarily unavailable. Deterministic migration review is unchanged.'}), 502

    @app.route('/api/migration/ai/explain', methods=['POST'])
    def migration_ai_explain():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({'success': False, 'error': 'A JSON request is required.'}), 400
        identity = tuple(payload.get(key) for key in ('source_vdom', 'source_kind', 'source_name'))
        if any(not isinstance(value, str) or not value for value in identity):
            return jsonify({'success': False, 'error': 'A review group identity is required.'}), 400
        prepared, error = ai_review_payload(payload)
        if error:
            return error
        settings, provider, state = prepared
        try:
            _, proposal = explain_review_group(ai_provider=provider, settings=settings, state=state,
                group_identity=identity, cache=proposal_cache)
            return jsonify({'success': True, 'proposal': proposal.to_dict()})
        except ValueError as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400
        except AIError as exc:
            _LOGGER.warning('AI candidate explanation failed provider=%s model=%s',
                            settings.provider, settings.model)
            return ai_error_response(exc)
        except Exception:
            _LOGGER.error('AI candidate explanation operation failed provider=%s model=%s',
                          settings.provider, settings.model)
            return jsonify({'success': False, 'error': 'AI assistance is temporarily unavailable. Deterministic migration review is unchanged.'}), 502

    @app.route('/api/migration/ai/confirm', methods=['POST'])
    def confirm_migration_ai_proposal():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({'success': False, 'error': 'A JSON request is required.'}), 400
        settings, _, available = ai_runtime()
        if not settings or not settings.enabled or not available:
            return jsonify({'success': False, 'error': 'AI assistance is not configured.'}), 503
        proposal = proposal_cache.get(payload.get('proposal_id'))
        if proposal is None or proposal.kind.value != 'ARCHITECTURE_QUESTION':
            return jsonify({'success': False, 'error': 'AI proposal is stale; regenerate AI review.'}), 409
        choice_index = payload.get('choice_index')
        if not isinstance(choice_index, int) or isinstance(choice_index, bool) or not 0 <= choice_index < len(proposal.choices):
            return jsonify({'success': False, 'error': 'A valid proposal choice is required.'}), 400
        try:
            state = _build_ai_review_state(payload)
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400
        from fwmigrate.conversion.fortigate_to_palo_alto.ai.context import build_ai_review_context
        from fwmigrate.conversion.fortigate_to_palo_alto.ai.prompts import FG_PAN_AI_PROMPT_VERSION
        try:
            current = build_ai_review_context(source_digest=state['source_digest'], target_digest=state['target_digest'],
                target_device=state['target_device'], decisions=state['decisions'],
                review_workflow=state['review_workflow'], review_context=state['review_context'],
                decision_candidates=state['decision_candidates'], auto_decisions=state['auto_decisions'],
                target_findings=state['target_findings'], operation='questions',
                prompt_version=FG_PAN_AI_PROMPT_VERSION, max_bytes=get_ai_settings().max_context_bytes,
                max_groups=get_ai_settings().max_review_groups)
        except AIError:
            return jsonify({'success': False, 'error': 'AI proposal is stale; regenerate AI review.'}), 409
        if current['context_digest'] != proposal.context_digest:
            return jsonify({'success': False, 'error': 'AI proposal is stale; regenerate AI review.'}), 409
        choice = proposal.choices[choice_index]
        by_key = {item.key: item for item in state['decisions'].decisions}
        assignments = choice.assignments
        if not assignments or len({item.decision_key for item in assignments}) != len(assignments):
            return jsonify({'success': False, 'error': 'AI proposal contains an invalid choice.'}), 409
        updated = []
        for assignment in assignments:
            decision = by_key.get(assignment.decision_key)
            candidates = state['decision_candidates'].get(assignment.decision_key, ())
            allowed = {candidate.get('value') for candidate in candidates if isinstance(candidate, dict)}
            if (assignment.decision_key not in proposal.decision_keys or decision is None
                    or decision.review_state != PANDecisionReviewState.PENDING
                    or decision.mode in {PANDecisionMode.AUTO, PANDecisionMode.UNSUPPORTED}
                    or assignment.value not in allowed):
                return jsonify({'success': False, 'error': 'AI proposal is stale; regenerate AI review.'}), 409
            updated.append(replace(decision, value=assignment.value,
                review_state=PANDecisionReviewState.CONFIRMED, evidence_source='ENGINEER',
                evidence_type='ENGINEER_ACCEPTED_AI_SUGGESTION', evidence_value={
                    'proposal_id': proposal.proposal_id, 'context_digest': proposal.context_digest,
                    'provider': proposal.provider, 'model': proposal.model,
                    'prompt_version': proposal.prompt_version,
                }, target_object=assignment.value))
        by_key.update((item.key, item) for item in updated)
        decisions = PANMigrationDecisionSet(tuple(sorted(by_key.values(), key=lambda item: item.key)))
        return jsonify({'success': True, 'confirmed_count': len(updated), 'decisions': decisions.to_dict(),
            'decision_document': _decision_document(state['source_digest'], decisions,
                _target_evidence(payload).metadata if payload.get('target_preview_id') else None)})

    @app.route('/api/migration/decisions/approve', methods=['POST'])
    def approve_migration_decisions():
        payload = request.get_json(silent=True)
        try:
            if not isinstance(payload, dict) or not isinstance(payload.get('decision_keys'), list) or not payload['decision_keys']:
                raise ValueError('decision_keys must be a non-empty array')
            if any(not isinstance(key, str) for key in payload['decision_keys']) or len(set(payload['decision_keys'])) != len(payload['decision_keys']):
                raise ValueError('decision_keys must contain unique strings')
            entry = _lookup_preview(payload.get('preview_id'), 'fortigate')
            if entry is None:
                raise ValueError('A valid FortiGate preview_id is required')
            previous = _load_decision_document(payload.get('decision_document'), entry.source_digest)
            analysis = _clone_preview(entry)
            target_context = _target_evidence(payload)
            target = target_context.analysis if target_context else None
            device = target_context.selected_device if target_context else None
            results = _auto_review_results(analysis.extracted.config, analysis.derived, previous, target, device)
            by_key = {item.key: item for item in previous.decisions}
            for key in payload['decision_keys']:
                result = results.get(key)
                if result is None or result.get('status') not in {'VERIFIED', 'DERIVED'} or not result.get('value'):
                    raise ValueError(f'Decision {key!r} is no longer VERIFIED or DERIVED')
            for key in payload['decision_keys']:
                by_key[key] = replace(by_key[key], value=results[key]['value'],
                    review_state=PANDecisionReviewState.CONFIRMED, evidence_source='ENGINEER',
                    evidence_type='APPROVED_AUTO_REVIEW', evidence_value=results[key]['status'],
                    target_object=results[key]['value'])
            decisions = PANMigrationDecisionSet(tuple(sorted(by_key.values(), key=lambda item: item.key)))
            return jsonify({'success': True, 'approved_count': len(payload['decision_keys']),
                'decisions': decisions.to_dict(), 'decision_document': _decision_document(entry.source_digest, decisions,
                    target_context.metadata if target_context else None)})
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

    @app.route('/api/migration/automation/run', methods=['POST'])
    def run_migration_automation():
        payload = request.get_json(silent=True)
        try:
            if not isinstance(payload, dict):
                raise ValueError('A JSON object is required')
            enabled = payload.get('enabled_policies', [])
            if not isinstance(enabled, list) or any(not isinstance(item, str) for item in enabled):
                raise ValueError('enabled_policies must be an array of policy names')
            enabled = tuple(AutomationPolicy(item) for item in enabled)
            if len(set(enabled)) != len(enabled):
                raise ValueError('enabled_policies must contain unique policy names')
            entry = _lookup_preview(payload.get('preview_id'), 'fortigate')
            if entry is None:
                raise ValueError('A valid FortiGate preview_id is required')
            document = payload.get('decision_document')
            decisions = _load_decision_document(document, entry.source_digest)
            analysis = _clone_preview(entry)
            target_context = _target_evidence(payload)
            result = run_automation_until_stable(
                analysis.extracted.config, analysis.derived, decisions,
                target_context.analysis if target_context else None,
                target_context.selected_device if target_context else None,
                enabled_policies=enabled,
            )
            return jsonify({'success': True, 'decisions': result.decisions.to_dict(),
                'decision_document': _decision_document(entry.source_digest, result.decisions,
                    target_context.metadata if target_context else None),
                'audit': list(result.audit), 'iterations': result.iterations, 'stable': result.stable})
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

    @app.route('/api/migration/target-intent/import', methods=['POST'])
    def import_target_intent():
        payload = request.get_json(silent=True)
        try:
            if not isinstance(payload, dict):
                raise ValueError('A JSON object is required')
            entry = _lookup_preview(payload.get('preview_id'), 'fortigate')
            if entry is None:
                raise ValueError('A valid FortiGate preview_id is required')
            document = payload.get('decision_document')
            previous = _load_decision_document(document, entry.source_digest) if document else None
            analysis = _clone_preview(entry)
            requirements = build_mapping_requirements(analysis.extracted.config, analysis.derived)
            decisions = build_decision_set(analysis.extracted.config, analysis.derived, requirements, previous)
            decisions = apply_target_intent(analysis.extracted.config, decisions, payload.get('intent', payload.get('yaml', {})))
            target_context = _target_evidence(payload)
            target = target_context.analysis if target_context else None
            device = target_context.selected_device if target_context else None
            automation = run_automation_until_stable(analysis.extracted.config, analysis.derived, decisions,
                target, device, enabled_policies=payload.get('enabled_policies', ()))
            decisions = automation.decisions
            auto = _auto_review_results(analysis.extracted.config, analysis.derived, decisions, target, device)
            return jsonify({'success': True, 'decisions': decisions.to_dict(),
                'decision_document': _decision_document(entry.source_digest, decisions,
                    target_context.metadata if target_context else None), 'auto_decisions': auto,
                'target_intent': export_target_intent(decisions), 'automation_audit': list(automation.audit),
                'automation_stable': automation.stable})
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

    @app.route('/api/migration/target-intent/export', methods=['POST'])
    def export_target_intent_document():
        payload = request.get_json(silent=True)
        try:
            if not isinstance(payload, dict):
                raise ValueError('A JSON object is required')
            entry = _lookup_preview(payload.get('preview_id'), 'fortigate')
            if entry is None:
                raise ValueError('A valid FortiGate preview_id is required')
            decisions = _load_decision_document(payload.get('decision_document'), entry.source_digest)
            return jsonify({'success': True, 'yaml': export_target_intent(decisions)})
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

    @app.route('/api/migration/rules/apply', methods=['POST'])
    def apply_migration_rule():
        payload = request.get_json(silent=True)
        try:
            if not isinstance(payload, dict):
                raise ValueError('A JSON object is required')
            if payload.get('rule_type') == 'REPEATED_ZONE_ACTION':
                entry = _lookup_preview(payload.get('preview_id'), 'fortigate')
                if entry is None:
                    raise ValueError('A valid FortiGate preview_id is required')
                document = payload.get('decision_document')
                previous = _load_decision_document(document, entry.source_digest)
                analysis = _clone_preview(entry)
                decisions = apply_repeated_zone_action(analysis.extracted.config, previous,
                    source_vdom=payload.get('source_vdom'), source_zone=payload.get('source_zone'),
                    value=payload.get('value'), apply_to=payload.get('apply_to'))
                return jsonify({'success': True, 'applied_count': len(payload['apply_to']),
                    'decision_document': _decision_document(entry.source_digest, decisions,
                        document.get('target_evidence'))})
            try:
                raw_rule_type = payload.get('rule_type')
                rule_type = MigrationRuleType.ZONE_TO_MEMBERS if raw_rule_type == 'APPLY_ZONE_TO_MEMBERS' else MigrationRuleType(raw_rule_type)
            except ValueError as exc:
                raise ValueError('Unsupported migration rule') from exc
            entry = _lookup_preview(payload.get('preview_id'), 'fortigate')
            if entry is None:
                raise ValueError('A valid FortiGate preview_id is required')
            document = payload.get('decision_document')
            previous = _load_decision_document(document, entry.source_digest)
            analysis = _clone_preview(entry)
            affected = rule_affected_decision_keys(analysis.extracted.config, previous, rule_type,
                                                   payload.get('source_key'))
            apply_to = payload.get('apply_to')
            if not isinstance(apply_to, list) or not apply_to or any(not isinstance(key, str) for key in apply_to):
                raise ValueError('apply_to must be a non-empty array of decision keys')
            if len(set(apply_to)) != len(apply_to) or not set(apply_to) <= set(affected):
                raise ValueError('apply_to contains a decision outside the current server-validated rule scope')
            if rule_type == MigrationRuleType.ZONE_TO_MEMBERS:
                decisions = apply_zone_to_members(analysis.extracted.config, previous,
                    source_key=payload.get('source_key'), value=payload.get('value'), apply_to=apply_to)
                return jsonify({'success': True, 'applied_count': len(apply_to),
                    'decision_document': _decision_document(entry.source_digest, decisions,
                        document.get('target_evidence'))})
            target_context = _target_evidence(payload)
            results = classify_auto_decisions(analysis.extracted.config, analysis.derived, previous,
                target_context.analysis if target_context else None,
                target_context.selected_device if target_context else None)
            return jsonify({'success': True, 're_evaluated_count': len(apply_to),
                'auto_decisions': {key: results.get(key, {'status': 'MANUAL'}) for key in apply_to},
                'decision_document': _decision_document(entry.source_digest, previous,
                    target_context.metadata if target_context else document.get('target_evidence'))})
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400
        except Exception as exc:
            return jsonify({'success': False, 'error': str(exc)}), 500

    @app.route('/api/migration/mapping/import', methods=['POST'])
    def import_migration_mapping():
        try:
            import yaml
            mapping = yaml.safe_load(request.get_json(force=True).get('yaml', '')) or {}
            if not isinstance(mapping, dict):
                raise ValueError('Mapping YAML must contain an object')
            PANMigrationOptions(**mapping)
            return jsonify({'success': True, 'mapping': mapping})
        except Exception as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

    @app.route('/api/migration/decisions/export', methods=['POST'])
    def export_migration_decisions():
        payload = request.get_json(silent=True) or {}
        entry = _lookup_preview(payload.get('preview_id'), 'fortigate')
        if entry is None:
            return jsonify({'success': False, 'error': 'A valid preview_id is required'}), 400
        try:
            serialized = payload.get('decision_document', payload.get('decisions'))
            if serialized is None:
                analysis = _clone_preview(entry)
                requirements = build_mapping_requirements(analysis.extracted.config, analysis.derived)
                decision_set = build_decision_set(analysis.extracted.config, analysis.derived, requirements)
            elif isinstance(serialized, dict) and 'format_version' in serialized:
                decision_set = _load_decision_document(serialized, entry.source_digest)
            else:
                decision_set = PANMigrationDecisionSet.from_dict(
                    serialized if isinstance(serialized, dict) else {'decisions': serialized}
                )
            target_evidence = serialized.get('target_evidence') if isinstance(serialized, dict) else None
            document = _decision_document(entry.source_digest, decision_set, target_evidence)
            return jsonify({'success': True, 'document': document})
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

    @app.route('/api/migration/decisions/import', methods=['POST'])
    def import_migration_decisions():
        payload = request.get_json(silent=True) or {}
        entry = _lookup_preview(payload.get('preview_id'), 'fortigate')
        if entry is None:
            return jsonify({'success': False, 'error': 'A valid preview_id is required'}), 400
        try:
            decision_set = _load_decision_document(payload.get('document'), entry.source_digest)
            target_evidence = (payload.get('document') or {}).get('target_evidence') if isinstance(payload.get('document'), dict) else None
            return jsonify({'success': True, 'decision_document': _decision_document(entry.source_digest, decision_set, target_evidence),
                            'decisions': decision_set.to_dict(), 'mapping': _options_mapping(decision_set.to_options())})
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

    @app.route('/api/migrate', methods=['POST'])
    def migrate():
        """Plan the supported FortiGate to Palo Alto configuration."""
        payload = request.get_json(silent=True) or request.form
        source_vendor = payload.get('source_vendor', 'fortigate')
        target_vendor = payload.get('target_vendor', 'palo_alto')
        if not isinstance(source_vendor, str) or not isinstance(target_vendor, str):
            return jsonify({'success': False, 'error': 'source_vendor and target_vendor must be strings'}), 400
        if (source_vendor.casefold(), target_vendor.casefold()) != ('fortigate', 'palo_alto'):
            return jsonify({'success': False, 'error': 'Only fortigate -> palo_alto is supported'}), 400
        uploaded = request.files.get('file')
        try:
            preview_id = payload.get('preview_id')
            entry = _lookup_preview(preview_id, 'fortigate') if preview_id else None
            if uploaded is not None and uploaded.filename:
                raw = uploaded.read()
                analysis = source_reporters.get('fortigate').analyze_source(_decode_configuration(raw))
                entry = _cache_preview('fortigate', raw, analysis, os.path.basename(uploaded.filename))
            elif entry is not None:
                analysis = _clone_preview(entry)
            else:
                return jsonify({'success': False, 'error': 'A valid preview_id or configuration file is required'}), 400
            serialized = payload.get('decision_document', payload.get('decisions', payload.get('decision_set')))
            if serialized is not None:
                if isinstance(serialized, dict) and 'format_version' in serialized:
                    decision_set = _load_decision_document(serialized, entry.source_digest)
                else:
                    decision_set = PANMigrationDecisionSet.from_dict(
                        serialized if isinstance(serialized, dict) else {'decisions': serialized}
                    )
                options = decision_set.to_options()
                mapping = _options_mapping(options)
                decision_document = _decision_document(entry.source_digest, decision_set)
            else:
                mapping_value = payload.get('mapping', '{}')
                mapping = json.loads(mapping_value) if isinstance(mapping_value, str) else mapping_value
                if not isinstance(mapping, dict):
                    raise ValueError('Mapping must contain an object')
                options = PANMigrationOptions(**mapping)
                requirements = build_mapping_requirements(analysis.extracted.config, analysis.derived)
                decision_set = build_decision_set(analysis.extracted.config, analysis.derived, requirements)
                decision_set = _confirm_mapping_decisions(decision_set, options, analysis.extracted.config)
                decision_document = _decision_document(entry.source_digest, decision_set)
                mapping = _options_mapping(options)
            target_context = _target_evidence(payload)
            target_evidence_changed = _target_evidence_changed(serialized, target_context)
            target = target_context.analysis if target_context else None
            target_device = target_context.selected_device if target_context else None
            target_warnings = {}
            if target and target_device:
                decision_set, target_warnings = suggest_from_target(analysis.extracted.config, decision_set, target, target_device)
            target_findings = validate_against_target(analysis.extracted.config, decision_set, target, target_device)
            decision_evidence = _decision_evidence(decision_set, target_findings)
            recommendations = build_recommendations(
                analysis.extracted.config, analysis.derived, decision_set, target, target_device
            )
            plan = migration_planners.get(source_vendor, target_vendor).plan(
                analysis.extracted.config, analysis.derived, options=options
            )
            target_object_reuse = classify_target_object_reuse(plan, target, target_device)
            dependencies = build_plan_dependency_index(plan, decision_set)
            target_plan_findings = validate_target_plan(plan, target_object_reuse, target_findings,
                                                        decision_set, dependencies)
            dispositions, render_blockers = assess_target_plan(plan, target_object_reuse, target_findings,
                                                                decision_set, dependencies)
            validation = validate_plan(plan)
            support_guidance = build_support_guidance(plan, validation, decision_set, target_findings)
            rendered = PANSetRenderer().render(plan, validation, dispositions=dispositions,
                                               render_blockers=render_blockers,
                                               decision_keys=dependencies.decision_keys_by_item)
            safe_target_evidence = target_context.metadata if target_context else None
            rendered = replace(rendered, report={**rendered.report,
                'source': {'vendor': 'fortigate', 'digest': entry.source_digest},
                'target_evidence': safe_target_evidence,
                'review': {
                    'target_evidence_changed': target_evidence_changed,
                    'target_findings': [item.to_dict() for item in target_findings],
                    'target_plan_findings': [item.to_dict() for item in target_plan_findings],
                    'target_object_reuse': list(target_object_reuse),
                    'decision_evidence': decision_evidence,
                    'evidence_summary': _evidence_summary(decision_set, decision_evidence),
                    'support_guidance': [item.to_dict() for item in support_guidance],
                    'recommendations': [item.to_dict() for item in recommendations],
                }})
            counts = rendered.report['counts']
            render_counts = rendered.report['render_dispositions']
            mapping_codes = {'missing_vsys_mapping', 'missing_target_vsys', 'missing_virtual_router', 'missing_route_interface'}
            missing = [issue for issue in rendered.report['issue_summary'] if issue['code'] in mapping_codes or 'missing target' in issue['message'].lower() or 'missing palo alto vsys mapping' in issue['message'].lower()]
            plan_status = classify_artifact_status(rendered, pending_mapping_issues=missing).value
            rendered = replace(rendered, report={**rendered.report, 'plan_status': plan_status})
            artifact_id = uuid.uuid4().hex
            rendered_artifacts[artifact_id] = rendered
            artifact_sources[artifact_id] = (analysis, mapping,
                                             _decision_document(entry.source_digest, decision_set, safe_target_evidence),
                                             entry.source_name)
            issue_messages = {item['code']: item['message'] for item in rendered.report['issue_summary']}
            reasons = []
            for item in rendered.report['items']:
                if item['render_disposition'] != 'BLOCK' and item['command_renderable']:
                    continue
                for code in item['render_blockers']:
                    reasons.append({'code': code, 'message': issue_messages.get(code, code.replace('_', ' ').capitalize()),
                                    'source_vdom': item['source_vdom'], 'source_kind': item['source_kind'],
                                    'source_name': item['source_name'], 'target_name': item['target_name']})
            reasons.extend({'code': finding.code, 'message': finding.message, 'source_vdom': finding.source_vdom,
                            'source_kind': finding.source_kind, 'source_name': finding.source_name,
                            'target_name': finding.target_name} for finding in target_plan_findings)
            blocking_reasons = list({(item['code'], item['source_vdom'], item['source_kind'], item['source_name'], item['target_name']): item
                                     for item in reasons}.values())
            render_summary = {'create': render_counts.get('CREATE', 0), 'reuse': render_counts.get('REUSE', 0),
                              'blocked': render_counts.get('BLOCK', 0), 'satisfied': rendered.report['satisfied'],
                              'command_renderable': rendered.report['command_renderable']}
            return jsonify({
                'success': True,
                'artifact_id': artifact_id,
                'plan_status': plan_status,
                'commands': len(rendered.commands),
                'counts': {**counts, 'renderable': rendered.report['command_renderable']},
                'render_dispositions': render_counts,
                'render_summary': render_summary,
                'missing_mappings': missing,
                'blocking_reasons': blocking_reasons,
                'target_warnings': target_warnings,
                'target_findings': [item.to_dict() for item in target_findings],
                'target_plan_findings': [item.to_dict() for item in target_plan_findings],
                'target_object_reuse': list(target_object_reuse),
                'decision_evidence': decision_evidence,
                'evidence_summary': _evidence_summary(decision_set, decision_evidence),
                'support_guidance': [item.to_dict() for item in support_guidance],
                'recommendations': [item.to_dict() for item in recommendations],
                'target_evidence': safe_target_evidence,
                'target_evidence_changed': target_evidence_changed,
                'report': rendered.report,
                'validation': {'issue_summary': rendered.report['issue_summary']},
            })
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

    @app.route('/api/migration/bundle', methods=['POST'])
    def migration_bundle():
        payload = request.get_json(silent=True) or {}
        artifact_id = payload.get('artifact_id')
        rendered = rendered_artifacts.get(artifact_id)
        if rendered is None:
            return jsonify({'success': False, 'error': 'A current migration plan is required'}), 400
        if not rendered.commands and rendered.report.get('plan_status') != 'READY_NO_CHANGES':
            return jsonify({'success': False, 'error': 'No PAN-OS commands are currently renderable. Complete the required target mappings first.'}), 422
        source = artifact_sources.get(artifact_id)
        if source is None:
            return jsonify({'success': False, 'error': 'The migration source has expired'}), 400
        analysis, mapping, decision_document, source_name = source
        bundle = io.BytesIO()
        workbook = io.BytesIO()
        try:
            source_reporters.get('fortigate').export_excel(analysis, workbook, source_name=source_name)
            with zipfile.ZipFile(bundle, 'w', zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('palo_alto_config.set', '\n'.join(rendered.commands))
                archive.writestr('migration_report.json', json.dumps(rendered.report, indent=2))
                archive.writestr('migration_decisions.json', json.dumps(decision_document, indent=2))
                archive.writestr('target_mapping.yaml', yaml.safe_dump(mapping, sort_keys=False))
                archive.writestr('source_inventory.xlsx', workbook.getvalue())
            bundle.seek(0)
            return send_file(bundle, mimetype='application/zip', as_attachment=True, download_name='migration_fortigate_to_palo_alto.zip')
        except Exception as exc:
            return jsonify({'success': False, 'error': str(exc)}), 500

    @app.route('/api/migration/command-preview', methods=['POST'])
    def migration_command_preview():
        payload = request.get_json(silent=True) or {}
        artifact_id = payload.get('artifact_id')
        rendered = rendered_artifacts.get(artifact_id)
        if rendered is None:
            return jsonify({'success': False, 'error': 'A current migration plan is required'}), 400
        if not rendered.commands and rendered.report.get('plan_status') != 'READY_NO_CHANGES':
            return jsonify({'success': False, 'error': 'No PAN-OS commands are currently renderable. Complete the required target mappings first.'}), 422
        source = artifact_sources.get(artifact_id)
        if source is None:
            return jsonify({'success': False, 'error': 'The migration source has expired'}), 400
        _, _, decision_document, _ = source
        decisions = decision_document['decisions']
        return jsonify({
            'success': True,
            'commands': list(rendered.commands),
            'command_text': '\n'.join(rendered.commands),
            'command_count': len(rendered.commands),
            'command_sha256': rendered.report['command_sha256'],
            'no_changes_required': not rendered.commands,
            'review_summary': {
                'pending': sum(item['review_state'] == 'PENDING' and item['mode'] not in {'AUTO', 'UNSUPPORTED'} for item in decisions),
                'manual': rendered.report['counts'].get('MANUAL_REVIEW', 0),
                'unsupported': rendered.report['counts'].get('UNSUPPORTED', 0),
            },
        })

    @app.route('/api/migration/download', methods=['POST'])
    def migration_download():
        payload = request.get_json(silent=True) or {}
        rendered = rendered_artifacts.get(payload.get('artifact_id'))
        if rendered is None:
            return jsonify({'success': False, 'error': 'A current migration plan is required'}), 400
        if not rendered.commands and rendered.report.get('plan_status') != 'READY_NO_CHANGES':
            return jsonify({'success': False, 'error': 'No PAN-OS commands are currently renderable. Complete the required target mappings first.'}), 422
        return send_file(
            io.BytesIO('\n'.join(rendered.commands).encode('utf-8')),
            mimetype='text/plain', as_attachment=True, download_name='palo_alto_config.set',
        )

    def _deployment_options(payload):
        try:
            host, username, password = payload['host'], payload['username'], payload['password']
            if not all(isinstance(value, str) for value in (host, username, password)):
                raise ValueError
            options = PANDeploymentOptions(
                host=host.strip(), username=username.strip(),
                password=password, port=int(payload.get('port', 22)),
                validate=_parse_bool(payload.get('validate'), default=True),
            )
        except (KeyError, TypeError, ValueError):
            raise ValueError('Host, SSH username, and password are required; port must be numeric')
        if not options.host or not options.username or not options.password or not 1 <= options.port <= 65535:
            raise ValueError('Host, SSH username, password, and a valid port are required')
        return options

    @app.route('/api/deploy', methods=['POST'])
    def deploy_candidate():
        try:
            payload = request.get_json(silent=True) or {}
            artifact_id = payload.get('artifact_id')
            rendered = rendered_artifacts.get(artifact_id)
            if rendered is None:
                raise ValueError('A current validated rendered migration is required')
            if not rendered.commands:
                raise ValueError('The migration artifact contains no renderable commands')
            options = _deployment_options(payload)
            result = PANSSHDeployer(options).deploy(rendered)
            source = artifact_sources.get(artifact_id)
            decision_document = source[2] if source else None
            validation_feedback = _deployment_validation_feedback(rendered, decision_document, result.validation)
            succeeded = (result.failure_message is None and result.failed_command_index is None
                         and result.validation.status != 'FAILED' and result.commit.status != 'FAILED')
            return jsonify({'success': succeeded, 'result': asdict(result),
                            'validation_feedback': validation_feedback}), (200 if succeeded else 502)
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

    @app.route('/api/validate-candidate', methods=['POST'])
    def validate_candidate():
        try:
            result = PANSSHDeployer(_deployment_options(request.get_json(silent=True) or {})).validate()
            return jsonify({'success': result.status == 'SUCCESS', 'result': asdict(result)}), (200 if result.status == 'SUCCESS' else 502)
        except ValueError as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

    @app.route('/api/commit', methods=['POST'])
    def commit_candidate():
        try:
            result = PANSSHDeployer(_deployment_options(request.get_json(silent=True) or {})).commit()
            return jsonify({'success': result.status == 'SUCCESS', 'result': asdict(result)}), (200 if result.status == 'SUCCESS' else 502)
        except ValueError as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

    @app.route('/api/extract/excel', methods=['POST'])
    def extract_excel():
        """Parse a source configuration and download its vendor-native report."""
        try:
            payload = request.get_json(silent=True) or {}
            source_vendor = request.form.get('source_vendor') or payload.get('source_vendor') or 'fortigate'
            preview_id = request.form.get('preview_id') or payload.get('preview_id') or ''
            metrics = (
                SourceReportMetrics()
                if _parse_bool(request.form.get('collect_metrics') or payload.get('collect_metrics'))
                or _LOGGER.isEnabledFor(logging.DEBUG)
                else None
            )
            total_started = perf_counter()
            profile_value = request.form.get('excel_profile') or payload.get('excel_profile') or ExcelExportProfile.FAST.value
            try:
                profile = ExcelExportProfile(profile_value)
            except (TypeError, ValueError):
                return jsonify({'error': 'excel_profile must be one of: fast, full'}), 400
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
                analysis = (
                    preview_entry.analysis
                    if profile is ExcelExportProfile.FAST
                    else _clone_preview(preview_entry)
                )
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
            source_name = os.path.basename(uploaded_file.filename) if uploaded_file is not None and uploaded_file.filename else (preview_entry.source_name if preview_entry else None)
            export_metrics = (
                ExcelExportMetrics()
                if metrics is not None and profile is ExcelExportProfile.FAST and source_vendor == 'fortigate'
                else None
            )
            export_options = {'profile': profile, 'source_name': source_name}
            if export_metrics is not None:
                export_options['metrics'] = export_metrics
            reporter.export_excel(analysis, workbook, **export_options)
            export_elapsed = perf_counter() - export_started
            if metrics is not None:
                metrics.add('excel export call', export_elapsed * 1000)
                if export_metrics is not None:
                    metrics.details['excel_export'] = export_metrics.as_dict()
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
        """Plan diagnostics are unavailable without a migration planner."""
        return _conversion_unavailable()

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
            elif ext == '.json':
                file_types = ('JSON (*.json)', 'All files (*.*)')
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
    finally:
        manager = app.extensions.get('local_ai_runtime_manager')
        if manager is not None:
            manager.stop()
