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
from pathlib import Path
from dataclasses import asdict, replace
from copy import deepcopy
from dataclasses import dataclass
from time import perf_counter
from flask import Flask, render_template, request, send_file, jsonify

from fwmigrate.source_reporting.builtin import register_builtin_source_reporters
from fwmigrate.conversion.builtin import register_builtin_migration_planners
from fwmigrate.conversion import migration_planners
from fwmigrate.conversion.fortigate_to_palo_alto.design.graph import build_decision_graph
from fwmigrate.conversion.fortigate_to_palo_alto.design.session import create_design_session
from fwmigrate.conversion.fortigate_to_palo_alto.design.resolver import resolve_design_session_until_stable
from fwmigrate.conversion.fortigate_to_palo_alto.design.proposed import PANProposedDesignSession
from fwmigrate.conversion.fortigate_to_palo_alto.ai.orchestrator import (
    build_ai_proposed_design, state_with_proposed_design,
)
from fwmigrate.conversion.fortigate_to_palo_alto import (
    PANDecisionMode,
    PANDecisionReviewState,
    PANMigrationDecision,
    PANMigrationDecisionSet,
    PANMigrationOptions,
    build_decision_set,
    make_decision_key,
    build_recommendations,
    PANAutomationMode,
    apply_explicit_options,
    run_migration_pipeline,
)
from fwmigrate.conversion.fortigate_to_palo_alto import ai_advisor
from fwmigrate.conversion.fortigate_to_palo_alto.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.requirements import build_mapping_requirements
from fwmigrate.conversion.fortigate_to_palo_alto.target_suggestions import (
    discover_target_candidates, suggest_from_target, target_devices, target_device_metadata,
)
from fwmigrate.conversion.fortigate_to_palo_alto.target_validation import validate_against_target
from fwmigrate.conversion.fortigate_to_palo_alto.review_context import build_review_context
from fwmigrate.conversion.fortigate_to_palo_alto.review_evidence import build_review_evidence
from fwmigrate.conversion.fortigate_to_palo_alto.review_workflow import build_review_workflow
from fwmigrate.conversion.fortigate_to_palo_alto.decision_propagation import (
    MigrationRuleType, apply_repeated_zone_action, apply_zone_to_members,
    rule_affected_decision_keys,
)
from fwmigrate.conversion.fortigate_to_palo_alto.auto_decisions import classify_auto_decisions
from fwmigrate.conversion.fortigate_to_palo_alto.automation import AutomationPolicy, run_automation_until_stable
from fwmigrate.conversion.fortigate_to_palo_alto.target_evidence import (
    bind_legacy_target_evidence,
    reconcile_target_evidence,
    target_evidence_changed,
    target_evidence_identity,
)
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
from fwmigrate.deployment import PANDeploymentOptions, PANDeploymentSession, PANSSHDeployer
from fwmigrate.collection import CollectionStatus, source_collectors
from fwmigrate.collection.builtin import register_builtin_collectors
from fwmigrate.collection.snapshot import make_snapshot, parse_snapshot, MAX_BYTES

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None
if load_dotenv is not None:
    load_dotenv(Path(__file__).resolve().parents[2] / ".env.local", override=False)

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
_DECISION_FORMAT_VERSION = 3
_DEPLOYMENT_SESSION_TTL_SECONDS = 30 * 60


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
            item.evidence_source or (
                "ENGINEER" if item.review_state is PANDecisionReviewState.CONFIRMED else "SOURCE"
            )
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
    if not isinstance(document, dict) or document.get("format_version") not in {1, 2, _DECISION_FORMAT_VERSION}:
        raise ValueError("Unsupported migration decision document")
    if document.get("source_vendor") != "fortigate" or document.get("target_vendor") != "palo_alto":
        raise ValueError("Migration decision document must be fortigate -> palo_alto")
    if document.get("source_digest") != source_digest:
        raise ValueError("Migration decisions belong to a different source configuration")
    decisions = PANMigrationDecisionSet.from_dict({"decisions": document.get("decisions")})
    if document.get("format_version") in {1, 2}:
        decisions = bind_legacy_target_evidence(decisions, document.get("target_evidence"))
    return decisions


def _target_evidence_changed(document, target_context):
    previous = document.get("target_evidence") if isinstance(document, dict) else None
    current = target_context.metadata if target_context else None
    return target_evidence_changed(previous, current)


def _options_mapping(options):
    mapping = {
        "vdoms": {name: {key: value for key, value in asdict(item).items() if value is not None}
                   for name, item in options.vdoms.items()},
        "interfaces": {vdom: {name: {key: value for key, value in asdict(item).items() if value is not None}
                              for name, item in mappings.items()}
                       for vdom, mappings in options.interfaces.items()},
    }
    if options.zones is not None:
        mapping["zones"] = {vdom: {name: {"target_zone": item.target_zone} for name, item in mappings.items()
                                    if item.target_zone is not None}
                            for vdom, mappings in options.zones.items()}
    return mapping


def _confirm_mapping_decisions(decision_set, options, config):
    """Compatibility wrapper around the pair-specific pipeline mapping logic."""
    return apply_explicit_options(config, decision_set, options)

@dataclass(frozen=True)
class _PreviewCacheEntry:
    preview_id: str
    source_vendor: str
    source_digest: str
    created_at: float
    analysis: object
    source_name: str | None = None
    collection_status: CollectionStatus | None = None
    collection_warnings: tuple[str, ...] = ()
    collection_method: str | None = None


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


def _find_source_preview(source_vendor: str, source_digest: str, *,
                         collection_status: CollectionStatus | None = None,
                         collection_warnings: tuple[str, ...] = (),
                         collection_method: str | None = None) -> _PreviewCacheEntry | None:
    return next((entry for entry in _PREVIEW_CACHE.values()
                 if entry.source_vendor == source_vendor
                 and entry.source_digest == source_digest
                 and entry.collection_status == collection_status
                 and entry.collection_warnings == collection_warnings
                 and entry.collection_method == collection_method), None)


def _lookup_source_preview(source_vendor: str, raw: bytes, *,
                           collection_status: CollectionStatus | None = None,
                           collection_warnings: tuple[str, ...] = (),
                           collection_method: str | None = None) -> _PreviewCacheEntry | None:
    source_digest = _source_digest(source_vendor, raw)
    with _PREVIEW_CACHE_LOCK:
        _cleanup_preview_cache()
        return _find_source_preview(source_vendor, source_digest,
                                    collection_status=collection_status,
                                    collection_warnings=collection_warnings,
                                    collection_method=collection_method)


def _cache_preview(source_vendor: str, raw: bytes, analysis, source_name: str | None = None,
                   *, collection_status: CollectionStatus | None = None,
                   collection_warnings: tuple[str, ...] = (), collection_method: str | None = None) -> _PreviewCacheEntry:
    now = time.monotonic()
    source_digest = _source_digest(source_vendor, raw)
    with _PREVIEW_CACHE_LOCK:
        _cleanup_preview_cache(now)
        entry = _find_source_preview(source_vendor, source_digest,
                                     collection_status=collection_status,
                                     collection_warnings=collection_warnings,
                                     collection_method=collection_method)
        if entry is not None:
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
            collection_status=collection_status,
            collection_warnings=collection_warnings,
            collection_method=collection_method,
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


def _require_complete_collection(entry: _PreviewCacheEntry) -> None:
    if entry.collection_status is not None and entry.collection_status != CollectionStatus.SUCCESS:
        raise ValueError("Migration requires a complete live collection; this source is PARTIAL or FAILED.")


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


def _build_migration_review_state(entry, payload, apply_deterministic=False):
    """Build the deterministic migration review from a cached source preview."""
    _require_complete_collection(entry)
    analysis = _clone_preview(entry)
    requirements = build_mapping_requirements(analysis.extracted.config, analysis.derived)
    prior = payload.get('decision_document')
    previous = _load_decision_document(prior, entry.source_digest) if prior is not None else None
    target_context = _target_evidence(payload)
    target_metadata = target_context.metadata if target_context else None
    decisions = build_decision_set(analysis.extracted.config, analysis.derived, requirements, previous)
    decisions, invalidated_target_decisions = reconcile_target_evidence(decisions, target_metadata)
    review_evidence = build_review_evidence(analysis.extracted.config, analysis.derived)
    target = target_context.analysis if target_context else None
    device = target_context.selected_device if target_context else None
    target_warnings = {}
    if target and device:
        decisions, target_warnings = suggest_from_target(analysis.extracted.config, decisions, target, device)
    auto = _auto_review_results(analysis.extracted.config, analysis.derived, decisions, target, device)
    design_session = resolve_design_session_until_stable(
        analysis.extracted.config,
        analysis.derived,
        decisions,
        target,
        device,
        source_digest=entry.source_digest,
        target_evidence=target_metadata,
        requirements=requirements,
        enabled_policies=(
            AutomationPolicy.AUTO_APPLY_VERIFIED,
            AutomationPolicy.AUTO_APPLY_DERIVED,
        ) if apply_deterministic else (),
    )
    decisions = design_session.decisions
    findings = validate_against_target(analysis.extracted.config, decisions, target, device)
    candidates = discover_target_candidates(analysis.extracted.config, decisions, target, device,
                                            evidence=review_evidence) if target and device else {}
    evidence = _decision_evidence(decisions, findings)
    context = build_review_context(analysis.extracted.config, decisions, candidates=candidates,
        target_available=target is not None, target_selected=bool(device),
        target_device_count=len(target_context.devices) if target_context else 0,
        evidence=review_evidence)
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
        'design_session': design_session,
        'decision_candidates': candidates,
        'review_workflow': workflow,
        'review_context': context,
        'auto_decisions': auto,
        'target_findings': findings,
        'decision_evidence': evidence,
        'target_warnings': target_warnings,
        'recommendations': recommendations,
        'target_evidence_changed': _target_evidence_changed(prior, target_context) or bool(invalidated_target_decisions),
        'invalidated_target_decisions': invalidated_target_decisions,
    }


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
    app.config.setdefault('AI_DESIGN_SESSION_TTL_SECONDS', 30 * 60)
    app.config.setdefault('AI_DESIGN_SESSION_MAX', 32)

    if test_config:
        app.config.update(test_config)

    try:
        ai_config = ai_advisor.validate_static_configuration()
        _LOGGER.info('AI advisor %s provider=%s model=%s',
                     'configured' if ai_config['enabled'] else 'disabled',
                     ai_config['provider'], ai_config['model'])
    except ai_advisor.AdvisorError as exc:
        _LOGGER.warning('AI advisor configuration error category=%s', exc.code)

    rendered_artifacts = {}
    ai_proposals = {}
    ai_design_sessions = {}
    ai_proposal_lock = threading.Lock()
    ai_audit = []
    ai_audit_by_id = {}
    artifact_sources = {}
    deployment_sessions: dict[str, PANDeploymentSession] = {}

    def _sync_ai_design_audit(rows):
        by_id = {row.get('audit_id'): row for row in ai_audit if row.get('audit_id')}
        for row in rows:
            stored = by_id.get(row.get('audit_id'))
            if stored:
                for field in ('engineer_action', 'final_value', 'failure_category'):
                    if field in row:
                        stored[field] = row[field]

    def _design_audit_actions(session, actions):
        return tuple(
            {**row, 'engineer_action': actions[row['decision_key']][0],
             'final_value': actions[row['decision_key']][1]}
            if row.get('decision_key') in actions and row.get('engineer_action') is None else row
            for row in session.audit
        )

    def _expire_ai_design_sessions(now=None):
        now = time.time() if now is None else now
        ttl = max(1, int(app.config['AI_DESIGN_SESSION_TTL_SECONDS']))
        limit = max(1, int(app.config['AI_DESIGN_SESSION_MAX']))
        with ai_proposal_lock:
            expired = [key for key, value in ai_design_sessions.items() if now - value.created_at > ttl]
            for key in expired:
                session = ai_design_sessions.pop(key)
                for row in session.audit:
                    if row.get('engineer_action') is None:
                        row['engineer_action'] = 'UNRESOLVED'
                _sync_ai_design_audit(session.audit)
            while len(ai_design_sessions) > limit:
                oldest = min(ai_design_sessions, key=lambda key: ai_design_sessions[key].created_at)
                session = ai_design_sessions.pop(oldest)
                for row in session.audit:
                    if row.get('engineer_action') is None:
                        row['engineer_action'] = 'UNRESOLVED'
                _sync_ai_design_audit(session.audit)

    def _store_ai_design_session(session, previous=None):
        _expire_ai_design_sessions()
        for failure in session.failures:
            _LOGGER.warning(
                'AI design failed provider=%s model=%s category=%s reason=%s status=%s request_id=%s batch_size=%s candidate_count=%s request_bytes=%s',
                failure.get('provider'), failure.get('model'), failure.get('failure_category'),
                failure.get('safe_reason'), failure.get('status'), failure.get('request_id'),
                failure.get('batch_size'), failure.get('candidate_count'), failure.get('request_bytes'),
            )
        with ai_proposal_lock:
            if previous and ai_design_sessions.get(previous.session_id) is not previous:
                raise ValueError('This AI design session changed; reload and retry')
            old_rows = previous.audit if previous and previous.session_id == session.session_id else ()
            _sync_ai_design_audit(session.audit[:len(old_rows)])
            for row in session.audit[len(old_rows):]:
                ai_audit.append(row)
            ai_design_sessions[session.session_id] = session
            while len(ai_audit) > 5000:
                removed = ai_audit.pop(0)
                ai_audit_by_id.pop(removed.get('proposal_id'), None)

    def _lookup_ai_design_session(session_id):
        _expire_ai_design_sessions()
        with ai_proposal_lock:
            return ai_design_sessions.get(session_id)

    def _ai_design_state(payload):
        entry = _lookup_preview(payload.get('preview_id'), 'fortigate')
        if entry is None:
            raise ValueError('A valid FortiGate preview_id is required')
        state = _build_migration_review_state(entry, payload, True)
        if not state.get('target_digest') or not state.get('target_device'):
            raise ValueError('Upload PAN-OS target XML and select a target device before AI design review')
        return entry, state

    def _check_ai_design_identity(session, state):
        if (session.design.source_digest, session.design.target_digest, session.design.target_device) != (
            state['source_digest'], state['target_digest'], state['target_device']
        ):
            raise ValueError('This design session is stale; refresh the source and target evidence')

    def _ai_design_response(session, state, **extra):
        result = {
            'success': True,
            'design_session': session.to_dict(state['design_session'].dependency_graph),
            'decisions': state['decisions'].to_dict(),
            'decision_document': _decision_document(
                state['source_digest'], state['decisions'],
                state['target_context'].metadata if state['target_context'] else None,
            ),
        }
        result.update(extra)
        return result

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
            reporter = source_reporters.get(source_vendor)
            source_vendor = reporter.vendor_id
            preview_entry = _timed(
                metrics, 'analysis cache lookup',
                lambda: _lookup_source_preview(source_vendor, raw_content),
            )
            analysis_cache_hit = preview_entry is not None
            if preview_entry is None:
                file_content = _timed(metrics, 'decode', lambda: _decode_configuration(raw_content))
                analysis = _timed(
                    metrics,
                    'extraction',
                    lambda: reporter.analyze_source(file_content, metrics=metrics),
                )
                preview_entry = _cache_preview(source_vendor, raw_content, analysis, os.path.basename(file.filename))
            else:
                analysis = preview_entry.analysis
            if metrics is not None:
                metrics.set_metadata('analysis_cache_hit', analysis_cache_hit)
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
            collection_warnings = tuple(snapshot['warnings'])
            entry = _lookup_source_preview(source.vendor_id, raw, collection_status=source.status,
                                           collection_warnings=collection_warnings,
                                           collection_method=source.method)
            if entry is None:
                analysis = reporter.analyze_source(snapshot['source_text'])
                entry = _cache_preview(source.vendor_id, raw, analysis, source.source_name,
                                       collection_status=source.status,
                                       collection_warnings=collection_warnings, collection_method=source.method)
            else:
                analysis = entry.analysis
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
            source_bytes = source.source_text.encode('utf-8')
            collection_warnings = tuple(source.warnings)
            entry = _lookup_source_preview(source.vendor_id, source_bytes, collection_status=source.status,
                                           collection_warnings=collection_warnings,
                                           collection_method=source.method)
            if entry is None:
                analysis = reporter.analyze_source(source.source_text)
                entry = _cache_preview(source.vendor_id, source_bytes, analysis, source.source_name,
                                       collection_status=source.status, collection_warnings=collection_warnings,
                                       collection_method=source.method)
            else:
                analysis = entry.analysis
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
                entry = _lookup_source_preview('fortigate', raw)
                if entry is None:
                    analysis = source_reporters.get('fortigate').analyze_source(_decode_configuration(raw))
                    entry = _cache_preview('fortigate', raw, analysis, os.path.basename(uploaded.filename))
            state = _build_migration_review_state(entry, payload)
            target_context = state['target_context']
            target = target_context.analysis if target_context else None
            decisions = state['decisions']
            return jsonify({'success': True, 'preview_id': entry.preview_id, 'requirements': state['requirements'],
                            'decisions': decisions.to_dict(),
                            'design_session': state['design_session'].to_dict(),
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
                            'invalidated_target_decisions': list(state['invalidated_target_decisions']),
                            'recommendations': [item.to_dict() for item in state['recommendations']]})
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400
        except Exception as exc:
            return jsonify({'success': False, 'error': str(exc)}), 500

    def _ai_failure(exc, *, provider, model, batch_size, duration_ms, batch_id=None):
        error = exc if isinstance(exc, ai_advisor.AdvisorError) else ai_advisor.AdvisorError()
        cause = exc.__cause__ if isinstance(exc, ai_advisor.AdvisorError) and exc.__cause__ else exc
        diagnostic = ai_advisor.failure_record(error, provider=provider, model=model)
        if not isinstance(exc, ai_advisor.AdvisorError):
            _LOGGER.exception('Unexpected AI advisor failure provider=%s model=%s', provider, model)
        _LOGGER.warning(
            'AI request failed provider=%s model=%s category=%s reason=%s status=%s request_id=%s provider_code=%s provider_type=%s batch_size=%s candidate_count=%s request_bytes=%s duration_ms=%s exception=%s',
            provider, model, error.code, diagnostic.get('safe_reason'), error.status, error.request_id,
            diagnostic.get('provider_code'), diagnostic.get('provider_type'),
            diagnostic.get('batch_size', batch_size), diagnostic.get('candidate_count'),
            diagnostic.get('request_bytes'), duration_ms, cause.__class__.__name__,
        )
        if batch_id:
            with ai_proposal_lock:
                ai_audit.append({
                    'event': 'AI_REQUEST_FAILED', 'batch_id': batch_id,
                    'created_at': time.time(), 'request_duration_ms': duration_ms, **diagnostic,
                })
                if len(ai_audit) > 5000:
                    ai_audit_by_id.pop(ai_audit.pop(0).get('proposal_id'), None)
        status = 503 if error.code in {'AI_DISABLED', 'AI_UNAVAILABLE', 'AI_AUTH_FAILED', 'AI_RATE_LIMITED'} else 502
        return jsonify({'success': False, 'code': error.code, 'error': error.message,
                        'failure': diagnostic}), status

    def _record_repair_failures(result, batch_id):
        records = [dict(item) for item in result.failures]
        if result.exhausted:
            conflicts = [item["decision_key"] for item in result.proposals
                         if item.get("validation_status") == "CONFLICT"]
            if conflicts:
                proposal = result.proposals[0]
                records.append({
                    "failure_category": "AI_REPAIR_EXHAUSTED",
                    "provider": proposal.get("provider", "groq"),
                    "model": ai_advisor.groq_model("repair"),
                    "safe_reason": "Conflicts remained after the configured repair passes.",
                    "decision_keys": conflicts,
                    "batch_size": len(conflicts),
                    "candidate_count": 0,
                    "request_bytes": 0,
                })
        if records:
            now = time.time()
            with ai_proposal_lock:
                ai_audit.extend({"event": "AI_REPAIR_FAILED", "batch_id": batch_id,
                                 "created_at": now, **item} for item in records)
                while len(ai_audit) > 5000:
                    removed = ai_audit.pop(0)
                    ai_audit_by_id.pop(removed.get('proposal_id'), None)
            for failure in records:
                _LOGGER.warning(
                    'AI repair failed provider=%s model=%s category=%s reason=%s status=%s request_id=%s batch_size=%s candidate_count=%s request_bytes=%s',
                    failure.get('provider'), failure.get('model'), failure.get('failure_category'),
                    failure.get('safe_reason'), failure.get('status'), failure.get('request_id'),
                    failure.get('batch_size'), failure.get('candidate_count'), failure.get('request_bytes'),
                )
        return records

    @app.route('/api/migration/ai/status', methods=['GET'])
    def migration_ai_status():
        try:
            return jsonify(ai_advisor.advisor_status())
        except ai_advisor.AdvisorError as exc:
            return _ai_failure(exc, provider='configuration', model='', batch_size=0, duration_ms=0)

    @app.route('/api/migration/ai/test', methods=['POST'])
    def migration_ai_test():
        if not ai_advisor.advisor_enabled():
            return jsonify({'success': False, 'code': 'AI_DISABLED', 'error': 'AI advisor is disabled.'}), 503
        started = perf_counter()
        provider, model = ai_advisor.advisor_provider(), ai_advisor.advisor_model()
        try:
            return jsonify(ai_advisor.test_advisor())
        except Exception as exc:
            return _ai_failure(exc, provider=provider, model=model, batch_size=1,
                               duration_ms=round((perf_counter() - started) * 1000))

    @app.route('/api/migration/ai/design', methods=['POST'])
    def build_migration_ai_design():
        payload = request.get_json(silent=True)
        if not ai_advisor.advisor_enabled():
            return jsonify({'success': False, 'code': 'AI_DISABLED', 'error': 'AI advisor is disabled.'}), 503
        try:
            if not isinstance(payload, dict):
                raise ValueError('A JSON object is required')
            entry, state = _ai_design_state(payload)
            session_id = payload.get('design_session_id')
            stored_previous = _lookup_ai_design_session(session_id) if session_id else None
            if session_id and stored_previous is None:
                return jsonify({'success': False, 'error': 'This AI design session expired; start a new review.'}), 409
            previous = stored_previous
            if stored_previous:
                _check_ai_design_identity(stored_previous, state)
                if payload.get('retry_exceptions'):
                    retained = tuple(item for item in stored_previous.design.proposals
                                     if item.validation_status == 'VALID'
                                     and item.action.value == 'USE_EXISTING')
                    previous = replace(stored_previous, design=stored_previous.design.with_state(proposals=retained))
            session = build_ai_proposed_design(state, previous)
            _store_ai_design_session(session, stored_previous)
            return jsonify(_ai_design_response(session, state))
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400
        except Exception as exc:
            return _ai_failure(exc, provider=ai_advisor.advisor_provider(), model=ai_advisor.advisor_model(),
                               batch_size=0, duration_ms=0)

    @app.route('/api/migration/ai/design/<session_id>', methods=['GET'])
    def get_migration_ai_design(session_id):
        session = _lookup_ai_design_session(session_id)
        if session is None:
            return jsonify({'success': False, 'error': 'This AI design session expired; start a new review.'}), 404
        return jsonify({'success': True, 'design_session': session.to_dict(None)})

    @app.route('/api/migration/ai/design/<session_id>/approve', methods=['POST'])
    def approve_migration_ai_design(session_id):
        payload = request.get_json(silent=True)
        try:
            if not isinstance(payload, dict):
                raise ValueError('A JSON object is required')
            session = _lookup_ai_design_session(session_id)
            if session is None:
                raise ValueError('This AI design session expired; start a new review.')
            entry, state = _ai_design_state(payload)
            _check_ai_design_identity(session, state)
            design = session.design.with_state(decisions=state['decisions'])
            proposals = design.proposals
            if payload.get('approve_all') is True:
                selected = [item for item in proposals if item.action.value == 'USE_EXISTING'
                            and item.validation_status == 'VALID']
            elif payload.get('family'):
                family = str(payload['family']).strip().casefold()
                fields = {
                    'interfaces': {'target_interface'}, 'zones': {'target_zone'},
                    'ownership': {'vsys'}, 'virtual routers': {'virtual_router'},
                }
                selected_fields = fields.get(family, {family})
                source_vdom = payload.get('source_vdom')
                decisions_by_key = {item.key: item for item in state['decisions'].decisions}
                selected = [item for item in proposals
                            if item.action.value == 'USE_EXISTING' and item.validation_status == 'VALID'
                            and decisions_by_key[item.decision_key].target_field in selected_fields
                            and (source_vdom is None
                                 or decisions_by_key[item.decision_key].source_vdom == source_vdom)]
            else:
                keys = payload.get('decision_keys')
                if (not isinstance(keys, list) or not keys
                        or any(not isinstance(key, str) or not key for key in keys)
                        or len(set(keys)) != len(keys)):
                    raise ValueError('decision_keys, family, or approve_all is required')
                requested = set(keys)
                selected = [item for item in proposals if item.decision_key in requested]
                if len(selected) != len(requested):
                    raise ValueError('One or more selected proposals are no longer in this design')
            if not selected:
                raise ValueError('No valid AI proposals were selected')
            state = state_with_proposed_design(state, design)
            whole = ai_advisor.validate_proposal_set(state, [item.to_dict() for item in proposals])
            whole_by_key = {item['decision_key']: item for item in whole}
            if any(whole_by_key[item.decision_key]['validation_status'] != 'VALID' for item in selected):
                raise ValueError('One or more selected proposals are stale or conflict with the current design')
            confirmed, validated = ai_advisor.approve_proposals_as_engineer(
                state, [item.to_dict() for item in selected], proposed_design=design
            )
            selected_keys = {item['decision_key'] for item in validated}
            remaining = tuple(item for item in design.proposals if item.decision_key not in selected_keys)
            audit_actions = {key: ('APPROVED', whole_by_key[key]['proposed_value']) for key in selected_keys}
            updated = replace(
                session, design=design.with_state(decisions=confirmed, proposals=remaining),
                audit=_design_audit_actions(session, audit_actions),
            )
            _store_ai_design_session(updated, session)
            state = dict(state, decisions=confirmed)
            return jsonify(_ai_design_response(updated, state, approved_count=len(validated)))
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 409

    @app.route('/api/migration/ai/design/<session_id>/modify', methods=['POST'])
    def modify_migration_ai_design(session_id):
        payload = request.get_json(silent=True)
        try:
            if not isinstance(payload, dict) or not isinstance(payload.get('changes'), list) or not payload['changes']:
                raise ValueError('changes must be a non-empty array')
            session = _lookup_ai_design_session(session_id)
            if session is None:
                raise ValueError('This AI design session expired; start a new review.')
            entry, state = _ai_design_state(payload)
            _check_ai_design_identity(session, state)
            identity = target_evidence_identity(state['target_context'].metadata)
            if identity is None or identity[1] is None:
                raise ValueError('Target evidence and a selected PAN-OS device are required')
            by_key = {item.key: item for item in state['decisions'].decisions}
            ai_decision_keys = {item.decision_key for item in session.design.proposals}
            changes = {}
            for item in payload['changes']:
                if not isinstance(item, dict) or not isinstance(item.get('decision_key'), str):
                    raise ValueError('Each change requires a decision_key and value')
                key, value = item['decision_key'], item.get('value')
                if key not in by_key or 'value' not in item or (value is not None and (not isinstance(value, str) or not value.strip())):
                    raise ValueError('Each change must select a current decision and a value or null')
                if key in changes:
                    raise ValueError('changes cannot repeat a decision_key')
                changes[key] = value.strip() if isinstance(value, str) else None
            for key, value in changes.items():
                decision = by_key[key]
                if value is None:
                    by_key[key] = replace(
                        decision, value=None,
                        mode=PANDecisionMode.REQUIRED if decision.mode is PANDecisionMode.AUTO else decision.mode,
                        review_state=PANDecisionReviewState.PENDING,
                        evidence_source=None, evidence_type=None, evidence_value=None, target_object=None,
                        evidence_target_digest=None, evidence_target_device=None,
                    )
                else:
                    by_key[key] = replace(
                        decision, value=value, review_state=PANDecisionReviewState.CONFIRMED,
                        evidence_source='ENGINEER',
                        evidence_type=('ENGINEER_MODIFIED_AI_PROPOSAL' if key in ai_decision_keys else 'MANUAL'),
                        evidence_value=value, target_object=value,
                        evidence_target_digest=identity[0], evidence_target_device=identity[1],
                    )
            decisions = PANMigrationDecisionSet(tuple(sorted(by_key.values(), key=lambda item: item.key)))
            document = _decision_document(entry.source_digest, decisions, state['target_context'].metadata)
            updated_payload = dict(payload, decision_document=document)
            state = _build_migration_review_state(entry, updated_payload)
            audit_actions = {
                key: ('MODIFIED' if value is not None else 'UNRESOLVED', value)
                for key, value in changes.items()
            }
            build_session = replace(session, audit=_design_audit_actions(session, audit_actions))
            rebuilt = build_ai_proposed_design(state, build_session)
            _store_ai_design_session(rebuilt, session)
            return jsonify(_ai_design_response(rebuilt, state, decisions=state['decisions'].to_dict(),
                                              decision_document=document))
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 409

    @app.route('/api/migration/ai/design/<session_id>/reject', methods=['POST'])
    def reject_migration_ai_design_proposals(session_id):
        payload = request.get_json(silent=True)
        try:
            if not isinstance(payload, dict):
                raise ValueError('A JSON object is required')
            keys = payload.get('decision_keys')
            if (not isinstance(keys, list) or not keys
                    or any(not isinstance(key, str) or not key for key in keys)
                    or len(set(keys)) != len(keys)):
                raise ValueError('decision_keys must contain unique proposal keys')
            session = _lookup_ai_design_session(session_id)
            if session is None:
                raise ValueError('This AI design session expired; start a new review.')
            entry, state = _ai_design_state(payload)
            _check_ai_design_identity(session, state)
            by_key = {item.decision_key: item for item in session.design.proposals}
            if any(key not in by_key for key in keys):
                raise ValueError('One or more selected proposals are no longer in this design')
            proposals = tuple(
                replace(item, validation_status='REJECTED',
                        validation_findings=('Rejected by engineer',)) if item.decision_key in keys else item
                for item in session.design.proposals
            )
            updated = replace(
                session, design=session.design.with_state(proposals=proposals),
                audit=_design_audit_actions(session, {key: ('REJECTED', None) for key in keys}),
            )
            _store_ai_design_session(updated, session)
            return jsonify(_ai_design_response(updated, state))
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 409

    @app.route('/api/migration/ai/propose', methods=['POST'])
    def propose_migration_ai():
        payload = request.get_json(silent=True)
        if not ai_advisor.advisor_enabled():
            return jsonify({'success': False, 'code': 'AI_DISABLED', 'error': 'AI advisor is disabled.'}), 503
        try:
            if not isinstance(payload, dict):
                raise ValueError('A JSON object is required')
            entry = _lookup_preview(payload.get('preview_id'), 'fortigate')
            if entry is None:
                raise ValueError('A valid FortiGate preview_id is required')
            state = _build_migration_review_state(entry, payload)
            decision_keys = payload.get('decision_keys')
            if decision_keys is None:
                decision_keys = list(ai_advisor.ready_proposal_keys(state))
            if not isinstance(decision_keys, list):
                raise ValueError('decision_keys must be an array')
            if decision_keys:
                ai_advisor.build_proposal_context(
                    state, decision_keys[:ai_advisor._max_decisions()],
                    model=ai_advisor.model_for_decisions(
                        state, decision_keys[:ai_advisor._max_decisions()],
                        provider=ai_advisor.advisor_provider(),
                    ),
                    provider=ai_advisor.advisor_provider(),
                )
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

        started = perf_counter()
        batch_id = uuid.uuid4().hex
        proposals = []
        failure_code = None
        failure_details = []
        for offset in range(0, len(decision_keys), ai_advisor._max_decisions()):
            batch = decision_keys[offset:offset + ai_advisor._max_decisions()]
            try:
                prepared = ai_advisor.build_proposal_context(
                    state, batch,
                    model=ai_advisor.model_for_decisions(state, batch, provider=ai_advisor.advisor_provider()),
                    provider=ai_advisor.advisor_provider(),
                )
                current = ai_advisor.request_proposals(prepared)
                repaired = ai_advisor.repair_conflicted_proposals(state, batch, current)
                proposals.extend(repaired.proposals)
                failure_details.extend(_record_repair_failures(repaired, batch_id))
                if failure_details:
                    failure_code = failure_details[0]["failure_category"]
            except Exception as exc:
                failure = _ai_failure(exc, provider=ai_advisor.advisor_provider(), model=ai_advisor.advisor_model(),
                                      batch_size=len(batch), duration_ms=round((perf_counter() - started) * 1000),
                                      batch_id=batch_id)
                if not proposals:
                    return failure
                failed_response = failure[0].get_json()
                failure_code = failed_response['code']
                if failed_response.get('failure'):
                    failure_details.append(failed_response['failure'])
                break
        if proposals:
            proposal_keys = tuple(item['decision_key'] for item in proposals)
            repaired = ai_advisor.repair_conflicted_proposals(state, proposal_keys, proposals)
            proposals = list(repaired.proposals)
            failure_details.extend(_record_repair_failures(repaired, batch_id))
            if failure_details:
                failure_code = failure_code or failure_details[0]["failure_category"]
            failure_code = failure_code or next(
                (item.get('escalation_failure_category') for item in proposals
                 if item.get('escalation_failure_category')), None)

        now = time.time()
        duration_ms = round((perf_counter() - started) * 1000)
        result = []
        with ai_proposal_lock:
            for proposal_id, (created, _) in list(ai_proposals.items()):
                if now - created > 15 * 60:
                    ai_proposals.pop(proposal_id, None)
                    audit = ai_audit_by_id.get(proposal_id)
                    if audit and audit['engineer_action'] is None:
                        audit['engineer_action'] = 'UNRESOLVED'
            while len(ai_proposals) + len(proposals) > 256:
                oldest = min(ai_proposals, key=lambda item: ai_proposals[item][0])
                ai_proposals.pop(oldest, None)
                audit = ai_audit_by_id.get(oldest)
                if audit and audit['engineer_action'] is None:
                    audit['engineer_action'] = 'UNRESOLVED'
            for proposal in proposals:
                proposal_id = uuid.uuid4().hex
                ai_proposals[proposal_id] = (now, proposal)
                proposal_context = ai_advisor.build_proposal_context(
                    state,
                    [proposal['decision_key']],
                    model=proposal['model'],
                    provider=proposal.get('provider', 'groq'),
                )
                audit = {
                    'proposal_id': proposal_id,
                    'batch_id': batch_id,
                    'request_duration_ms': duration_ms,
                    'failure_category': failure_code or proposal.get('escalation_failure_category'),
                    'response_mode': proposal.get('response_mode', 'STRICT_SCHEMA'),
                    'repair_pass': proposal.get('repair_pass', 0),
                    'created_at': now,
                    'provider': proposal.get('provider', 'groq'),
                    'escalated_from': proposal.get('escalated_from'),
                    'escalation_failure_category': proposal.get('escalation_failure_category'),
                    'model': proposal['model'],
                    'prompt_version': proposal['prompt_version'],
                    'source_digest': proposal['source_digest'],
                    'target_digest': proposal['target_digest'],
                    'target_device': proposal['target_device'],
                    'state_digest': proposal['state_digest'],
                    'context_digest': proposal['context_digest'],
                    'base_context_digest': proposal.get('base_context_digest', proposal['context_digest']),
                    'decision_key': proposal['decision_key'],
                    'review_context': proposal_context['request']['decisions'][0],
                    'proposal': {
                        'action': proposal['action'],
                        'proposed_value': proposal['proposed_value'],
                        'target_scope': proposal['target_scope'],
                        'evidence_refs': proposal['evidence_refs'],
                    },
                    'validation_result': {
                        'status': proposal.get('validation_status', 'VALID'),
                        'findings': proposal.get('validation_findings', []),
                    },
                    'engineer_action': None,
                    'final_value': None,
                }
                ai_audit.append(audit)
                ai_audit_by_id[proposal_id] = audit
                while len(ai_audit) > 5000:
                    removed = ai_audit.pop(0)
                    ai_audit_by_id.pop(removed.get('proposal_id'), None)
                result.append({**proposal, 'proposal_id': proposal_id})
        return jsonify({'success': True, 'proposals': result, 'failure_category': failure_code,
                        'failures': failure_details})

    @app.route('/api/migration/ai/approve', methods=['POST'])
    def approve_migration_ai_proposal():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({'success': False, 'error': 'A JSON object is required'}), 400
        proposal_id = payload.get('proposal_id')
        with ai_proposal_lock:
            record = ai_proposals.get(proposal_id) if isinstance(proposal_id, str) else None
        if record is None:
            return jsonify({'success': False, 'error': 'This AI proposal expired; request a new proposal.'}), 409
        if time.time() - record[0] > 15 * 60:
            with ai_proposal_lock:
                if ai_proposals.get(proposal_id) is record:
                    ai_proposals.pop(proposal_id, None)
                    audit = ai_audit_by_id.get(proposal_id)
                    if audit and audit['engineer_action'] is None:
                        audit['engineer_action'] = 'UNRESOLVED'
            return jsonify({'success': False, 'error': 'This AI proposal expired; request a new proposal.'}), 409
        try:
            entry = _lookup_preview(payload.get('preview_id'), 'fortigate')
            if entry is None:
                raise ValueError('A valid FortiGate preview_id is required')
            state = _build_migration_review_state(entry, payload)
            proposal = record[1]
            confirmed, validated = ai_advisor.approve_proposals_as_engineer(state, [proposal])
            validated = validated[0]
            target_context = state['target_context']
            with ai_proposal_lock:
                if ai_proposals.get(proposal_id) is not record:
                    raise ValueError('This AI proposal has already been used')
                ai_proposals.pop(proposal_id, None)
                audit = ai_audit_by_id.get(proposal_id)
                if audit:
                    audit['engineer_action'] = 'APPROVED'
                    audit['final_value'] = validated['proposed_value']
            return jsonify({
                'success': True,
                'approved_count': 1,
                'decisions': confirmed.to_dict(),
                'decision_document': _decision_document(
                    entry.source_digest, confirmed, target_context.metadata
                ),
            })
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 409

    @app.route('/api/migration/ai/approve-bulk', methods=['POST'])
    def approve_migration_ai_proposals():
        payload = request.get_json(silent=True)
        try:
            if not isinstance(payload, dict):
                raise ValueError('A JSON object is required')
            proposal_ids = payload.get('proposal_ids')
            if (not isinstance(proposal_ids, list) or not proposal_ids or len(proposal_ids) > 64
                    or any(not isinstance(item, str) or not item for item in proposal_ids)
                    or len(set(proposal_ids)) != len(proposal_ids)):
                raise ValueError('proposal_ids must contain 1 to 64 unique proposal IDs')
            with ai_proposal_lock:
                records = {key: ai_proposals.get(key) for key in proposal_ids}
            now = time.time()
            if any(record is None or now - record[0] > 15 * 60 for record in records.values()):
                raise ValueError('One or more AI proposals expired; request current proposals.')
            entry = _lookup_preview(payload.get('preview_id'), 'fortigate')
            if entry is None:
                raise ValueError('A valid FortiGate preview_id is required')
            state = _build_migration_review_state(entry, payload)
            proposals = [records[key][1] for key in proposal_ids]
            confirmed, validated = ai_advisor.approve_proposals_as_engineer(state, proposals)
            target_context = state['target_context']
            with ai_proposal_lock:
                if any(ai_proposals.get(key) is not record for key, record in records.items()):
                    raise ValueError('One or more AI proposals have already been used')
                for key in proposal_ids:
                    ai_proposals.pop(key, None)
                    audit = ai_audit_by_id.get(key)
                    if audit:
                        item = next(value for value in validated if value['decision_key'] == audit['decision_key'])
                        audit['engineer_action'] = 'APPROVED'
                        audit['final_value'] = item['proposed_value']
            return jsonify({
                'success': True,
                'approved_count': len(validated),
                'decisions': confirmed.to_dict(),
                'decision_document': _decision_document(
                    entry.source_digest, confirmed, target_context.metadata
                ),
            })
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 409

    @app.route('/api/migration/ai/outcome', methods=['POST'])
    def record_migration_ai_outcome():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({'success': False, 'error': 'A JSON object is required'}), 400
        proposal_id = payload.get('proposal_id')
        action = payload.get('engineer_action')
        final_value = payload.get('final_value')
        if not isinstance(action, str) or action not in {'MODIFIED', 'REJECTED', 'UNRESOLVED'}:
            return jsonify({'success': False, 'error': 'engineer_action must be MODIFIED, REJECTED, or UNRESOLVED'}), 400
        if action == 'MODIFIED' and (not isinstance(final_value, str) or not final_value.strip()):
            return jsonify({'success': False, 'error': 'A final_value is required for a modified proposal'}), 400
        with ai_proposal_lock:
            audit = ai_audit_by_id.get(proposal_id) if isinstance(proposal_id, str) else None
            if audit is None:
                return jsonify({'success': False, 'error': 'This AI proposal is no longer available for audit.'}), 404
            if audit['engineer_action'] is not None:
                return jsonify({'success': False, 'error': 'This AI proposal already has a recorded outcome.'}), 409
            audit['engineer_action'] = action
            audit['final_value'] = final_value.strip() if action == 'MODIFIED' else None
            ai_proposals.pop(proposal_id, None)
        return jsonify({'success': True})

    @app.route('/api/migration/ai/audit/export', methods=['GET'])
    def export_migration_ai_audit():
        with ai_proposal_lock:
            rows = list(ai_audit)
        content = ''.join(json.dumps(item, separators=(',', ':')) + '\n' for item in rows)
        return send_file(
            io.BytesIO(content.encode('utf-8')),
            mimetype='application/x-ndjson',
            as_attachment=True,
            download_name='migration_ai_audit.jsonl',
        )

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
            previous, invalidated_target_decisions = reconcile_target_evidence(
                previous,
                target_context.metadata if target_context else None,
            )
            target = target_context.analysis if target_context else None
            device = target_context.selected_device if target_context else None
            results = _auto_review_results(analysis.extracted.config, analysis.derived, previous, target, device)
            by_key = {item.key: item for item in previous.decisions}
            for key in payload['decision_keys']:
                result = results.get(key)
                if result is None or result.get('status') not in {'VERIFIED', 'DERIVED'} or not result.get('value'):
                    raise ValueError(f'Decision {key!r} is no longer VERIFIED or DERIVED')
            for key in payload['decision_keys']:
                uses_target = bool(results[key].get('uses_target_evidence'))
                if uses_target:
                    identity = target_evidence_identity(target_context.metadata if target_context else None)
                    if identity is None or identity[1] is None:
                        raise ValueError('Target-backed approval requires a selected PAN-OS device')
                    target_digest, evidence_device = identity
                else:
                    target_digest, evidence_device = None, None
                by_key[key] = replace(
                    by_key[key],
                    value=results[key]['value'],
                    review_state=PANDecisionReviewState.CONFIRMED,
                    evidence_source='ENGINEER',
                    evidence_type='APPROVED_AUTO_REVIEW',
                    evidence_value=results[key]['status'],
                    target_object=results[key]['value'],
                    evidence_target_digest=target_digest,
                    evidence_target_device=evidence_device,
                )
            decisions = PANMigrationDecisionSet(tuple(sorted(by_key.values(), key=lambda item: item.key)))
            return jsonify({'success': True, 'approved_count': len(payload['decision_keys']),
                'decisions': decisions.to_dict(), 'decision_document': _decision_document(entry.source_digest, decisions,
                    target_context.metadata if target_context else None),
                'invalidated_target_decisions': list(invalidated_target_decisions)})
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
            decisions, invalidated_target_decisions = reconcile_target_evidence(
                decisions,
                target_context.metadata if target_context else None,
            )
            result = run_automation_until_stable(
                analysis.extracted.config, analysis.derived, decisions,
                target_context.analysis if target_context else None,
                target_context.selected_device if target_context else None,
                target_evidence=target_context.metadata if target_context else None,
                enabled_policies=enabled,
            )
            return jsonify({'success': True, 'decisions': result.decisions.to_dict(),
                'decision_document': _decision_document(entry.source_digest, result.decisions,
                    target_context.metadata if target_context else None),
                'audit': list(result.audit), 'iterations': result.iterations, 'stable': result.stable,
                'invalidated_target_decisions': list(invalidated_target_decisions)})
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
            target_context = _target_evidence(payload)
            target_metadata = target_context.metadata if target_context else None
            decisions = build_decision_set(analysis.extracted.config, analysis.derived, requirements, previous)
            decisions, invalidated_target_decisions = reconcile_target_evidence(decisions, target_metadata)
            decisions = apply_target_intent(analysis.extracted.config, decisions, payload.get('intent', payload.get('yaml', {})))
            target = target_context.analysis if target_context else None
            device = target_context.selected_device if target_context else None
            automation = run_automation_until_stable(
                analysis.extracted.config, analysis.derived, decisions,
                target, device, target_evidence=target_metadata,
                enabled_policies=payload.get('enabled_policies', ()),
            )
            decisions = automation.decisions
            auto = _auto_review_results(analysis.extracted.config, analysis.derived, decisions, target, device)
            return jsonify({'success': True, 'decisions': decisions.to_dict(),
                'decision_document': _decision_document(entry.source_digest, decisions,
                    target_context.metadata if target_context else None), 'auto_decisions': auto,
                'target_intent': export_target_intent(decisions), 'automation_audit': list(automation.audit),
                'automation_stable': automation.stable,
                'invalidated_target_decisions': list(invalidated_target_decisions)})
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
                uploaded_entry = _lookup_source_preview('fortigate', raw)
                if uploaded_entry is not None:
                    entry = uploaded_entry
                    analysis = _clone_preview(entry)
                else:
                    analysis = source_reporters.get('fortigate').analyze_source(_decode_configuration(raw))
                    entry = _cache_preview('fortigate', raw, analysis, os.path.basename(uploaded.filename))
            elif entry is not None:
                analysis = _clone_preview(entry)
            else:
                return jsonify({'success': False, 'error': 'A valid preview_id or configuration file is required'}), 400

            _require_complete_collection(entry)
            serialized = payload.get('decision_document', payload.get('decisions', payload.get('decision_set')))
            decision_set = None
            options = None
            if serialized is not None:
                if isinstance(serialized, dict) and 'format_version' in serialized:
                    decision_set = _load_decision_document(serialized, entry.source_digest)
                else:
                    decision_set = PANMigrationDecisionSet.from_dict(
                        serialized if isinstance(serialized, dict) else {'decisions': serialized}
                    )
            else:
                mapping_value = payload.get('mapping', '{}')
                mapping = json.loads(mapping_value) if isinstance(mapping_value, str) else mapping_value
                if not isinstance(mapping, dict):
                    raise ValueError('Mapping must contain an object')
                options = PANMigrationOptions(**mapping)

            target_context = _target_evidence(payload)
            target_evidence_changed = _target_evidence_changed(serialized, target_context)
            target = target_context.analysis if target_context else None
            target_device = target_context.selected_device if target_context else None
            mode_value = payload.get('automation_mode', PANAutomationMode.VERIFIED_AND_DERIVED.value)
            if not isinstance(mode_value, str):
                raise ValueError('automation_mode must be a string')
            try:
                automation_mode = PANAutomationMode(mode_value.upper())
            except ValueError as exc:
                raise ValueError('Unsupported automation_mode') from exc

            result = run_migration_pipeline(
                analysis.extracted.config,
                analysis.derived,
                decisions=decision_set,
                options=options,
                target=target,
                target_device=target_device,
                target_evidence=target_context.metadata if target_context else None,
                automation_mode=automation_mode,
                source_digest=entry.source_digest,
                planner=migration_planners.get(source_vendor, target_vendor),
                target_object_reuse_classifier=classify_target_object_reuse,
            )
            target_evidence_changed = target_evidence_changed or bool(result.invalidated_target_decisions)
            decision_set = result.decisions
            mapping = _options_mapping(result.options)
            safe_target_evidence = target_context.metadata if target_context else None
            decision_document = _decision_document(entry.source_digest, decision_set, safe_target_evidence)
            decision_evidence = _decision_evidence(decision_set, result.target_findings)

            rendered = replace(result.rendered, report={
                **result.rendered.report,
                'source': {'vendor': 'fortigate', 'digest': entry.source_digest},
                'target_evidence': safe_target_evidence,
                'review': {
                    'target_evidence_changed': target_evidence_changed,
                    'invalidated_target_decisions': list(result.invalidated_target_decisions),
                    'target_findings': [item.to_dict() for item in result.target_findings],
                    'target_plan_findings': [item.to_dict() for item in result.target_plan_findings],
                    'target_object_reuse': list(result.target_object_reuse),
                    'decision_evidence': decision_evidence,
                    'evidence_summary': _evidence_summary(decision_set, decision_evidence),
                    'support_guidance': [item.to_dict() for item in result.support_guidance],
                    'recommendations': [item.to_dict() for item in result.recommendations],
                    'automation_audit': list(result.automation_audit),
                },
            })
            plan_status = result.artifact_status
            artifact_id = uuid.uuid4().hex
            rendered_artifacts[artifact_id] = rendered
            artifact_sources[artifact_id] = (analysis, mapping, decision_document, entry.source_name)

            counts = rendered.report['counts']
            render_counts = rendered.report['render_dispositions']
            mapping_codes = {
                'missing_vsys_mapping', 'missing_target_vsys',
                'missing_virtual_router', 'missing_route_interface',
                'missing_nat_zone', 'missing_nat_interface',
            }
            missing = [
                issue for issue in rendered.report['issue_summary']
                if issue['code'] in mapping_codes
                or 'missing target' in issue['message'].lower()
                or 'missing palo alto vsys mapping' in issue['message'].lower()
            ]
            issue_messages = {item['code']: item['message'] for item in rendered.report['issue_summary']}
            reasons = []
            for item in rendered.report['items']:
                if item['render_disposition'] != 'BLOCK' and item['command_renderable']:
                    continue
                for code in item['render_blockers']:
                    reasons.append({
                        'code': code,
                        'message': issue_messages.get(code, code.replace('_', ' ').capitalize()),
                        'source_vdom': item['source_vdom'],
                        'source_kind': item['source_kind'],
                        'source_name': item['source_name'],
                        'target_name': item['target_name'],
                    })
            reasons.extend({
                'code': finding.code,
                'message': finding.message,
                'source_vdom': finding.source_vdom,
                'source_kind': finding.source_kind,
                'source_name': finding.source_name,
                'target_name': finding.target_name,
            } for finding in result.target_plan_findings)
            reasons.extend({
                'code': f"MIGRATION_COVERAGE_{item['status']}",
                'message': item['reason'],
                'source_vdom': item['source_vdom'],
                'source_kind': item['source_kind'],
                'source_name': item['source_name'],
                'target_name': item.get('target_object_type'),
            } for item in result.coverage.get('unplanned', ()))
            blocking_reasons = list({
                (item['code'], item['source_vdom'], item['source_kind'], item['source_name'], item['target_name']): item
                for item in reasons
            }.values())
            render_summary = {
                'create': render_counts.get('CREATE', 0),
                'reuse': render_counts.get('REUSE', 0),
                'blocked': render_counts.get('BLOCK', 0),
                'satisfied': rendered.report['satisfied'],
                'command_renderable': rendered.report['command_renderable'],
            }
            return jsonify({
                'success': True,
                'artifact_id': artifact_id,
                'plan_status': plan_status,
                'commands': len(rendered.commands),
                'counts': {**counts, 'renderable': rendered.report['command_renderable']},
                'render_dispositions': render_counts,
                'render_summary': render_summary,
                'missing_mappings': missing,
                'unresolved_required_mappings': [item.to_dict() for item in result.unresolved_decisions],
                'blocking_reasons': blocking_reasons,
                'target_warnings': result.target_warnings,
                'target_findings': [item.to_dict() for item in result.target_findings],
                'target_plan_findings': [item.to_dict() for item in result.target_plan_findings],
                'target_object_reuse': list(result.target_object_reuse),
                'decision_evidence': decision_evidence,
                'evidence_summary': _evidence_summary(decision_set, decision_evidence),
                'support_guidance': [item.to_dict() for item in result.support_guidance],
                'recommendations': [item.to_dict() for item in result.recommendations],
                'coverage': result.coverage,
                'automation_audit': list(result.automation_audit),
                'target_evidence': safe_target_evidence,
                'target_evidence_changed': target_evidence_changed,
                'invalidated_target_decisions': list(result.invalidated_target_decisions),
                'decisions': decision_set.to_dict(),
                'design_session': result.design_session.to_dict() if result.design_session else None,
                'decision_document': decision_document,
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

    def _require_deployment_session(payload):
        session_id = payload.get('deployment_session_id')
        if not isinstance(session_id, str) or not session_id:
            raise ValueError('A validated candidate deployment session is required')
        session = deployment_sessions.get(session_id)
        if session is None:
            raise ValueError('The validated candidate deployment session is missing or expired')
        if time.time() - session.validated_at > _DEPLOYMENT_SESSION_TTL_SECONDS:
            deployment_sessions.pop(session_id, None)
            raise ValueError('The validated candidate deployment session has expired; prepare the candidate again')
        artifact_id = payload.get('artifact_id')
        if artifact_id != session.artifact_id:
            raise ValueError('The deployment session belongs to a different migration artifact')
        rendered = rendered_artifacts.get(session.artifact_id)
        if rendered is None:
            deployment_sessions.pop(session_id, None)
            raise ValueError('The migration artifact for this deployment session has expired')
        if (
            len(rendered.commands) != session.command_count
            or rendered.report.get('command_sha256') != session.command_sha256
        ):
            deployment_sessions.pop(session_id, None)
            raise ValueError('The migration artifact changed after candidate validation')
        options = _deployment_options(payload)
        if (options.host, options.port, options.username) != (session.host, session.port, session.username):
            raise ValueError('The deployment session belongs to a different PAN-OS target identity')
        return session, rendered, options

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
            options = replace(_deployment_options(payload), validate=True, commit=False)
            result = PANSSHDeployer(options).deploy(rendered)
            source = artifact_sources.get(artifact_id)
            decision_document = source[2] if source else None
            validation_feedback = _deployment_validation_feedback(rendered, decision_document, result.validation)
            succeeded = (
                result.failure_message is None
                and result.failed_command_index is None
                and result.validation.status == 'SUCCESS'
                and result.commit.status != 'FAILED'
            )
            deployment_session_id = None
            if succeeded:
                for session_id, session in tuple(deployment_sessions.items()):
                    if session.artifact_id == artifact_id:
                        deployment_sessions.pop(session_id, None)
                deployment_session_id = uuid.uuid4().hex
                deployment_sessions[deployment_session_id] = PANDeploymentSession(
                    session_id=deployment_session_id,
                    artifact_id=artifact_id,
                    command_count=len(rendered.commands),
                    command_sha256=rendered.report['command_sha256'],
                    host=options.host,
                    port=options.port,
                    username=options.username,
                    validation_job_id=result.validation.job_id,
                    validated_at=time.time(),
                )
            return jsonify({
                'success': succeeded,
                'result': asdict(result),
                'validation_feedback': validation_feedback,
                'deployment_session_id': deployment_session_id,
                'candidate_validated': succeeded,
            }), (200 if succeeded else 502)
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

    @app.route('/api/validate-candidate', methods=['POST'])
    def validate_candidate():
        try:
            payload = request.get_json(silent=True) or {}
            session, rendered, options = _require_deployment_session(payload)
            result = PANSSHDeployer(replace(options, validate=True, commit=False)).validate()
            source = artifact_sources.get(session.artifact_id)
            decision_document = source[2] if source else None
            validation_feedback = _deployment_validation_feedback(rendered, decision_document, result)
            if result.status == 'SUCCESS':
                deployment_sessions[session.session_id] = replace(
                    session,
                    validation_job_id=result.job_id,
                    validated_at=time.time(),
                )
            else:
                deployment_sessions.pop(session.session_id, None)
            return jsonify({
                'success': result.status == 'SUCCESS',
                'result': asdict(result),
                'deployment_session_id': session.session_id if result.status == 'SUCCESS' else None,
                'validation_feedback': validation_feedback,
            }), (200 if result.status == 'SUCCESS' else 502)
        except ValueError as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

    @app.route('/api/commit', methods=['POST'])
    def commit_candidate():
        try:
            payload = request.get_json(silent=True) or {}
            session, _rendered, options = _require_deployment_session(payload)
            result = PANSSHDeployer(replace(options, validate=False, commit=False)).commit()
            if result.status == 'SUCCESS':
                deployment_sessions.pop(session.session_id, None)
            return jsonify({
                'success': result.status == 'SUCCESS',
                'result': asdict(result),
                'deployment_session_id': session.session_id if result.status != 'SUCCESS' else None,
            }), (200 if result.status == 'SUCCESS' else 502)
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
            if preview_entry is None and raw_content is not None:
                preview_entry = _timed(
                    metrics,
                    'cache lookup',
                    lambda: _lookup_source_preview(source_vendor, raw_content),
                )
            if preview_entry is not None:
                analysis = (
                    preview_entry.analysis
                    if profile is ExcelExportProfile.FAST or source_vendor == "fortigate"
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
