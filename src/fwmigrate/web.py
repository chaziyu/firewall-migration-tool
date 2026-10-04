import os
import sys
import io
import uuid
import re
import secrets
import hashlib
import logging
import threading
import time
import json
import zipfile
import yaml
from pathlib import Path
from dataclasses import asdict, replace
from dataclasses import dataclass
from functools import wraps
from pydantic import ValidationError
from flask import Flask, Request as FlaskRequest, request, send_file, jsonify

from fwmigrate.source_reporting.builtin import register_builtin_source_reporters
from fwmigrate.conversion.builtin import register_builtin_migration_planners
from fwmigrate.conversion import migration_planners
from fwmigrate.conversion.fortigate_to_palo_alto import run_migration_pipeline
from fwmigrate.conversion.fortigate_to_palo_alto.application import (
    PANAutomationMode,
    PANDecisionMode,
    PANDecisionReviewState,
    PANMigrationDecision,
    PANMigrationDecisionSet,
    PANMigrationOptions,
    build_decision_set,
    make_decision_key,
    build_recommendations,
    build_decision_document,
    load_decision_document,
    options_mapping,
    deployment_validation_feedback,
    build_review_state,
    confirm_mapping_decisions,
    build_mapping_requirements,
    evidence_summary,
    discover_target_candidates,
    suggest_from_target,
    target_devices,
    target_device_metadata,
    validate_against_target,
    build_review_context,
    build_review_evidence,
    build_review_workflow,
    MigrationRuleType,
    apply_repeated_zone_action,
    apply_zone_to_members,
    rule_affected_decision_keys,
    classify_auto_decisions,
    AutomationPolicy,
    run_automation_until_stable,
    reconcile_target_evidence,
    target_evidence_changed as target_evidence_has_changed,
    auto_review_results,
    decision_evidence as build_decision_evidence,
    target_evidence_identity,
    apply_target_intent,
    export_target_intent,
    classify_target_object_reuse,
    build_plan_dependency_index,
    item_key,
    assess_target_plan,
    validate_target_plan,
    build_support_guidance,
    validate_plan,
)
from fwmigrate.conversion.fortigate_to_palo_alto.application.review import (
    confirm_interface_mappings, InterfaceMappingConfirmationError,
)
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.artifact_status import classify_artifact_status
from fwmigrate.deployment import PANDeploymentOptions, PANDeploymentSession, PANSSHDeployer
from fwmigrate.collection import CollectionStatus, source_collectors
from fwmigrate.collection.builtin import register_builtin_collectors
from fwmigrate.collection.snapshot import make_snapshot, parse_snapshot, MAX_BYTES
from fwmigrate.web_support.frontend import register_frontend_routes
from fwmigrate.web_support.reporting import _parse_bool
from fwmigrate.web_api.source import register_source_routes
from fwmigrate.web_support.request_source import analyze_request_source, _clone_preview, _require_complete_collection
from fwmigrate.web_support.artifact_signing import sign_envelope, verify_envelope, verify_artifact
from fwmigrate.conversion.fortigate_to_palo_alto.design.deterministic import (
    build_deterministic_draft, approve_draft, draft_context,
)

register_builtin_source_reporters()
register_builtin_migration_planners()

from fwmigrate.source_reporting import source_reporters
_LOGGER = logging.getLogger(__name__)
_DEPLOYMENT_SESSION_TTL_SECONDS = 30 * 60


class _CandidateSessionError(ValueError):
    """Expected session failures with a fixed, approved public contract."""

    MESSAGES = {
        'session_required': 'A validated candidate deployment session is required',
        'session_missing': 'The validated candidate deployment session is missing or expired',
        'session_expired': 'The validated candidate deployment session has expired; prepare the candidate again',
        'artifact_mismatch': 'The deployment session belongs to a different migration artifact',
        'artifact_expired': 'The migration artifact for this deployment session has expired',
        'artifact_changed': 'The migration artifact changed after candidate validation',
        'target_mismatch': 'The deployment session belongs to a different PAN-OS target identity',
    }

    def __init__(self, code):
        self.code = code
        super().__init__(self.MESSAGES[code])


class _MemoryOnlyUploadRequest(FlaskRequest):
    """Keep bounded customer uploads in memory instead of Werkzeug temp files."""

    def _get_file_stream(
        self,
        total_content_length,
        content_type,
        filename=None,
        content_length=None,
    ):
        return io.BytesIO()

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
    if not payload.get('target_source') and not request.files.get('target_file'):
        return None
    entry = analyze_request_source(payload, 'palo_alto', target=True)
    analysis = _clone_preview(entry)
    devices = target_devices(analysis)
    selected = payload.get('target_device') or (devices[0] if len(devices) == 1 else None)
    if selected and selected not in devices:
        raise ValueError('Selected target device is not in the uploaded PAN-OS configuration')
    return _TargetEvidenceContext(analysis, entry.source_digest, tuple(devices), selected)


def _build_migration_review_state(entry, payload, apply_deterministic=False):
    """Adapt request-owned evidence into the pair-specific review service."""
    _require_complete_collection(entry)
    analysis = _clone_preview(entry)
    prior = payload.get('decision_document')
    target_context = _target_evidence(payload)
    target_metadata = target_context.metadata if target_context else None
    state = build_review_state(
        analysis.extracted.config,
        analysis.derived,
        entry.source_digest,
        previous_document=prior,
        target=target_context.analysis if target_context and payload.get('reference_role') != 'TEMPLATE' else None,
        target_device=target_context.selected_device if target_context and payload.get('reference_role') != 'TEMPLATE' else None,
        target_metadata=target_metadata if payload.get('reference_role') != 'TEMPLATE' else None,
        target_device_count=len(target_context.devices) if target_context else 0,
        apply_deterministic=apply_deterministic,
        include_configuration=payload.get('_deterministic_draft', False),
    )
    return {'analysis': analysis, 'target_context': target_context, **state}


def create_app(test_config=None):
    register_builtin_collectors()
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        base_dir = os.path.join(sys._MEIPASS, 'fwmigrate')
        frontend_dist = os.path.join(sys._MEIPASS, 'frontend', 'dist')
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        frontend_dist = os.path.join(os.path.dirname(base_dir), 'frontend', 'dist')

    app = Flask(__name__, static_folder=None)
    app.request_class = _MemoryOnlyUploadRequest

    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

    if test_config:
        app.config.update(test_config)
    app.config.setdefault('FRONTEND_DIST_DIR', os.environ.get('FWMIGRATE_FRONTEND_DIST_DIR') or frontend_dist)
    app.config.setdefault(
        'ALLOW_REMOTE_COLLECTION',
        os.environ.get('FWMIGRATE_ALLOW_REMOTE_COLLECTION', '').strip().casefold() in {'1', 'true', 'yes', 'on'},
    )
    app.config.setdefault(
        'ALLOW_REMOTE_DEPLOYMENT',
        os.environ.get('FWMIGRATE_ALLOW_REMOTE_DEPLOYMENT', '').strip().casefold() in {'1', 'true', 'yes', 'on'},
    )
    app.config.setdefault('MAX_CONTENT_LENGTH', 2 * MAX_BYTES + 5_000_000)

    require_web_auth = app.config.get('REQUIRE_WEB_AUTH')
    if require_web_auth is None:
        require_web_auth = str(os.environ.get('FWMIGRATE_REQUIRE_WEB_AUTH', '')).strip().lower() in {
            '1', 'true', 'yes', 'on',
        }
    web_username = str(
        app.config.get('WEB_AUTH_USERNAME')
        or os.environ.get('FWMIGRATE_WEB_USERNAME')
        or 'fwmigrate'
    )
    web_password = app.config.get('WEB_AUTH_PASSWORD') or os.environ.get('FWMIGRATE_WEB_PASSWORD')
    if app.config.get('ALLOW_REMOTE_COLLECTION') and not web_password:
        raise RuntimeError(
            'Remote live collection requires configured web authentication'
        )
    if app.config.get('ALLOW_REMOTE_DEPLOYMENT') and not web_password:
        raise RuntimeError(
            'Remote deployment requires configured web authentication'
        )
    if require_web_auth and not web_password:
        raise RuntimeError(
            'Hosted web authentication is required but FWMIGRATE_WEB_PASSWORD is not configured'
        )

    if web_password:
        expected_password = str(web_password)

        @app.before_request
        def _authenticate_hosted_web():
            if request.path == '/healthz':
                return None
            authorization = request.authorization
            if (
                authorization is not None
                and authorization.type == 'basic'
                and secrets.compare_digest(authorization.username or '', web_username)
                and secrets.compare_digest(authorization.password or '', expected_password)
            ):
                return None
            response = jsonify({'error': 'Authentication required'})
            response.status_code = 401
            response.headers['WWW-Authenticate'] = 'Basic realm="Firewall Migration Tool"'
            return response

    @app.after_request
    def _security_headers(response):
        response.headers.setdefault('Content-Security-Policy',
            "default-src 'self'; connect-src 'self'; img-src 'self' data: blob:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self'; font-src 'self' data:; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('Referrer-Policy', 'no-referrer')
        response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        if request.path.startswith('/api/'):
            response.headers['Cache-Control'] = 'no-store, private'
            response.headers['Pragma'] = 'no-cache'
        return response

    @app.route('/healthz', methods=['GET'])
    def healthz():
        return jsonify({'status': 'ok'})

    signing_key = app.config.get('WORKSPACE_SIGNING_KEY') or os.environ.get('FWMIGRATE_WORKSPACE_SIGNING_KEY')
    if signing_key:
        signing_key = signing_key.encode() if isinstance(signing_key, str) else signing_key
        if len(signing_key) < 32:
            raise ValueError('Workspace signing key must contain at least 32 bytes')
    else:
        signing_key = os.urandom(32)
        _LOGGER.warning('Temporary workspace signing key: signed artifacts expire on server restart')
    deployment_sessions = {}
    target_locks = {}
    coordination_lock = threading.RLock()

    def _candidate_operation(function):
        @wraps(function)
        def locked(*args, **kwargs):
            if (
                not app.config.get('ALLOW_REMOTE_DEPLOYMENT')
                and request.remote_addr not in {'127.0.0.1', '::1'}
            ):
                return jsonify({
                    'success': False,
                    'error': 'Remote deployment is disabled on this server.',
                }), 403
            payload = request.get_json(silent=True) or {}
            try:
                if request.path == '/api/deploy':
                    rendered = _request_artifact(payload)
                    if not rendered.commands:
                        raise ValueError('The migration artifact contains no renderable commands')
                options = _deployment_options(payload)
            except ValueError as exc:
                return jsonify({'success': False, 'error': str(exc)}), 400
            key = (options.host.casefold(), options.port)
            with coordination_lock:
                lock, users = target_locks.get(key, (threading.RLock(), 0))
                target_locks[key] = (lock, users + 1)
            try:
                with lock:
                    return function(*args, **kwargs)
            finally:
                with coordination_lock:
                    lock, users = target_locks[key]
                    if users == 1:
                        target_locks.pop(key)
                    else:
                        target_locks[key] = (lock, users - 1)
        return locked

    @app.before_request
    def _prune_deployment_sessions():
        with coordination_lock:
            for key, session in tuple(deployment_sessions.items()):
                if time.time() - session.validated_at >= _DEPLOYMENT_SESSION_TTL_SECONDS:
                    deployment_sessions.pop(key, None)

    def _migration_source(payload):
        entry = analyze_request_source(payload, 'fortigate')
        _require_complete_collection(entry)
        return entry

    def _request_artifact(payload):
        return verify_artifact(payload.get('artifact'), signing_key)

    def _decision_approval_snapshot(decisions):
        fields = ('value', 'review_state', 'approved_operation', 'approval_context',
                  'evidence_source', 'evidence_type', 'evidence_value', 'target_object',
                  'evidence_target_digest', 'evidence_target_device')
        result = {}
        for row in decisions.decisions:
            data = row.to_dict()
            result[row.key] = {field: data[field] for field in fields}
        return result

    def _reviewed_design_document(payload, entry, *, strict=False):
        document = payload.get('decision_document')
        if not isinstance(document, dict):
            return document, None
        decisions = load_decision_document(document, entry.source_digest)
        approval = document.get('design_approval')
        if approval is None:
            if any(row.approved_operation for row in decisions.decisions):
                raise ValueError('Draft operations require a signed engineer approval')
            return document, None
        verify_envelope(approval, signing_key)
        if approval.get('envelope_type') != 'pan_design_approval':
            raise ValueError('A signed design approval is required')
        target_context = _target_evidence(payload)
        bound = approval['context']
        context = draft_context(entry.source_digest, target_context.metadata if target_context else None,
            payload.get('reference_role', bound['reference_role']),
            target_context.selected_device if target_context else None,
            payload.get('target_intent', bound['intent']))
        context['overrides'] = payload.get('draft_overrides', bound.get('overrides', {}))
        current = _decision_approval_snapshot(decisions)
        stale = context != bound or current != approval.get('decisions')
        if stale:
            if strict:
                raise ValueError('Approved design is stale or modified; prepare and review it again')
            decisions = PANMigrationDecisionSet(tuple(replace(row, value=None,
                review_state=PANDecisionReviewState.PENDING, approved_operation=None, approval_context=None,
                evidence_source=None, evidence_type=None, evidence_value=None, target_object=None)
                if row.approved_operation or row.approval_context else row for row in decisions.decisions))
            return build_decision_document(entry.source_digest, decisions), None
        return document, approval

    def _deterministic_state(payload, entry):
        document, approval = _reviewed_design_document(payload, entry)
        bound = (approval or {}).get('context', {})
        payload = {**payload, 'decision_document': document,
                   '_deterministic_draft': True,
                   'reference_role': payload.get('reference_role', bound.get('reference_role'))}
        state = _build_migration_review_state(entry, payload)
        target_context = state['target_context']
        draft = build_deterministic_draft(state['analysis'].extracted.config, state['analysis'].derived,
            state['decisions'], source_digest=entry.source_digest,
            target=target_context.analysis if target_context else None,
            target_device=target_context.selected_device if target_context else None,
            reference=target_context.metadata if target_context else None,
            reference_role=payload.get('reference_role'),
            intent=payload.get('target_intent', bound.get('intent')),
            overrides=payload.get('draft_overrides', bound.get('overrides')))
        return state, draft, approval

    @app.route('/api/migration/design/prepare', methods=['POST'])
    def prepare_migration_design():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            raise ValueError('A JSON object is required')
        entry = _migration_source(payload)
        state, draft, approval = _deterministic_state(payload, entry)
        response = _migration_review_response(entry, state).get_json()
        response['draft'] = sign_envelope(draft.to_dict(), signing_key)
        response['decision_document']['draft_required'] = True
        if approval:
            response['decision_document']['design_approval'] = approval
        return jsonify(response)

    @app.route('/api/migration/design/approve', methods=['POST'])
    def approve_migration_design():
        try:
            payload = request.get_json(silent=True)
            if not isinstance(payload, dict):
                raise ValueError('A JSON object is required')
            signed = verify_envelope(payload.get('draft'), signing_key)
            if signed.get('envelope_type') != 'pan_migration_draft':
                raise ValueError('A signed deterministic draft is required')
            entry = _migration_source(payload)
            state, draft, previous_approval = _deterministic_state(payload, entry)
            body = draft.to_dict()
            if signed.get('digest') != body['digest'] or payload.get('draft_digest') != body['digest']:
                raise ValueError('Draft is stale; prepare and review the current configuration')
            selected = payload.get('selected_groups')
            confirmed = approve_draft(state['decisions'], draft, selected,
                approved_groups=tuple('item:' + key for key in (previous_approval or {}).get('configuration', {})))
            selected = set(selected)
            approved_rows = dict((previous_approval or {}).get('configuration', {}))
            approved_rows.update({row['item_key']: row for row in body['configuration'] if row['group_key'] in selected})
            # Bind the exact approved operations, values, scope, evidence and dependency context.
            approval = sign_envelope({'envelope_type': 'pan_design_approval', 'context': body['context'],
                'draft_digest': body['digest'], 'configuration': approved_rows,
                'decisions': _decision_approval_snapshot(confirmed)}, signing_key)
            document = build_decision_document(entry.source_digest, confirmed,
                state['target_context'].metadata if state['target_context'] and body['context']['reference_role'] == 'DESTINATION' else None)
            document['design_approval'] = approval
            document['draft_required'] = True
            return jsonify({'success': True, 'approved_count': len(selected), 'decision_document': document,
                            'decisions': confirmed.to_dict()})
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 409

    @app.errorhandler(ValueError)
    def _invalid_request(error):
        return jsonify({'success': False, 'error': str(error)}), 400

    @app.errorhandler(ValidationError)
    def _invalid_model(_error):
        return jsonify({'success': False, 'error': 'Invalid configuration fields'}), 400

    register_frontend_routes(app)
    register_source_routes(app)

    def _migration_review_response(entry, state):
        target_context = state['target_context']
        target = target_context.analysis if target_context else None
        decisions = state['decisions']
        return jsonify({'success': True, 'source_digest': entry.source_digest, 'requirements': state['requirements'],
                        'decisions': decisions.to_dict(),
                        'design_session': state['design_session'].to_dict(),
                        'decision_document': build_decision_document(entry.source_digest, decisions,
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
                        'evidence_summary': evidence_summary(decisions, state['decision_evidence']),
                        'target_evidence': target_context.metadata if target_context else None,
                        'target_evidence_changed': state['target_evidence_changed'],
                        'invalidated_target_decisions': list(state['invalidated_target_decisions']),
                        'recommendations': [item.to_dict() for item in state['recommendations']]})

    @app.route('/api/migration/requirements', methods=['POST'])
    def migration_requirements():
        payload = request.get_json(silent=True) or request.form
        try:
            entry = _migration_source(payload)
            state = _build_migration_review_state(entry, payload)
            return _migration_review_response(entry, state)
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400
        except Exception:
            _LOGGER.exception('Migration requirements failed')
            return jsonify({'success': False, 'error': 'Migration requirements failed'}), 500

    @app.route('/api/migration/interfaces/confirm', methods=['POST'])
    def migration_interfaces_confirm():
        payload = request.get_json(silent=True)
        try:
            if not isinstance(payload, dict):
                raise ValueError('An interface confirmation request is required')
            entry = _migration_source(payload)
            _require_complete_collection(entry)
            analysis = _clone_preview(entry)
            target_context = _target_evidence(payload)
            state = confirm_interface_mappings(
                analysis.extracted.config, analysis.derived, entry.source_digest,
                previous_document=payload.get('decision_document'), selections=payload.get('selections'),
                reviewed_target_evidence=payload.get('reviewed_target_evidence'),
                target=target_context.analysis if target_context else None,
                target_device=target_context.selected_device if target_context else None,
                target_metadata=target_context.metadata if target_context else None,
                target_device_count=len(target_context.devices) if target_context else 0,
            )
            return _migration_review_response(entry, {'target_context': target_context, **state})
        except InterfaceMappingConfirmationError as exc:
            return jsonify({'success': False, 'error': str(exc), 'errors': exc.errors}), 400
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

    @app.route('/api/migration/decisions/approve', methods=['POST'])
    def approve_migration_decisions():
        payload = request.get_json(silent=True)
        try:
            if not isinstance(payload, dict) or not isinstance(payload.get('decision_keys'), list) or not payload['decision_keys']:
                raise ValueError('decision_keys must be a non-empty array')
            if any(not isinstance(key, str) for key in payload['decision_keys']) or len(set(payload['decision_keys'])) != len(payload['decision_keys']):
                raise ValueError('decision_keys must contain unique strings')
            entry = _migration_source(payload)
            previous = load_decision_document(payload.get('decision_document'), entry.source_digest)
            analysis = _clone_preview(entry)
            target_context = _target_evidence(payload)
            previous, invalidated_target_decisions = reconcile_target_evidence(
                previous,
                target_context.metadata if target_context else None,
            )
            target = target_context.analysis if target_context else None
            device = target_context.selected_device if target_context else None
            results = auto_review_results(analysis.extracted.config, analysis.derived, previous, target, device)
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
                'decisions': decisions.to_dict(), 'decision_document': build_decision_document(entry.source_digest, decisions,
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
            entry = _migration_source(payload)
            document = payload.get('decision_document')
            decisions = load_decision_document(document, entry.source_digest)
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
                'decision_document': build_decision_document(entry.source_digest, result.decisions,
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
            entry = _migration_source(payload)
            document = payload.get('decision_document')
            previous = load_decision_document(document, entry.source_digest) if document else None
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
            auto = auto_review_results(analysis.extracted.config, analysis.derived, decisions, target, device)
            return jsonify({'success': True, 'decisions': decisions.to_dict(),
                'decision_document': build_decision_document(entry.source_digest, decisions,
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
            entry = _migration_source(payload)
            decisions = load_decision_document(payload.get('decision_document'), entry.source_digest)
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
                entry = _migration_source(payload)
                document = payload.get('decision_document')
                previous = load_decision_document(document, entry.source_digest)
                analysis = _clone_preview(entry)
                decisions = apply_repeated_zone_action(analysis.extracted.config, previous,
                    source_vdom=payload.get('source_vdom'), source_zone=payload.get('source_zone'),
                    value=payload.get('value'), apply_to=payload.get('apply_to'))
                return jsonify({'success': True, 'applied_count': len(payload['apply_to']),
                    'decision_document': build_decision_document(entry.source_digest, decisions,
                        document.get('target_evidence'))})
            try:
                raw_rule_type = payload.get('rule_type')
                rule_type = MigrationRuleType.ZONE_TO_MEMBERS if raw_rule_type == 'APPLY_ZONE_TO_MEMBERS' else MigrationRuleType(raw_rule_type)
            except ValueError as exc:
                raise ValueError('Unsupported migration rule') from exc
            entry = _migration_source(payload)
            document = payload.get('decision_document')
            previous = load_decision_document(document, entry.source_digest)
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
                    'decision_document': build_decision_document(entry.source_digest, decisions,
                        document.get('target_evidence'))})
            target_context = _target_evidence(payload)
            results = classify_auto_decisions(analysis.extracted.config, analysis.derived, previous,
                target_context.analysis if target_context else None,
                target_context.selected_device if target_context else None)
            return jsonify({'success': True, 're_evaluated_count': len(apply_to),
                'auto_decisions': {key: results.get(key, {'status': 'MANUAL'}) for key in apply_to},
                'decision_document': build_decision_document(entry.source_digest, previous,
                    target_context.metadata if target_context else document.get('target_evidence'))})
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400
        except Exception:
            _LOGGER.exception('Migration re-evaluation failed')
            return jsonify({'success': False, 'error': 'Migration re-evaluation failed'}), 500

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
        entry = _migration_source(payload)
        try:
            serialized = payload.get('decision_document', payload.get('decisions'))
            if serialized is None:
                analysis = _clone_preview(entry)
                requirements = build_mapping_requirements(analysis.extracted.config, analysis.derived)
                decision_set = build_decision_set(analysis.extracted.config, analysis.derived, requirements)
            elif isinstance(serialized, dict) and 'format_version' in serialized:
                decision_set = load_decision_document(serialized, entry.source_digest)
            else:
                decision_set = PANMigrationDecisionSet.from_dict(
                    serialized if isinstance(serialized, dict) else {'decisions': serialized}
                )
            target_evidence = serialized.get('target_evidence') if isinstance(serialized, dict) else None
            document = build_decision_document(entry.source_digest, decision_set, target_evidence)
            if isinstance(serialized, dict) and serialized.get('design_approval'):
                verify_envelope(serialized['design_approval'], signing_key)
                document['design_approval'] = serialized['design_approval']
                document['draft_required'] = True
            return jsonify({'success': True, 'document': document})
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

    @app.route('/api/migration/decisions/import', methods=['POST'])
    def import_migration_decisions():
        payload = request.get_json(silent=True) or {}
        entry = _migration_source(payload)
        try:
            decision_set = load_decision_document(payload.get('document'), entry.source_digest)
            target_evidence = (payload.get('document') or {}).get('target_evidence') if isinstance(payload.get('document'), dict) else None
            document = build_decision_document(entry.source_digest, decision_set, target_evidence)
            if payload['document'].get('design_approval'):
                verify_envelope(payload['document']['design_approval'], signing_key)
                document['design_approval'] = payload['document']['design_approval']
                document['draft_required'] = True
            return jsonify({'success': True, 'decision_document': document,
                            'decisions': decision_set.to_dict(), 'mapping': options_mapping(decision_set.to_options())})
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
            entry = _migration_source(payload)
            analysis = entry.analysis

            _require_complete_collection(entry)
            serialized = payload.get('decision_document', payload.get('decisions', payload.get('decision_set')))
            design_approval = None
            if isinstance(serialized, dict) and 'format_version' in serialized:
                serialized, design_approval = _reviewed_design_document(payload, entry, strict=True)
                if serialized.get('draft_required') and design_approval is None:
                    raise ValueError('Review and approve the deterministic draft before building an artifact')
            decision_set = None
            options = None
            if serialized is not None:
                if isinstance(serialized, dict) and 'format_version' in serialized:
                    decision_set = load_decision_document(serialized, entry.source_digest)
                else:
                    decision_set = PANMigrationDecisionSet.from_dict(
                        serialized if isinstance(serialized, dict) else {'decisions': serialized}
                    )
                    if any(row.approved_operation for row in decision_set.decisions):
                        raise ValueError('Draft operations require a signed engineer approval')
            else:
                mapping_value = payload.get('mapping', '{}')
                mapping = json.loads(mapping_value) if isinstance(mapping_value, str) else mapping_value
                if not isinstance(mapping, dict):
                    raise ValueError('Mapping must contain an object')
                options = PANMigrationOptions(**mapping)

            target_context = _target_evidence(payload)
            target_evidence_changed = target_evidence_has_changed((serialized.get('target_evidence') if isinstance(serialized, dict) else None), (target_context.metadata if target_context else None))
            target = target_context.analysis if target_context else None
            target_device = target_context.selected_device if target_context else None
            if design_approval and design_approval['context']['reference_role'] != 'DESTINATION':
                target, target_device = None, None
            mode_value = payload.get('automation_mode', PANAutomationMode.REVIEW_ONLY.value if design_approval else PANAutomationMode.VERIFIED_AND_DERIVED.value)
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
                approved_item_keys=set(design_approval['configuration']) if design_approval else None,
            )
            target_evidence_changed = target_evidence_changed or bool(result.invalidated_target_decisions)
            decision_set = result.decisions
            mapping = options_mapping(result.options)
            safe_target_evidence = target_context.metadata if target_context else None
            decision_document = build_decision_document(entry.source_digest, decision_set, safe_target_evidence)
            if design_approval:
                decision_document['design_approval'] = design_approval
            decision_evidence = build_decision_evidence(decision_set, result.target_findings)

            rendered = replace(result.rendered, report={
                **result.rendered.report,
                'source': {'vendor': 'fortigate', 'digest': entry.source_digest},
                'target_evidence': safe_target_evidence,
                'approved_design_digest': design_approval['draft_digest'] if design_approval else None,
                'destination_verified': bool(design_approval and design_approval['context']['reference_role'] == 'DESTINATION'
                                             and target is not None and target_device),
                'review': {
                    'target_evidence_changed': target_evidence_changed,
                    'invalidated_target_decisions': list(result.invalidated_target_decisions),
                    'target_findings': [item.to_dict() for item in result.target_findings],
                    'target_plan_findings': [item.to_dict() for item in result.target_plan_findings],
                    'target_object_reuse': list(result.target_object_reuse),
                    'decision_evidence': decision_evidence,
                    'evidence_summary': evidence_summary(decision_set, decision_evidence),
                    'support_guidance': [item.to_dict() for item in result.support_guidance],
                    'recommendations': [item.to_dict() for item in result.recommendations],
                    'automation_audit': list(result.automation_audit),
                },
            })
            plan_status = result.artifact_status
            if design_approval and not rendered.report['destination_verified']:
                plan_status = 'PARTIAL'
                rendered = replace(rendered, report={**rendered.report, 'plan_status': plan_status})
            artifact_id = uuid.uuid4().hex
            artifact = sign_envelope({
                'artifact_id': artifact_id, 'commands': list(rendered.commands),
                'command_count': len(rendered.commands), 'command_sha256': rendered.report['command_sha256'],
                'report': rendered.report, 'decision_document': decision_document, 'mapping': mapping,
            }, signing_key)

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
            if render_counts.get('CONFIGURE'):
                render_summary['configure'] = render_counts['CONFIGURE']
            response = {
                'success': True,
                'artifact_id': artifact_id,
                'plan_status': plan_status,
                'commands': list(rendered.commands),
                'command_count': len(rendered.commands),
                'command_sha256': artifact['command_sha256'],
                'artifact': artifact,
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
                'evidence_summary': evidence_summary(decision_set, decision_evidence),
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
            }
            if payload.get('compact_response') is True:
                # The signed artifact contains the complete evidence; keep only the React summaries beside it.
                response = {key: response[key] for key in (
                    'success', 'artifact_id', 'plan_status', 'command_count', 'command_sha256',
                    'artifact', 'counts', 'render_summary', 'blocking_reasons',
                )}
            return jsonify(response)
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

    @app.route('/api/migration/bundle', methods=['POST'])
    def migration_bundle():
        payload = request.get_json(silent=True) or {}
        artifact_id = (payload.get('artifact') or {}).get('artifact_id')
        rendered = _request_artifact(payload)
        if rendered is None:
            return jsonify({'success': False, 'error': 'A current migration plan is required'}), 400
        if not rendered.commands and rendered.report.get('plan_status') != 'READY_NO_CHANGES':
            return jsonify({'success': False, 'error': 'No PAN-OS commands are currently renderable. Complete the required target mappings first.'}), 422
        entry = _migration_source(payload)
        _require_complete_collection(entry)
        if entry.source_digest != rendered.report['source']['digest']:
            raise ValueError('Bundle source does not match the signed artifact')
        analysis, source_name = entry.analysis, entry.source_name
        mapping = payload['artifact']['mapping']
        decision_document = payload['artifact']['decision_document']
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
        except Exception:
            _LOGGER.exception('Migration bundle export failed')
            return jsonify({'success': False, 'error': 'Migration bundle export failed'}), 500

    @app.route('/api/migration/command-preview', methods=['POST'])
    def migration_command_preview():
        payload = request.get_json(silent=True) or {}
        artifact_id = (payload.get('artifact') or {}).get('artifact_id')
        rendered = _request_artifact(payload)
        if rendered is None:
            return jsonify({'success': False, 'error': 'A current migration plan is required'}), 400
        if not rendered.commands and rendered.report.get('plan_status') != 'READY_NO_CHANGES':
            return jsonify({'success': False, 'error': 'No PAN-OS commands are currently renderable. Complete the required target mappings first.'}), 422
        decision_document = payload['artifact']['decision_document']
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
        rendered = _request_artifact(payload)
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
            raise _CandidateSessionError('session_required')
        session = deployment_sessions.get(session_id)
        if session is None:
            raise _CandidateSessionError('session_missing')
        if time.time() - session.validated_at > _DEPLOYMENT_SESSION_TTL_SECONDS:
            deployment_sessions.pop(session_id, None)
            raise _CandidateSessionError('session_expired')
        artifact_id = (payload.get('artifact') or {}).get('artifact_id')
        if artifact_id != session.artifact_id:
            raise _CandidateSessionError('artifact_mismatch')
        rendered = _request_artifact(payload)
        if rendered is None:
            deployment_sessions.pop(session_id, None)
            raise _CandidateSessionError('artifact_expired')
        if (
            len(rendered.commands) != session.command_count
            or rendered.report.get('command_sha256') != session.command_sha256
        ):
            deployment_sessions.pop(session_id, None)
            raise _CandidateSessionError('artifact_changed')
        options = _deployment_options(payload)
        if (options.host.casefold(), options.port) != (session.host.casefold(), session.port):
            raise _CandidateSessionError('target_mismatch')
        return session, rendered, options

    @app.route('/api/deploy', methods=['POST'])
    @_candidate_operation
    def deploy_candidate():
        try:
            payload = request.get_json(silent=True) or {}
            artifact_id = (payload.get('artifact') or {}).get('artifact_id')
            rendered = _request_artifact(payload)
            if rendered is None:
                raise ValueError('A current validated rendered migration is required')
            if not rendered.commands:
                raise ValueError('The migration artifact contains no renderable commands')
            options = replace(_deployment_options(payload), validate=True)
            for session_id, session in tuple(deployment_sessions.items()):
                if (session.host.casefold(), session.port) == (options.host.casefold(), options.port):
                    deployment_sessions.pop(session_id, None)
            result = PANSSHDeployer(options).deploy(rendered)
            decision_document = payload['artifact']['decision_document']
            validation_feedback = deployment_validation_feedback(rendered, decision_document, result.validation)
            succeeded = (
                result.failure_message is None
                and result.failed_command_index is None
                and result.validation.status == 'SUCCESS'
            )
            deployment_session_id = None
            if succeeded:
                deployment_session_id = uuid.uuid4().hex
                deployment_sessions[deployment_session_id] = PANDeploymentSession(
                    session_id=deployment_session_id,
                    artifact_id=artifact_id,
                    command_count=len(rendered.commands),
                    command_sha256=rendered.report['command_sha256'],
                    host=options.host,
                    port=options.port,
                    validation_job_id=result.validation.job_id,
                    validated_at=time.time(),
                )
            return jsonify({
                'success': succeeded,
                'error': None if succeeded else result.failure_message or result.validation.response or 'Candidate preparation failed',
                'result': asdict(result),
                'validation_feedback': validation_feedback,
                'deployment_session_id': deployment_session_id,
                'candidate_validated': succeeded,
            }), (200 if succeeded else 502)
        except (ValueError, KeyError, TypeError) as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

    @app.route('/api/validate-candidate', methods=['POST'])
    @_candidate_operation
    def validate_candidate():
        try:
            payload = request.get_json(silent=True) or {}
            session, rendered, options = _require_deployment_session(payload)
            result = PANSSHDeployer(replace(options, validate=True)).validate()
            decision_document = payload['artifact']['decision_document']
            validation_feedback = deployment_validation_feedback(rendered, decision_document, result)
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
                'error': None if result.status == 'SUCCESS' else result.response or 'Candidate validation failed',
                'result': asdict(result),
                'deployment_session_id': session.session_id if result.status == 'SUCCESS' else None,
                'validation_feedback': validation_feedback,
            }), (200 if result.status == 'SUCCESS' else 502)
        except ValueError as exc:
            return jsonify({'success': False, 'error': str(exc)}), 400

    @app.route('/api/commit', methods=['POST'])
    @_candidate_operation
    def commit_candidate():
        try:
            payload = request.get_json(silent=True) or {}
            session, _rendered, options = _require_deployment_session(payload)
            result = PANSSHDeployer(replace(options, validate=False)).commit()
            if result.status == 'SUCCESS':
                deployment_sessions.pop(session.session_id, None)
            return jsonify({
                'success': result.status == 'SUCCESS',
                'error': None if result.status == 'SUCCESS' else result.response or 'Candidate commit failed',
                'result': asdict(result),
                'deployment_session_id': session.session_id if result.status != 'SUCCESS' else None,
            }), (200 if result.status == 'SUCCESS' else 502)
        except _CandidateSessionError as exc:
            return jsonify({
                'success': False,
                'error': _CandidateSessionError.MESSAGES[exc.code],
                'error_code': exc.code,
            }), 400
        except ValueError:
            _LOGGER.info("Invalid candidate commit request")
            return jsonify({'success': False, 'error': 'Invalid candidate commit request'}), 400

    return app
