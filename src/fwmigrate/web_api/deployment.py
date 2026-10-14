"""HTTP endpoints and process-local coordination for PAN-OS candidate deployment."""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import asdict, replace
from functools import wraps

from flask import jsonify, request

from fwmigrate.conversion.fortigate_to_palo_alto.application import ArtifactEligibilityError, deployment_validation_feedback, deployment_serial
from fwmigrate.deployment import PANDeploymentOptions, PANDeploymentSession
from fwmigrate.web_support.artifact_signing import verify_artifact, verify_envelope
from fwmigrate.web_support.reporting import _parse_bool

_LOGGER = logging.getLogger(__name__)
_DEPLOYMENT_SESSION_TTL_SECONDS = 30 * 60

# Fixed application integrity checks are safe; transport/device exception text is not.
_SAFE_DEPLOYMENT_ERRORS = frozenset({
    'Destination changed since review; refresh evidence and approve the design again',
    'Live PAN-OS serial is missing or differs from the approved destination',
    'Cannot read complete PAN-OS candidate state',
    'Approved destination baseline evidence is required before preparation',
    'Cannot verify live PAN-OS identity and candidate state',
    'Candidate changed after validation; prepare the candidate again',
    'Cannot verify whether the candidate has existing changes',
    'Candidate has existing or unknown unreviewed changes; resolve them before preparation',
    'A validated candidate fingerprint is required',
})


def _public_deployment_error(message, fallback):
    return message if message in _SAFE_DEPLOYMENT_ERRORS else fallback


def _public_deployment_result(result):
    """Keep status/identity/counts while excluding untrusted failure diagnostics."""
    public = asdict(result)
    if 'failure_message' in public:
        if public['failure_message'] is not None:
            public['failure_message'] = _public_deployment_error(public['failure_message'], 'Candidate preparation failed')
        for command in public.get('command_results', ()):
            command['response'] = 'Candidate command accepted' if command['accepted'] else 'Candidate command failed'
        for name in ('validation', 'commit'):
            nested = public.get(name)
            if nested and nested['status'] not in {'SUCCESS', 'NOT_RUN'}:
                nested['response'] = _public_deployment_error(nested['response'], 'Candidate operation failed')
    elif public['status'] not in {'SUCCESS', 'NOT_RUN'}:
        public['response'] = _public_deployment_error(public['response'], 'Candidate operation failed')
    return public


def _recovery(state, *, result=None, artifact_id=None):
    return {"state": state, "artifact_id": artifact_id,
            "commands_attempted": getattr(result, "commands_attempted", None),
            "commands_succeeded": getattr(result, "commands_succeeded", None),
            "failed_command_index": getattr(result, "failed_command_index", None),
            "next_action": "NONE" if state == "COMMITTED" else "REVIEW_VALIDATION" if state == "VALIDATED" else "INSPECT_CANDIDATE",
            "explanation": "Re-enter credentials to inspect identity, reviewed baseline and candidate changes. Reconcile with the operator; changes may include another administrator's work. Never replay or discard automatically."}


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


class DeploymentCoordinator:
    """Per-app candidate session and target-lock state."""

    def __init__(self) -> None:
        self.sessions = {}
        self.target_locks = {}
        self.lock = threading.RLock()


def register_deployment_routes(
    app,
    signing_key,
    coordinator: DeploymentCoordinator,
    *,
    deployer_factory,
) -> None:
    deployment_sessions = coordinator.sessions
    target_locks = coordinator.target_locks
    coordination_lock = coordinator.lock

    def _request_artifact(payload):
        artifact = payload.get('artifact')
        rendered = verify_artifact(artifact, signing_key)
        document = artifact.get('decision_document') or {}
        approval = verify_envelope(document.get('design_approval'), signing_key)
        deployment_serial(rendered, document, approval)
        return rendered

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
                if request.path in {'/api/deploy', '/api/inspect-candidate'}:
                    rendered = _request_artifact(payload)
                    if rendered is None:
                        raise ValueError('A current validated rendered migration is required')
                    if not rendered.commands:
                        return jsonify({'success': False, 'error': 'The migration artifact contains no renderable commands'}), 400
                options = _deployment_options(payload)
            except ArtifactEligibilityError as exc:
                return jsonify({'success': False, 'error': str(exc), 'error_code': 'artifact_ineligible'}), 400
            except (ValueError, KeyError, TypeError):
                _LOGGER.warning('Invalid deployment request payload.')
                return jsonify({'success': False, 'error': 'A signed READY design with approved destination serial evidence is required.'}), 400
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
        if not session.device_serial or not session.candidate_sha256:
            deployment_sessions.pop(session_id, None)
            raise _CandidateSessionError('session_missing')
        options = replace(options, expected_serial=session.device_serial,
                          expected_candidate_sha256=session.candidate_sha256)
        return session, rendered, options

    @app.route('/api/deploy', methods=['POST'])
    @_candidate_operation
    def deploy_candidate():
        submitted = False
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
            serial = payload['artifact']['decision_document']['design_approval']['context']['target_serial']
            context = payload['artifact']['decision_document']['design_approval']['context']
            options = replace(options, expected_serial=serial,
                expected_baseline_sha256=context['baseline_sha256'], baseline_format=context['baseline_format'])
            submitted = True
            result = deployer_factory(options).deploy(rendered)
            decision_document = payload['artifact']['decision_document']
            validation_feedback = deployment_validation_feedback(rendered, decision_document, result.validation)
            if validation_feedback and validation_feedback.get('message'):
                validation_feedback['message'] = _public_deployment_error(validation_feedback['message'], 'Candidate validation failed')
            succeeded = (
                result.failure_message is None
                and result.failed_command_index is None
                and result.validation.status == 'SUCCESS'
                and result.validation.device_serial == serial
                and bool(result.validation.candidate_sha256)
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
                    device_serial=result.validation.device_serial,
                    candidate_sha256=result.validation.candidate_sha256,
                )
            return jsonify({
                'success': succeeded,
                'error': None if succeeded else _public_deployment_error(result.failure_message, 'Candidate preparation failed'),
                'result': _public_deployment_result(result),
                'validation_feedback': validation_feedback,
                'deployment_session_id': deployment_session_id,
                'candidate_validated': succeeded,
                'recovery': _recovery('VALIDATED' if succeeded else ('VALIDATION_FAILED' if result.commands_succeeded == result.commands_attempted and result.commands_attempted else result.recovery_state), result=result, artifact_id=artifact_id),
            }), (200 if succeeded else 502)
        except (ValueError, KeyError, TypeError):
            _LOGGER.info('Deployment request rejected due to invalid payload or state')
            return jsonify({'success': False, 'error': 'Invalid deployment request', 'recovery': _recovery('OUTCOME_UNKNOWN' if submitted else 'REJECTED_BEFORE_WRITES')}), 400
        except Exception:
            _LOGGER.info('Candidate preparation outcome unknown')
            return jsonify({'success': False, 'error': 'Candidate preparation outcome unknown', 'recovery': _recovery('OUTCOME_UNKNOWN')}), 502

    @app.route('/api/inspect-candidate', methods=['POST'])
    @_candidate_operation
    def inspect_candidate():
        payload = request.get_json(silent=True) or {}
        try:
            _request_artifact(payload)
            context = payload['artifact']['decision_document']['design_approval']['context']
            options = replace(_deployment_options(payload), expected_serial=context['target_serial'],
                expected_baseline_sha256=context['baseline_sha256'], baseline_format=context['baseline_format'])
            result = deployer_factory(options).inspect()
            return jsonify({'success': True, 'inspection': asdict(result),
                            'recovery': _recovery(result.state, artifact_id=payload['artifact']['artifact_id'])})
        except Exception:
            return jsonify({'success': False, 'error': 'Candidate inspection unavailable; renew evidence and review or reconcile with the operator.',
                            'recovery': _recovery('OUTCOME_UNKNOWN')}), 400

    @app.route('/api/validate-candidate', methods=['POST'])
    @_candidate_operation
    def validate_candidate():
        try:
            payload = request.get_json(silent=True) or {}
            session, rendered, options = _require_deployment_session(payload)
            result = deployer_factory(replace(options, validate=True)).validate()
            decision_document = payload['artifact']['decision_document']
            validation_feedback = deployment_validation_feedback(rendered, decision_document, result)
            if validation_feedback and validation_feedback.get('message'):
                validation_feedback['message'] = _public_deployment_error(validation_feedback['message'], 'Candidate validation failed')
            valid = (result.status == 'SUCCESS' and result.device_serial == session.device_serial
                     and result.candidate_sha256 == session.candidate_sha256)
            if valid:
                deployment_sessions[session.session_id] = replace(
                    session,
                    validation_job_id=result.job_id,
                    validated_at=time.time(),
                )
            else:
                deployment_sessions.pop(session.session_id, None)
            return jsonify({
                'success': valid,
                'error': None if valid else 'Candidate identity or state verification failed',
                'result': _public_deployment_result(result),
                'deployment_session_id': session.session_id if valid else None,
                'validation_feedback': validation_feedback,
                'recovery': _recovery('VALIDATED' if valid else 'CANDIDATE_CHANGED'),
            }), (200 if valid else 502)
        except ArtifactEligibilityError as exc:
            deployment_sessions.pop(payload.get('deployment_session_id'), None)
            return jsonify({'success': False, 'error': str(exc), 'error_code': 'artifact_ineligible'}), 400
        except _CandidateSessionError as exc:
            return jsonify({
                'success': False,
                'error': _CandidateSessionError.MESSAGES[exc.code],
                'error_code': exc.code,
                'recovery': _recovery('SESSION_LOST'),
            }), 400
        except Exception:
            deployment_sessions.pop(payload.get('deployment_session_id'), None)
            _LOGGER.info('Invalid candidate validation request')
            return jsonify({'success': False, 'error': 'Candidate validation requires recovery', 'recovery': _recovery('OUTCOME_UNKNOWN')}), 400

    @app.route('/api/commit', methods=['POST'])
    @_candidate_operation
    def commit_candidate():
        try:
            payload = request.get_json(silent=True) or {}
            session, _rendered, options = _require_deployment_session(payload)
            result = deployer_factory(replace(options, validate=False)).commit()
            deployment_sessions.pop(session.session_id, None)
            return jsonify({
                'success': result.status == 'SUCCESS',
                'error': None if result.status == 'SUCCESS' else 'Candidate commit outcome requires inspection',
                'recovery': _recovery('COMMITTED' if result.status == 'SUCCESS' else 'OUTCOME_UNKNOWN' if result.status in {'UNKNOWN', 'TIMEOUT'} else 'RECONCILIATION_REQUIRED'),
                'result': _public_deployment_result(result),
                'deployment_session_id': None,
            }), (200 if result.status == 'SUCCESS' else 502)
        except ArtifactEligibilityError as exc:
            deployment_sessions.pop(payload.get('deployment_session_id'), None)
            return jsonify({'success': False, 'error': str(exc), 'error_code': 'artifact_ineligible'}), 400
        except _CandidateSessionError as exc:
            return jsonify({
                'success': False,
                'error': _CandidateSessionError.MESSAGES[exc.code],
                'error_code': exc.code,
                'recovery': _recovery('SESSION_LOST'),
            }), 400
        except Exception:
            deployment_sessions.pop(payload.get('deployment_session_id'), None)
            _LOGGER.info("Invalid candidate commit request")
            return jsonify({'success': False, 'error': 'Candidate commit outcome unknown', 'recovery': _recovery('OUTCOME_UNKNOWN')}), 400
