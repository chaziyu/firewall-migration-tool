"""HTTP endpoints and process-local coordination for PAN-OS candidate deployment."""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import asdict, replace
from functools import wraps

from flask import jsonify, request

from fwmigrate.conversion.fortigate_to_palo_alto.application import deployment_validation_feedback
from fwmigrate.deployment import PANDeploymentOptions, PANDeploymentSession
from fwmigrate.web_support.artifact_signing import verify_artifact
from fwmigrate.web_support.reporting import _parse_bool

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
        return verify_artifact(payload.get('artifact'), signing_key)

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
            except ValueError:
                _LOGGER.warning('Invalid deployment request payload.', exc_info=True)
                return jsonify({'success': False, 'error': 'Invalid deployment request.'}), 400
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
            result = deployer_factory(options).deploy(rendered)
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
        except (ValueError, KeyError, TypeError):
            _LOGGER.exception('Deployment request rejected due to invalid payload or state')
            return jsonify({'success': False, 'error': 'Invalid deployment request'}), 400

    @app.route('/api/validate-candidate', methods=['POST'])
    @_candidate_operation
    def validate_candidate():
        try:
            payload = request.get_json(silent=True) or {}
            session, rendered, options = _require_deployment_session(payload)
            result = deployer_factory(replace(options, validate=True)).validate()
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
            result = deployer_factory(replace(options, validate=False)).commit()
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
