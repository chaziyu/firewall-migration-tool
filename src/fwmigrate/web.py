import os
import sys
import io
import secrets
import logging

from pydantic import ValidationError
from flask import Flask, Request as FlaskRequest, jsonify, request

from fwmigrate.collection.builtin import register_builtin_collectors
from fwmigrate.collection.snapshot import MAX_BYTES
from fwmigrate.conversion.builtin import register_builtin_migration_planners
from fwmigrate.source_reporting import source_reporters
from fwmigrate.source_reporting.builtin import register_builtin_source_reporters
from fwmigrate.web_api.deployment import DeploymentCoordinator, register_deployment_routes
from fwmigrate.web_api.migration import register_migration_routes
from fwmigrate.web_api.source import register_source_routes
from fwmigrate.web_support.frontend import register_frontend_routes

register_builtin_source_reporters()
register_builtin_migration_planners()

_LOGGER = logging.getLogger(__name__)


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
    deployment_coordinator = DeploymentCoordinator()

    @app.errorhandler(ValueError)
    def _invalid_request(error):
        return jsonify({'success': False, 'error': str(error)}), 400

    @app.errorhandler(ValidationError)
    def _invalid_model(_error):
        return jsonify({'success': False, 'error': 'Invalid configuration fields'}), 400

    register_frontend_routes(app)
    register_source_routes(app)
    register_migration_routes(app, signing_key)
    register_deployment_routes(app, signing_key, deployment_coordinator)

    return app
