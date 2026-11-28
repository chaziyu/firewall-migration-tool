import os
import io
import secrets
import tempfile
import uuid
import logging

from pydantic import ValidationError
from flask import Flask, Request as FlaskRequest, current_app, jsonify, request
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from fwmigrate.web_support.analysis_cache import AnalysisCache, SealedSourceStore, cache_settings_from_app
from fwmigrate.web_support.request_controls import register_request_controls
from fwmigrate.web_support.request_source import SourceCacheExpiredError
from fwmigrate.web_support.public_errors import safe_validation_message

from fwmigrate.collection.builtin import register_builtin_collectors
from fwmigrate.collection.snapshot import MAX_BYTES
from fwmigrate.conversion import migration_planners
from fwmigrate.conversion.builtin import register_builtin_migration_planners, register_builtin_migration_workflows
from fwmigrate.source_reporting import source_reporters as source_reporters
from fwmigrate.source_reporting.builtin import register_builtin_source_reporters
from fwmigrate.web_api.migration import register_migration_routes
from fwmigrate.web_api.migration_pairs import register_migration_pair_routes
from fwmigrate.web_api.fortigate_to_juniper_srx import register_fortigate_to_juniper_srx_routes
from fwmigrate.web_api.fortigate_to_cisco_asa import register_fortigate_to_cisco_asa_routes
from fwmigrate.web_api.fortigate_to_checkpoint import register_fortigate_to_checkpoint_routes
from fwmigrate.web_api.palo_alto_to_fortigate import register_palo_alto_to_fortigate_routes
from fwmigrate.web_api.palo_alto_to_juniper_srx import register_palo_alto_to_juniper_srx_routes
from fwmigrate.web_api.palo_alto_to_cisco_asa import register_palo_alto_to_cisco_asa_routes
from fwmigrate.web_api.palo_alto_to_checkpoint import register_palo_alto_to_checkpoint_routes
from fwmigrate.web_api.palo_alto_to_cisco_ftd import register_palo_alto_to_cisco_ftd_routes
from fwmigrate.web_api.source import register_source_routes
from fwmigrate.web_api.diagnostics import register_diagnostic_routes
from fwmigrate.web_api.simulators import register_simulator_routes
from fwmigrate.web_api.tsf import register_tsf_routes
from fwmigrate.web_api.update import register_update_routes
from fwmigrate.web_api.chat import register_chat_routes
from fwmigrate.web_support.frontend import register_frontend_routes

register_builtin_collectors()
register_builtin_source_reporters()
register_builtin_migration_planners()
register_builtin_migration_workflows()

_LOGGER = logging.getLogger(__name__)


def classify_target_object_reuse(*args, **kwargs):
    """Defer importing FortiGate-to-PAN-OS reuse classification until first use."""
    from fwmigrate.conversion.fortigate_to_palo_alto.application import (
        classify_target_object_reuse as _classify_target_object_reuse,
    )

    return _classify_target_object_reuse(*args, **kwargs)


class _MemoryOnlyUploadRequest(FlaskRequest):
    """Keep bounded customer uploads in memory; spool TSF archives to disk."""

    max_form_memory_size = MAX_BYTES + 1_000_000

    @property
    def max_content_length(self):
        if self.path == '/api/tsf/upload':
            tsf_max_mb = int(current_app.config.get('TSF_MAX_ZIP_MB', 500))
            return tsf_max_mb * 1024 * 1024 + 5_000_000
        return super().max_content_length

    def _get_file_stream(
        self,
        total_content_length,
        content_type,
        filename=None,
        content_length=None,
    ):
        if self.path == '/api/tsf/upload':
            return tempfile.SpooledTemporaryFile(max_size=16 * 1024 * 1024)
        return io.BytesIO()


class _LocalFlask(Flask):
    """Route local loopback app.run() calls through the dual-stack HTTP/1.1 server."""

    def run(self, host=None, port=None, debug=None, load_dotenv=True, **options):
        resolved_host = host or '127.0.0.1'
        resolved_port = int(port or 5000)
        if not debug and not options and resolved_host in {'127.0.0.1', '::1', 'localhost'}:
            from fwmigrate.web_support.local_server import run_local_server

            run_local_server(self, host=resolved_host, port=resolved_port)
            return
        super().run(host=host, port=port, debug=debug, load_dotenv=load_dotenv, **options)


def create_app(test_config=None):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    frontend_dist = os.path.join(os.path.dirname(base_dir), 'frontend', 'dist')

    app = _LocalFlask(__name__, static_folder=None)
    app.request_class = _MemoryOnlyUploadRequest

    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

    if test_config:
        app.config.update(test_config)
    app.config.setdefault('FRONTEND_DIST_DIR', os.environ.get('FWMIGRATE_FRONTEND_DIST_DIR') or frontend_dist)
    app.config.setdefault('WEB_MODE', os.environ.get('FWMIGRATE_WEB_MODE', 'public'))
    if app.config['WEB_MODE'] not in {'public', 'local'}:
        raise ValueError('WEB_MODE must be public or local')
    for setting in ('TRUSTED_PROXY_FOR', 'TRUSTED_PROXY_PROTO'):
        value = app.config.get(setting, os.environ.get('FWMIGRATE_' + setting, '0'))
        if not ((type(value) is int and value >= 0) or
                (isinstance(value, str) and value.isascii() and value.isdecimal())):
            raise ValueError(f'{setting} must be a nonnegative integer')
        app.config[setting] = int(value)
    if app.config['TRUSTED_PROXY_FOR'] or app.config['TRUSTED_PROXY_PROTO']:
        if app.config['WEB_MODE'] == 'local':
            raise ValueError('Proxy trust is not supported in local mode')
        app.wsgi_app = ProxyFix(
            app.wsgi_app, x_for=app.config['TRUSTED_PROXY_FOR'],
            x_proto=app.config['TRUSTED_PROXY_PROTO'], x_host=0, x_port=0, x_prefix=0,
        )
    if not app.config.get('ALLOWED_HOSTS'):
        hosts = os.environ.get('FWMIGRATE_ALLOWED_HOSTS', '')
        app.config['ALLOWED_HOSTS'] = [host.strip().lower() for host in hosts.split(',') if host.strip()] or [
            'localhost', '127.0.0.1', '::1',
        ]
        render_host = os.environ.get('RENDER_EXTERNAL_HOSTNAME')
        if render_host:
            app.config['ALLOWED_HOSTS'].append(render_host.strip().lower())
    is_local_mode = app.config['WEB_MODE'] == 'local'
    app.config.setdefault(
        'ALLOW_DEV_ORIGINS',
        str(os.environ.get('FWMIGRATE_ALLOW_DEV_ORIGIN', '')).strip().lower() in {'1', 'true', 'yes', 'on'},
    )
    app.config.setdefault(
        'API_RATE_LIMIT_PER_MINUTE',
        int(os.environ.get('FWMIGRATE_API_RATE_LIMIT_PER_MINUTE', '300' if is_local_mode else '30')),
    )
    app.config.setdefault(
        'MAX_CONCURRENT_REQUESTS',
        int(os.environ.get('FWMIGRATE_MAX_CONCURRENT_REQUESTS', '6' if is_local_mode else '2')),
    )
    app.config.setdefault(
        'MAX_CONCURRENT_EXPORTS',
        int(os.environ.get('FWMIGRATE_MAX_CONCURRENT_EXPORTS', '3' if is_local_mode else '2')),
    )
    app.config.setdefault('MAX_CONTENT_LENGTH', 2 * MAX_BYTES + 5_000_000)
    default_tsf_max_mb = '500' if app.config['WEB_MODE'] == 'local' else '100'
    app.config.setdefault('TSF_MAX_ZIP_MB', int(os.environ.get('FWMIGRATE_TSF_MAX_ZIP_MB', default_tsf_max_mb)))
    app.config.setdefault('TSF_SESSION_TTL_HOURS', int(os.environ.get('FWMIGRATE_TSF_SESSION_TTL_HOURS', '6')))
    if os.environ.get('TSF_SESSIONS_DIR'):
        app.config.setdefault('TSF_SESSIONS_DIR', os.environ.get('TSF_SESSIONS_DIR'))
    register_request_controls(app)
    cache_max, cache_ttl = cache_settings_from_app(app)
    app.extensions['analysis_cache'] = AnalysisCache(max_entries=cache_max, ttl_seconds=cache_ttl)
    app.extensions['sealed_source_store'] = SealedSourceStore(max_entries=cache_max, ttl_seconds=cache_ttl)

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
    if require_web_auth and not web_password:
        raise RuntimeError(
            'Hosted web authentication is required but FWMIGRATE_WEB_PASSWORD is not configured'
        )

    if web_password:
        expected_password = str(web_password)

        @app.before_request
        def _authenticate_hosted_web():
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
        if request.is_secure:
            response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000')
        if request.path.startswith('/api/'):
            response.headers['Cache-Control'] = 'no-store, private'
            response.headers['Pragma'] = 'no-cache'
        return response

    @app.errorhandler(SourceCacheExpiredError)
    def _source_cache_expired(error):
        return jsonify({
            'success': False,
            'error': safe_validation_message(error, 'Cached source expired; please re-send configuration.'),
            'error_code': 'source_expired',
        }), 410

    @app.errorhandler(ValueError)
    def _invalid_request(error):
        return jsonify({'success': False, 'error': safe_validation_message(error, 'Invalid request')}), 400

    @app.errorhandler(ValidationError)
    def _invalid_model(_error):
        return jsonify({'success': False, 'error': 'Invalid configuration fields'}), 400

    @app.errorhandler(Exception)
    def _unexpected_error(error):
        if isinstance(error, HTTPException):
            return error
        _LOGGER.error('Request processing failed')
        return jsonify({'success': False, 'error': 'Request processing failed', 'error_code': 'internal_error'}), 500

    register_frontend_routes(app)
    register_source_routes(app, collector_registry=app.config.get('SOURCE_COLLECTOR_REGISTRY'))
    register_diagnostic_routes(app)
    register_simulator_routes(app)
    register_tsf_routes(app)
    register_update_routes(app)
    register_chat_routes(app)
    register_migration_pair_routes(app)
    register_fortigate_to_juniper_srx_routes(app)
    register_fortigate_to_cisco_asa_routes(app)
    register_fortigate_to_checkpoint_routes(app)
    register_palo_alto_to_fortigate_routes(app)
    register_palo_alto_to_juniper_srx_routes(app)
    register_palo_alto_to_cisco_asa_routes(app)
    register_palo_alto_to_checkpoint_routes(app)
    register_palo_alto_to_cisco_ftd_routes(app)
    register_migration_routes(
        app,
        migration_planner_registry=migration_planners,
        object_reuse_classifier=classify_target_object_reuse,
        uuid_factory=uuid.uuid4,
    )

    return app
