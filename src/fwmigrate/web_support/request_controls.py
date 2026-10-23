"""Application-owned, process-local controls for API processing."""

from __future__ import annotations

import math
import threading
import time
from collections import OrderedDict
from functools import wraps
from urllib.parse import urlsplit

from flask import current_app, g, jsonify, make_response, request
from werkzeug.wsgi import ClosingIterator
from werkzeug.wsgi import get_host


def live_device_access_allowed(app):
    return (
        app.config['WEB_MODE'] == 'local'
        and request.remote_addr in {'127.0.0.1', '::1'}
        and urlsplit(request.host_url).hostname in {'localhost', '127.0.0.1', '::1'}
    )


class IPRateLimiter:
    """Fixed windows with bounded tracking; saturation fails closed for new IPs."""

    def __init__(self, limit=30, window=60, max_entries=4096, *, clock=time.monotonic):
        if limit < 1 or window <= 0 or max_entries < 1:
            raise ValueError('Request control limits must be positive')
        self.limit = limit
        self.window = window
        self.max_entries = max_entries
        self.clock = clock
        self.entries = OrderedDict()
        self.lock = threading.Lock()

    def retry_after(self, ip):
        """Consume a request, returning zero if allowed or seconds until retry."""
        with self.lock:
            now = self.clock()
            while self.entries:
                _, (started, _) = next(iter(self.entries.items()))
                if now - started < self.window:
                    break
                self.entries.popitem(last=False)
            entry = self.entries.get(ip)
            if entry is None:
                if len(self.entries) >= self.max_entries:
                    started, _ = next(iter(self.entries.values()))
                    return max(1, math.ceil(started + self.window - now))
                self.entries[ip] = (now, 1)
                return 0
            started, count = entry
            if count >= self.limit:
                return max(1, math.ceil(started + self.window - now))
            self.entries[ip] = (started, count + 1)
            return 0


def register_request_controls(app):
    limiter = IPRateLimiter(limit=app.config['API_RATE_LIMIT_PER_MINUTE'])
    maximum = app.config['MAX_CONCURRENT_REQUESTS']
    if maximum < 1:
        raise ValueError('Request control limits must be positive')
    semaphore = threading.BoundedSemaphore(maximum)
    app.extensions['request_controls'] = {'rate_limiter': limiter, 'semaphore': semaphore}
    export_maximum = app.config['MAX_CONCURRENT_EXPORTS']
    if export_maximum < 1:
        raise ValueError('Export concurrency must be positive')
    app.extensions['request_controls']['exports'] = threading.BoundedSemaphore(export_maximum)

    @app.before_request
    def protect_browser_requests():
        # Exact hostname checks also cover Flask 3.0 and IPv6 loopback.
        hostname = urlsplit('//' + get_host(request.environ)).hostname
        if hostname not in app.config['ALLOWED_HOSTS']:
            return jsonify({'success': False, 'error': 'Host is not allowed'}), 400
        if not request.path.startswith('/api/') or request.method in {'GET', 'HEAD', 'OPTIONS'}:
            return None
        origins = {request.host_url.rstrip('/')}
        if app.config['WEB_MODE'] == 'local':
            origins.update({'http://127.0.0.1:5173', 'http://localhost:5173'})
        origin = request.headers.get('Origin')
        if (origin is not None and origin not in origins) or (
            origin is None and request.headers.get('Sec-Fetch-Site') == 'cross-site'
        ):
            return jsonify({'success': False, 'error': 'Cross-origin API requests are not allowed'}), 403
        return None

    def rejected(code, message, retry_after):
        response = jsonify({'success': False, 'error': message, 'error_code': code})
        response.status_code = 429
        response.headers['Retry-After'] = str(retry_after)
        return response

    @app.before_request
    def control_api_processing():
        if request.method != 'POST' or not request.path.startswith('/api/'):
            return None
        retry_after = limiter.retry_after(request.remote_addr or '')
        if retry_after:
            return rejected('rate_limit_exceeded', 'API request rate limit exceeded', retry_after)
        if not semaphore.acquire(blocking=False):
            return rejected('server_busy', 'Server is busy; retry later', 1)
        g.api_processing_permit = True
        return None

    @app.teardown_request
    def release_api_processing(_error):
        if g.pop('api_processing_permit', False):
            semaphore.release()


def limit_export_response(view):
    """Bound workbook generation AND retained response buffers until WSGI close."""
    @wraps(view)
    def limited(*args, **kwargs):
        semaphore = current_app.extensions['request_controls']['exports']
        if not semaphore.acquire(blocking=False):
            response = jsonify({'success': False, 'error': 'Workbook export is busy; retry later',
                                'error_code': 'export_busy'})
            response.status_code = 429
            response.headers['Retry-After'] = '1'
            return response
        released = False
        lock = threading.Lock()

        def release():
            nonlocal released
            with lock:
                if not released:
                    released = True
                    semaphore.release()

        try:
            response = make_response(view(*args, **kwargs))
            if response.status_code >= 400:
                release()
            else:
                # send_file uses direct_passthrough, bypassing Response.call_on_close.
                original = response.response

                def finish():
                    try:
                        close = getattr(original, 'close', None)
                        if close is not None:
                            close()
                    finally:
                        release()

                def stream():
                    try:
                        yield from original
                    finally:
                        finish()

                # Also handle close before the generator is first advanced.
                response.response = ClosingIterator(stream(), finish)
            return response
        except BaseException:
            release()
            raise
    return limited
