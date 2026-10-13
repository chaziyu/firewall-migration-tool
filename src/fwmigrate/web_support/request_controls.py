"""Application-owned, process-local controls for API processing."""

from __future__ import annotations

import math
import threading
import time
from collections import OrderedDict

from flask import g, jsonify, request


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
