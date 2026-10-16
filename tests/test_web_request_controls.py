from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest

from fwmigrate.web import create_app
from fwmigrate.web_support.request_controls import IPRateLimiter


def test_shared_bucket_uses_remote_addr_and_ignores_forwarded_headers():
    app = create_app({'TESTING': True, 'API_RATE_LIMIT_PER_MINUTE': 2})
    client = app.test_client()
    assert client.post('/api/preview').status_code == 400
    assert client.post('/api/extract/excel').status_code == 400
    denied = client.post('/api/migrate', headers={'X-Forwarded-For': '192.0.2.99'})
    assert denied.status_code == 429
    assert denied.json['error_code'] == 'rate_limit_exceeded'
    assert 1 <= int(denied.headers['Retry-After']) <= 60
    assert denied.headers['Cache-Control'] == 'no-store, private'
    assert client.get('/api/vendors').status_code == 200
    assert client.get('/assets/missing.js').status_code != 429
    assert client.post('/api/preview', environ_overrides={'REMOTE_ADDR': '192.0.2.2'}).status_code == 400
    assert create_app({'TESTING': True}).test_client().post('/api/preview').status_code == 400


def test_trusted_proxy_uses_separate_client_buckets_and_rightmost_hop():
    client = create_app({'TESTING': True, 'TRUSTED_PROXY_FOR': 1,
                         'API_RATE_LIMIT_PER_MINUTE': 1}).test_client()
    assert client.post('/api/preview', headers={'X-Forwarded-For': '192.0.2.1'}).status_code == 400
    assert client.post('/api/preview', headers={'X-Forwarded-For': '192.0.2.2'}).status_code == 400
    denied = client.post('/api/preview', headers={'X-Forwarded-For': '198.51.100.99, 192.0.2.1'})
    assert denied.status_code == 429
    assert denied.json['error_code'] == 'rate_limit_exceeded'


@pytest.mark.parametrize('setting', ['TRUSTED_PROXY_FOR', 'TRUSTED_PROXY_PROTO'])
@pytest.mark.parametrize('value', [-1, '-1', True, 1.5, '1.5', None, '', 'one'])
def test_invalid_proxy_hops_fail_at_startup(setting, value):
    with pytest.raises(ValueError, match='nonnegative integer'):
        create_app({'TESTING': True, setting: value})


@pytest.mark.parametrize('setting', ['TRUSTED_PROXY_FOR', 'TRUSTED_PROXY_PROTO'])
def test_proxy_hops_can_be_configured_from_environment(setting, monkeypatch):
    monkeypatch.setenv('FWMIGRATE_' + setting, '1')
    assert create_app({'TESTING': True}).config[setting] == 1


def test_default_limit_and_window_expiry():
    now = [0.0]
    limiter = IPRateLimiter(clock=lambda: now[0])
    assert all(limiter.retry_after('one') == 0 for _ in range(30))
    assert limiter.retry_after('one') == 60
    assert limiter.retry_after('two') == 0
    now[0] = 59.1
    assert limiter.retry_after('one') == 1
    now[0] = 60
    assert limiter.retry_after('one') == 0
    assert len(limiter.entries) == 1


def test_tracking_saturation_does_not_evict_active_limits():
    now = [0.0]
    limiter = IPRateLimiter(limit=1, max_entries=2, clock=lambda: now[0])
    assert limiter.retry_after('one') == 0
    now[0] = 10
    assert limiter.retry_after('two') == 0
    for number in range(1000):
        assert limiter.retry_after(f'new-{number}') == 50
    assert len(limiter.entries) == 2
    assert limiter.retry_after('one') == 50
    now[0] = 60
    assert limiter.retry_after('three') == 0
    assert set(limiter.entries) == {'two', 'three'}


def test_rate_limiter_is_thread_safe():
    limiter = IPRateLimiter(limit=30)
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda _: limiter.retry_after('one'), range(100)))
    assert results.count(0) == 30
    assert len(limiter.entries) == 1


@pytest.mark.parametrize('failure', [None, ValueError, RuntimeError])
def test_concurrent_processing_and_recovery(failure):
    app = create_app({'TESTING': True})
    entered = [Event(), Event()]
    release = Event()

    @app.post('/api/block/<int:number>')
    def block(number):
        entered[number].set()
        assert release.wait(5)
        if failure:
            raise failure('SYNTHETIC_PRIVATE_SECRET')
        return {'success': True}

    with ThreadPoolExecutor(max_workers=6) as pool:
        active = [pool.submit(lambda n=n: app.test_client().post(f'/api/block/{n}')) for n in range(2)]
        try:
            assert all(event.wait(5) for event in entered)
            rejected = [pool.submit(lambda: app.test_client().post('/api/preview')) for _ in range(4)]
            for pending in rejected:
                response = pending.result(timeout=2)
                assert response.status_code == 429
                assert response.json['error_code'] == 'server_busy'
                assert response.headers['Retry-After'] == '1'
            assert app.test_client().get('/api/vendors').status_code == 200
        finally:
            release.set()
        for pending in active:
            assert pending.result(timeout=5).status_code == (200 if failure is None else 400 if failure is ValueError else 500)
    # A rejected request must never release a permit it did not acquire.
    semaphore = app.extensions['request_controls']['semaphore']
    assert semaphore.acquire(blocking=False)
    assert semaphore.acquire(blocking=False)
    assert not semaphore.acquire(blocking=False)
    semaphore.release()
    semaphore.release()
    for _ in range(3):
        assert app.test_client().post('/api/preview').status_code == 400


@pytest.mark.parametrize('setting', ['API_RATE_LIMIT_PER_MINUTE', 'MAX_CONCURRENT_REQUESTS'])
def test_invalid_controls_fail_at_startup(setting):
    with pytest.raises(ValueError, match='positive'):
        create_app({'TESTING': True, setting: 0})
