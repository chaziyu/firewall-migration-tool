from concurrent.futures import ThreadPoolExecutor
import io

from fwmigrate.web import create_app, source_reporters
from fwmigrate.web_support.analysis_cache import AnalysisCache, SealedSourceStore
from fwmigrate.web_support.request_source import analyze_request_source


def test_analysis_cache_lru_ttl_and_thread_safety():
    now = [100.0]
    cache = AnalysisCache(max_entries=2, ttl_seconds=10.0, clock=lambda: now[0])

    cache.put("fortigate", "d1", "a1")
    cache.put("fortigate", "d2", "a2")
    assert cache.get("fortigate", "d1") == "a1"  # refreshes d1 LRU order
    cache.put("fortigate", "d3", "a3")  # evicts d2
    assert cache.get("fortigate", "d2") is None
    assert cache.get("fortigate", "d1") == "a1"
    assert cache.get("fortigate", "d3") == "a3"

    now[0] = 111.0  # expires both
    assert len(cache) == 0
    assert cache.get("fortigate", "d1") is None

    calls = 0

    def loader():
        nonlocal calls
        calls += 1
        return {"parsed": True}

    assert cache.get_or_load("palo_alto", "dx", loader) == {"parsed": True}
    assert cache.get_or_load("palo_alto", "dx", loader) == {"parsed": True}
    assert calls == 1
    assert cache.evict("palo_alto", "dx") is True
    assert cache.evict("palo_alto", "dx") is False

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda idx: cache.put("fortigate", f"k{idx}", idx), range(50)))
    assert len(cache) <= 2


def test_sealed_source_store_compresses_and_obfuscates_plaintext():
    now = [0.0]
    store = SealedSourceStore(max_entries=2, ttl_seconds=60.0, clock=lambda: now[0])
    secret_text = "config system global\n    set hostname SECRET-FIREWALL-01\nend\n" * 4
    store.put_text("fortigate", "digest-1", secret_text)

    entry = store._cache._entries[("fortigate", "digest-1")].value
    assert b"SECRET-FIREWALL-01" not in entry.ciphertext
    assert store.get_text("fortigate", "digest-1") == secret_text


def test_analyze_request_source_uses_app_cache_only_when_requested(monkeypatch):
    app = create_app({"TESTING": True, "WEB_MODE": "local"})

    reporter = source_reporters.get("fortigate")
    original = reporter.analyze_source
    calls = []

    def counting_analyze(source, **options):
        calls.append(source)
        return original(source, **options)

    monkeypatch.setattr(reporter, "analyze_source", counting_analyze)
    sample = "config system global\n    set hostname FG-CACHE-TEST\nend\n"

    with app.test_request_context("/api/test", method="POST", data={"file": (io.BytesIO(sample.encode()), "fg.conf")}):
        first = analyze_request_source({}, "fortigate", use_cache=True)
    with app.test_request_context("/api/test", method="POST", data={"file": (io.BytesIO(sample.encode()), "fg.conf")}):
        second = analyze_request_source({}, "fortigate", use_cache=True)
    with app.test_request_context("/api/test", method="POST", data={"file": (io.BytesIO(sample.encode()), "fg.conf")}):
        third = analyze_request_source({}, "fortigate", use_cache=False)

    assert first.analysis is second.analysis
    assert third.analysis is not first.analysis
    assert len(calls) == 2
