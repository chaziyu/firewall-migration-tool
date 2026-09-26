from fwmigrate.conversion.fortigate_to_palo_alto.ai.cache import ProposalCache


def test_proposal_cache_expires_and_is_bounded():
    now = [0.0]
    cache = ProposalCache(ttl_seconds=15, max_proposals=1, clock=lambda: now[0])
    first = type("Proposal", (), {"proposal_id": "first"})()
    second = type("Proposal", (), {"proposal_id": "second"})()
    cache.put_many(("groq", "m", "questions", "d1", "p1"), (first,))
    assert cache.get("first") is first
    cache.put_many(("groq", "m", "questions", "d2", "p1"), (second,))
    assert cache.get("first") is None and cache.get("second") is second
    now[0] = 16
    assert cache.get("second") is None
