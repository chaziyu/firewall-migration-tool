"""Small, process-local cache for short-lived advisory proposals."""

from dataclasses import dataclass
import threading
import time


@dataclass(frozen=True, slots=True)
class CachedAIProposal:
    proposal: object
    created_at: float
    expires_at: float


class ProposalCache:
    def __init__(self, *, ttl_seconds=900, max_proposals=128, clock=time.monotonic):
        self._ttl = ttl_seconds
        self._max = max_proposals
        self._clock = clock
        self._items = {}
        self._keys = {}
        self._lock = threading.Lock()

    def _cleanup(self, now):
        for proposal_id, entry in list(self._items.items()):
            if entry.expires_at <= now:
                self._items.pop(proposal_id, None)
        for key, proposal_ids in list(self._keys.items()):
            kept = [proposal_id for proposal_id in proposal_ids if proposal_id in self._items]
            if kept:
                self._keys[key] = kept
            else:
                self._keys.pop(key, None)

    def get_many(self, key):
        with self._lock:
            self._cleanup(self._clock())
            return tuple(self._items[item].proposal for item in self._keys.get(key, ()) if item in self._items)

    def get(self, proposal_id):
        with self._lock:
            self._cleanup(self._clock())
            entry = self._items.get(str(proposal_id or ""))
            return entry.proposal if entry else None

    def put_many(self, key, proposals):
        now = self._clock()
        with self._lock:
            self._cleanup(now)
            while len(self._items) + len(proposals) > self._max and self._items:
                oldest = min(self._items, key=lambda item: self._items[item].created_at)
                self._items.pop(oldest, None)
            ids = []
            for proposal in proposals:
                self._items[proposal.proposal_id] = CachedAIProposal(proposal, now, now + self._ttl)
                ids.append(proposal.proposal_id)
            self._keys[key] = ids


proposal_cache = ProposalCache()
