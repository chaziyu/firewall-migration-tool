from __future__ import annotations

from ..models import CheckPointResponse
from ..rulebase import flatten_rulebase
from .common import record


def extract_policy_records(response: CheckPointResponse):
    payload = response.data.get("rulebase", [])
    if not isinstance(payload, list):
        return []
    return [record(response, value, index) for index, (value, _section) in enumerate(flatten_rulebase(payload), 1)]
