"""Proposals stay pending until bound to an explicit design approval."""


def build_decision_set(requirements, confirmed=False):
    return [{**row, "mode": "REQUIRED", "review_state": "CONFIRMED" if confirmed and row.get("value") is not None else "PENDING"}
            for row in requirements["decisions"]]
