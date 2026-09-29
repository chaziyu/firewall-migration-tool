"""Report proposal quality metrics from sanitized AI audit JSONL."""

import argparse
import json
from collections import Counter
from pathlib import Path


def _metric(numerator, denominator):
    return {
        "rate": numerator / denominator if denominator else None,
        "numerator": numerator,
        "denominator": denominator,
    }


def evaluate_rows(rows):
    """Evaluate audit rows, including optional labels added to a curated dataset.

    Curated rows may include ``expected_engineer_decision`` (a value string or
    ``{"action": ..., "value": ...}``), ``acceptable_alternatives`` (strings),
    ``expected_abstention`` and ``expected_conflict`` booleans.
    """
    proposals = [row for row in rows if isinstance(row.get("proposal"), dict)]
    exact = acceptable = exact_total = acceptable_total = 0
    conflict_hits = expected_conflicts = 0
    valid = unsafe = use_existing = escalated = 0
    reviewed = modified = 0

    for row in proposals:
        proposal = row["proposal"]
        action = proposal.get("action")
        value = proposal.get("proposed_value")
        status = row.get("validation_result", {}).get("status")
        if action == "USE_EXISTING":
            use_existing += 1
            valid += status == "VALID"
            unsafe += status != "VALID"
        escalated += row.get("escalated_from") == "qwen_local"

        expected = row.get("expected_engineer_decision")
        if isinstance(expected, str):
            expected_value, expected_action = expected, "USE_EXISTING"
        elif isinstance(expected, dict):
            expected_value = expected.get("value")
            expected_action = expected.get("action", "USE_EXISTING")
        else:
            expected_value = expected_action = None
        if expected_action is not None:
            exact_total += 1
            is_exact = action == expected_action and (
                expected_action != "USE_EXISTING" or value == expected_value
            )
            exact += is_exact
            if expected_action == "USE_EXISTING" and isinstance(expected_value, str):
                acceptable_total += 1
                alternatives = row.get("acceptable_alternatives", [])
                acceptable += value == expected_value or (
                    isinstance(alternatives, list) and value in alternatives
                )

        expected_conflict = row.get("expected_conflict")
        if expected_conflict is True:
            expected_conflicts += 1
            conflict_hits += status == "CONFLICT"

        review_action = row.get("engineer_action")
        if review_action in {"APPROVED", "MODIFIED", "REJECTED", "UNRESOLVED"}:
            reviewed += 1
            modified += review_action == "MODIFIED"

    # Ignore unlabeled rows when calculating abstention precision.
    labeled_abstention_rows = [
        row for row in proposals if isinstance(row.get("expected_abstention"), bool)
    ]
    predicted_abstentions = sum(
        row.get("proposal", {}).get("action") == "NO_SAFE_PROPOSAL"
        for row in labeled_abstention_rows
    )
    true_abstentions = sum(
        row.get("proposal", {}).get("action") == "NO_SAFE_PROPOSAL"
        for row in labeled_abstention_rows
        if row.get("expected_abstention") is True
    )
    return {
        "provider_failures": dict(Counter(row["failure_category"] for row in rows
                                          if row.get("event") == "AI_REQUEST_FAILED")),
        "valid_proposal_rate": _metric(valid, len(proposals)),
        "exact_engineer_agreement": _metric(exact, exact_total),
        "acceptable_agreement": _metric(acceptable, acceptable_total),
        "abstention_precision": _metric(true_abstentions, predicted_abstentions),
        "unsafe_proposal_rate": _metric(unsafe, use_existing),
        "conflict_detection": _metric(conflict_hits, expected_conflicts),
        "groq_escalation_rate": _metric(escalated, len(proposals)),
        "engineer_modification_rate": _metric(modified, reviewed),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("audit_jsonl", type=Path, help="sanitized audit or curated JSONL")
    args = parser.parse_args()
    with args.audit_jsonl.open(encoding="utf-8") as source:
        rows = [json.loads(line) for line in source if line.strip()]
    print(json.dumps(evaluate_rows(rows), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
