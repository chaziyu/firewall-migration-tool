"""Report proposal quality and efficiency metrics from sanitized AI audit JSONL."""

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


def _metric(numerator, denominator):
    return {
        "rate": numerator / denominator if denominator else None,
        "numerator": numerator,
        "denominator": denominator,
    }


def _average(values):
    values = [value for value in values if isinstance(value, (int, float))]
    return {
        "average": sum(values) / len(values) if values else None,
        "count": len(values),
    }


def _candidate_bucket(value):
    if not isinstance(value, int):
        return "unknown"
    if value <= 2:
        return "0-2"
    if value <= 6:
        return "3-6"
    if value <= 12:
        return "7-12"
    return "13+"


def _group_summary(rows, key):
    grouped = defaultdict(list)
    for row in rows:
        grouped[str(key(row) or "unknown")].append(row)
    result = {}
    for name, group in sorted(grouped.items()):
        use_existing = [
            row for row in group
            if row.get("proposal", {}).get("action") == "USE_EXISTING"
        ]
        reviewed = [
            row for row in group
            if row.get("engineer_action") in {
                "APPROVED", "MODIFIED", "REJECTED", "UNRESOLVED"
            }
        ]
        result[name] = {
            "proposal_count": len(group),
            "valid_use_existing_rate": _metric(
                sum(
                    row.get("validation_result", {}).get("status") == "VALID"
                    for row in use_existing
                ),
                len(use_existing),
            ),
            "abstention_rate": _metric(
                sum(
                    row.get("proposal", {}).get("action") == "NO_SAFE_PROPOSAL"
                    for row in group
                ),
                len(group),
            ),
            "engineer_modification_rate": _metric(
                sum(row.get("engineer_action") == "MODIFIED" for row in reviewed),
                len(reviewed),
            ),
            "engineer_rejection_rate": _metric(
                sum(row.get("engineer_action") == "REJECTED" for row in reviewed),
                len(reviewed),
            ),
        }
    return result


def evaluate_rows(rows):
    """Evaluate audit rows, including optional labels added to a curated dataset.

    Curated rows may include expected_engineer_decision (a value string or
    {"action": ..., "value": ...}), acceptable_alternatives (strings),
    expected_abstention and expected_conflict booleans.

    Runtime audit rows may additionally include target_field, candidate_count,
    request_bytes, request_duration_ms and repair_pass. Missing optional fields
    are ignored rather than inferred.
    """
    proposals = [row for row in rows if isinstance(row.get("proposal"), dict)]
    exact = acceptable = exact_total = acceptable_total = 0
    conflict_hits = expected_conflicts = 0
    valid = unsafe = use_existing = escalated = 0
    reviewed = modified = rejected = 0

    for row in proposals:
        proposal = row["proposal"]
        action = proposal.get("action")
        value = proposal.get("proposed_value")
        status = row.get("validation_result", {}).get("status")
        if action == "USE_EXISTING":
            use_existing += 1
            valid += status == "VALID"
            unsafe += status != "VALID"
        escalated += bool(row.get("escalated_from"))

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
            rejected += review_action == "REJECTED"

    labeled_abstention_rows = [
        row for row in proposals if isinstance(row.get("expected_abstention"), bool)
    ]
    predicted_abstentions = sum(
        row.get("proposal", {}).get("action") == "NO_SAFE_PROPOSAL"
        for row in labeled_abstention_rows
    )
    true_abstention_predictions = sum(
        row.get("proposal", {}).get("action") == "NO_SAFE_PROPOSAL"
        for row in labeled_abstention_rows
        if row.get("expected_abstention") is True
    )
    expected_abstentions = sum(
        row.get("expected_abstention") is True for row in labeled_abstention_rows
    )

    return {
        "provider_failures": dict(Counter(
            row["failure_category"] for row in rows
            if row.get("event") == "AI_REQUEST_FAILED"
        )),
        "valid_proposal_rate": _metric(valid, len(proposals)),
        "exact_engineer_agreement": _metric(exact, exact_total),
        "acceptable_agreement": _metric(acceptable, acceptable_total),
        "abstention_precision": _metric(
            true_abstention_predictions, predicted_abstentions
        ),
        "abstention_recall": _metric(
            true_abstention_predictions, expected_abstentions
        ),
        "unsafe_proposal_rate": _metric(unsafe, use_existing),
        "conflict_detection": _metric(conflict_hits, expected_conflicts),
        "groq_escalation_rate": _metric(escalated, len(proposals)),
        "provider_fallback_rate": _metric(escalated, len(proposals)),
        "engineer_modification_rate": _metric(modified, reviewed),
        "engineer_rejection_rate": _metric(rejected, reviewed),
        "average_candidate_count": _average(
            row.get("candidate_count") for row in proposals
        ),
        "average_request_bytes": _average(
            row.get("request_bytes") for row in proposals
        ),
        "average_request_duration_ms": _average(
            row.get("request_duration_ms") for row in proposals
        ),
        "average_repair_pass": _average(
            row.get("repair_pass") for row in proposals
        ),
        "by_provider": _group_summary(proposals, lambda row: row.get("provider")),
        "by_model": _group_summary(proposals, lambda row: row.get("model")),
        "by_target_field": _group_summary(
            proposals, lambda row: row.get("target_field")
        ),
        "by_candidate_count": _group_summary(
            proposals, lambda row: _candidate_bucket(row.get("candidate_count"))
        ),
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
