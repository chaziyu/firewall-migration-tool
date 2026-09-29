from tools.evaluate_ai_advisor import evaluate_rows


def test_evaluation_reports_safety_and_labeled_metrics():
    rows = [
        {
            "proposal": {"action": "USE_EXISTING", "proposed_value": "ethernet1/1"},
            "validation_result": {"status": "VALID"},
            "expected_engineer_decision": "ethernet1/1",
            "acceptable_alternatives": ["ethernet1/2"],
            "expected_abstention": False,
            "expected_conflict": False,
            "escalated_from": None,
            "engineer_action": "APPROVED",
        },
        {
            "proposal": {"action": "USE_EXISTING", "proposed_value": "ethernet1/3"},
            "validation_result": {"status": "CONFLICT"},
            "expected_engineer_decision": {
                "action": "USE_EXISTING", "value": "ethernet1/2",
            },
            "expected_abstention": True,
            "expected_conflict": True,
            "escalated_from": "qwen_local",
            "engineer_action": "MODIFIED",
        },
        {
            "proposal": {"action": "NO_SAFE_PROPOSAL", "proposed_value": None},
            "validation_result": {"status": "VALID"},
            "expected_engineer_decision": {"action": "NO_SAFE_PROPOSAL"},
            "expected_abstention": True,
            "expected_conflict": False,
            "engineer_action": "REJECTED",
        },
        {"event": "AI_REQUEST_FAILED", "failure_category": "AI_TIMEOUT"},
    ]

    metrics = evaluate_rows(rows)

    assert metrics["valid_proposal_rate"]["rate"] == 1 / 3
    assert metrics["exact_engineer_agreement"]["rate"] == 2 / 3
    assert metrics["acceptable_agreement"]["rate"] == 1 / 2
    assert metrics["abstention_precision"]["rate"] == 1
    assert metrics["unsafe_proposal_rate"]["rate"] == 1 / 2
    assert metrics["conflict_detection"]["rate"] == 1
    assert metrics["groq_escalation_rate"]["rate"] == 1 / 3
    assert metrics["engineer_modification_rate"]["rate"] == 1 / 3
    assert metrics["provider_failures"] == {"AI_TIMEOUT": 1}
