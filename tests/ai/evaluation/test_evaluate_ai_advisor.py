from tools.evaluate_ai_advisor import evaluate_rows


def test_evaluation_reports_safety_labels_efficiency_and_groups():
    rows = [
        {
            "proposal": {"action": "USE_EXISTING", "proposed_value": "ethernet1/1"},
            "validation_result": {"status": "VALID"},
            "expected_engineer_decision": "ethernet1/1",
            "acceptable_alternatives": ["ethernet1/2"],
            "expected_abstention": False,
            "expected_conflict": False,
            "provider": "groq",
            "model": "openai/gpt-oss-20b",
            "target_field": "target_interface",
            "candidate_count": 2,
            "request_bytes": 2000,
            "request_duration_ms": 100,
            "repair_pass": 0,
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
            "provider": "groq",
            "model": "openai/gpt-oss-120b",
            "target_field": "target_interface",
            "candidate_count": 5,
            "request_bytes": 4000,
            "request_duration_ms": 300,
            "repair_pass": 1,
            "escalated_from": "qwen_local",
            "engineer_action": "MODIFIED",
        },
        {
            "proposal": {"action": "NO_SAFE_PROPOSAL", "proposed_value": None},
            "validation_result": {"status": "VALID"},
            "expected_engineer_decision": {"action": "NO_SAFE_PROPOSAL"},
            "expected_abstention": True,
            "expected_conflict": False,
            "provider": "qwen_local",
            "model": "Qwen/Qwen3-0.6B",
            "target_field": "target_zone",
            "candidate_count": 8,
            "request_bytes": 3000,
            "request_duration_ms": 200,
            "repair_pass": 0,
            "engineer_action": "REJECTED",
        },
        {"event": "AI_REQUEST_FAILED", "failure_category": "AI_TIMEOUT"},
    ]

    metrics = evaluate_rows(rows)

    assert metrics["valid_proposal_rate"]["rate"] == 1 / 3
    assert metrics["exact_engineer_agreement"]["rate"] == 2 / 3
    assert metrics["acceptable_agreement"]["rate"] == 1 / 2
    assert metrics["abstention_precision"]["rate"] == 1
    assert metrics["abstention_recall"]["rate"] == 1 / 2
    assert metrics["unsafe_proposal_rate"]["rate"] == 1 / 2
    assert metrics["conflict_detection"]["rate"] == 1
    assert metrics["groq_escalation_rate"]["rate"] == 1 / 3
    assert metrics["provider_fallback_rate"]["rate"] == 1 / 3
    assert metrics["engineer_modification_rate"]["rate"] == 1 / 3
    assert metrics["engineer_rejection_rate"]["rate"] == 1 / 3
    assert metrics["provider_failures"] == {"AI_TIMEOUT": 1}
    assert metrics["average_candidate_count"] == {"average": 5, "count": 3}
    assert metrics["average_request_bytes"] == {"average": 3000, "count": 3}
    assert metrics["average_request_duration_ms"] == {"average": 200, "count": 3}
    assert metrics["average_repair_pass"] == {"average": 1 / 3, "count": 3}
    assert metrics["by_provider"]["groq"]["proposal_count"] == 2
    assert metrics["by_model"]["openai/gpt-oss-120b"]["proposal_count"] == 1
    assert metrics["by_target_field"]["target_interface"]["proposal_count"] == 2
    assert metrics["by_candidate_count"]["0-2"]["proposal_count"] == 1
    assert metrics["by_candidate_count"]["3-6"]["proposal_count"] == 1
    assert metrics["by_candidate_count"]["7-12"]["proposal_count"] == 1
