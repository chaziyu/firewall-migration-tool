import json
import os
from pathlib import Path

import pytest

from fwmigrate.ai.config import AISettings
from fwmigrate.ai.llama_cpp import LlamaCppProvider
from fwmigrate.ai.local_runtime import LocalAIRuntimeManager
from fwmigrate.conversion.fortigate_to_palo_alto.ai.prompts import ARCHITECTURE_PROMPT, ARCHITECTURE_SCHEMA
from fwmigrate.conversion.fortigate_to_palo_alto.ai.sanitizer import sanitize_ai_context
from fwmigrate.conversion.fortigate_to_palo_alto.ai.validator import validate_architecture_output


@pytest.mark.local_ai
def test_local_model_eval_cases_pass_the_application_validator():
    if os.environ.get("AI_RUN_LOCAL_EVAL") != "1":
        pytest.skip("Set AI_RUN_LOCAL_EVAL=1 to run the local model evaluation corpus")
    settings = AISettings()
    runtime = LocalAIRuntimeManager(settings)
    if not runtime.is_available_or_installable():
        pytest.skip("The verified local model and pinned runtime are not installed")
    provider = LlamaCppProvider(settings, runtime_manager=runtime)
    path = Path(__file__).parents[1] / "fixtures" / "ai_eval" / "cases.json"
    cases = json.loads(path.read_text(encoding="utf-8"))
    for number, case in enumerate(cases, 1):
        count = case.get("decision_count", 1)
        decisions = []
        allowed = {}
        for index in range(count):
            key = f"decision_{index + 1}"
            allowed[key] = tuple(case["values"])
            decisions.append({"key": key, "target_field": case["field"], "mode": "REQUIRED",
                "review_state": "PENDING", "allowed_values": case["values"],
                "candidates": [{"value": value, "class": "POSSIBLE", "evidence": case["evidence"]}
                               for value in case["values"]],
                "source": {"source_type": case["kind"]}, "target_finding": "CONFLICT" if "conflicting" in case["name"] else None,
                "auto_status": "NEEDS_INPUT"})
        group = {"source_vdom": "root", "source_kind": case["kind"], "source_name": case["object"],
                 "queue": "NEEDS_INPUT", "affected_count": 1, "decisions": decisions}
        payload = sanitize_ai_context({"operation": "questions", "groups": [group]})
        result = provider.generate_structured(system_prompt=ARCHITECTURE_PROMPT, payload=payload,
            schema_name="fg_pan_architecture_questions", schema=ARCHITECTURE_SCHEMA)
        questions = validate_architecture_output(result.data, groups=payload["groups"],
            allowed_values=allowed, max_questions=settings.max_questions)
        if not case["values"]:
            assert not questions, case["name"]
        for question in questions:
            assert question["decision_keys"] == list(allowed), case["name"]
            assert question["title"] and question["question"], case["name"]
