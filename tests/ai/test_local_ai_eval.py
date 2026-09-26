import json
import os
from pathlib import Path

import pytest

from fwmigrate.ai.config import AISettings
from fwmigrate.ai.llama_cpp import LlamaCppProvider
from fwmigrate.ai.local_runtime import LocalAIRuntimeManager
from fwmigrate.conversion.fortigate_to_palo_alto.ai.prompts import ANALYSIS_PROMPT, ANALYSIS_SCHEMA
from fwmigrate.conversion.fortigate_to_palo_alto.ai.sanitizer import sanitize_ai_context
from fwmigrate.conversion.fortigate_to_palo_alto.ai.validator import validate_analysis_output


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
        if not case["values"]:
            continue  # No-candidate groups stay deterministic manual-design work.
        payload = sanitize_ai_context({"operation": "analysis", "groups": [group]})
        result = provider.generate_structured(system_prompt=ANALYSIS_PROMPT, payload=payload,
            schema_name="fg_pan_review_analysis", schema=ANALYSIS_SCHEMA)
        analyses = validate_analysis_output(result.data, groups=payload["groups"],
            allowed_values=allowed, max_results=settings.max_questions)
        for analysis in analyses:
            assert analysis["decision_keys"] == list(allowed), case["name"]
            assert analysis["title"] and analysis["summary"], case["name"]
