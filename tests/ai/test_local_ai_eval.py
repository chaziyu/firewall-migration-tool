import json
import os
from pathlib import Path
from time import perf_counter

import pytest

from fwmigrate.ai.config import AISettings
from fwmigrate.ai.llama_cpp import LlamaCppProvider
from fwmigrate.ai.local_runtime import LocalAIRuntimeManager
from fwmigrate.conversion.fortigate_to_palo_alto.ai.assistant import _compact_selection, _expand_compact_selection
from fwmigrate.conversion.fortigate_to_palo_alto.ai.prompts import COMPACT_SELECTION_PROMPT, COMPACT_SELECTION_SCHEMA
from fwmigrate.conversion.fortigate_to_palo_alto.ai.sanitizer import sanitize_ai_context
from fwmigrate.conversion.fortigate_to_palo_alto.ai.validator import validate_selection_output


@pytest.mark.local_ai
def test_local_model_prepares_closed_selections_or_abstains():
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
                "candidates": [{"value": value, "class": "POSSIBLE",
                                "strong_evidence": case["evidence"], "supporting_evidence": []}
                               for value in case["values"]],
                "source": {"source_type": case["kind"]}, "target_finding": "CONFLICT" if "conflicting" in case["name"] else None,
                "auto_status": "NEEDS_INPUT"})
        group = {"source_vdom": "root", "source_kind": case["kind"], "source_name": case["object"],
                 "queue": "NEEDS_INPUT", "affected_count": 1,
                 "confirmed_engineer_context": [], "decisions": decisions}
        if not case["values"]:
            assert not any(item["allowed_values"] for item in group["decisions"])
            continue
        group = sanitize_ai_context(group)
        payload, options = _compact_selection(group)
        started = perf_counter()
        result = provider.generate_structured(system_prompt=COMPACT_SELECTION_PROMPT, payload=payload,
            schema_name="fg_pan_review_selection_compact", schema=COMPACT_SELECTION_SCHEMA)
        assert perf_counter() - started < settings.local_timeout_seconds, case["name"]
        expanded = _expand_compact_selection(result.data, group, options)
        selection = validate_selection_output(expanded, group=group, allowed_values=allowed)
        assert selection["decision_keys"] == list(allowed), case["name"]
        expected = case["values"][0] if len(case["values"]) == 1 else None
        chosen = selection["suggested_assignments"]
        assert ([item["value"] for item in chosen] == [expected] if expected else not chosen), case["name"]
