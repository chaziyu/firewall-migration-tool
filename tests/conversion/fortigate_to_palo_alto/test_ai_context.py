from types import SimpleNamespace

from fwmigrate.conversion.fortigate_to_palo_alto.ai.context import build_ai_review_context


def _state(queue, operation="questions", candidates=(), selection_options=None):
    decision = SimpleNamespace(key="scope|interface|port1|target_interface", target_field="target_interface",
                               mode=SimpleNamespace(value="REQUIRED"), review_state=SimpleNamespace(value="PENDING"),
                               value=None, suggested_value=None, evidence_type=None, evidence_value=None)
    group = {"queue": queue, "source_vdom": "root", "source_kind": "interface", "source_name": "port1",
             "affected_count": 1, "decisions": [{"key": decision.key}]}
    return build_ai_review_context(source_digest="s", target_digest="t", target_device="fw1",
        decisions=SimpleNamespace(decisions=(decision,)), review_workflow={"review_groups": [group]},
        review_context={}, decision_candidates={decision.key: candidates},
        ai_selection_options=selection_options or {}, auto_decisions={}, target_findings=(),
        operation=operation, prompt_version="test")


def test_ai_questions_skip_ready_to_confirm_groups_but_explanations_keep_them():
    assert not _state("READY_TO_CONFIRM")["context"]["groups"]
    assert len(_state("READY_TO_CONFIRM", "explain")["context"]["groups"]) == 1


def test_ai_eligible_values_exclude_ambiguous_scopes():
    result = _state("CHOOSE_CANDIDATE", candidates=(
        {"value": "ethernet1/1", "class": "STRONG", "target_scope": "vsys-a"},
        {"value": "ethernet1/1", "class": "STRONG", "target_scope": "vsys-b"},
        {"value": "ethernet1/2", "match_class": "AMBIGUOUS", "scope_identity": "shared"},
        {"value": "ethernet1/3", "class": "POSSIBLE", "target_scope": "vsys-a"},
    ))
    group = result["context"]["groups"][0]
    assert group["decisions"][0]["allowed_values"] == ["ethernet1/3"]
    assert group["decisions"][0]["recommendation_category"] == "REVIEW_RECOMMENDATION"
    assert result["allowed_values"][group["decisions"][0]["key"]] == ("ethernet1/3",)


def test_select_uses_closed_inventory_only_when_deterministic_candidates_are_absent():
    option = {"value": "trust", "target_scope": "vsys:vsys1:device:fw1",
              "strong_evidence": ["Explicit PAN zone in VSYS vsys1"],
              "supporting_evidence": [], "contradictions": []}
    manual = _state("NEEDS_INPUT", "select", selection_options={
        "scope|interface|port1|target_interface": [option]})
    decision = manual["context"]["groups"][0]["decisions"][0]
    assert decision["allowed_values"] == ["trust"]
    assert decision["candidates"][0]["strong_evidence"] == option["strong_evidence"]
    assert not _state("NEEDS_INPUT", "select")["context"]["groups"]
    changed = _state("NEEDS_INPUT", "select", selection_options={
        "scope|interface|port1|target_interface": [{**option, "value": "untrust"}]})
    assert manual["state_digest"] != changed["state_digest"]


def test_analysis_paginates_candidate_groups_and_keeps_state_digest_batch_independent():
    decisions = []
    groups = []
    candidates = {}
    for index in range(25):
        key = f"scope|interface|port{index}|target_interface"
        decisions.append(SimpleNamespace(key=key, target_field="target_interface",
            mode=SimpleNamespace(value="REQUIRED"), review_state=SimpleNamespace(value="PENDING"),
            value=None, suggested_value=None, evidence_type=None, evidence_value=None))
        groups.append({"queue": "CHOOSE_CANDIDATE", "source_vdom": "root", "source_kind": "interface",
            "source_name": f"port{index}", "affected_count": 1, "decisions": [{"key": key}]})
        candidates[key] = [{"value": f"ethernet1/{index + 1}", "class": "POSSIBLE",
                            "evidence": [f"candidate for {index}"]}]
    missing_key = "scope|interface|missing|target_interface"
    decisions.append(SimpleNamespace(key=missing_key, target_field="target_interface",
        mode=SimpleNamespace(value="REQUIRED"), review_state=SimpleNamespace(value="PENDING"),
        value=None, suggested_value=None, evidence_type=None, evidence_value=None))
    groups.append({"queue": "NEEDS_INPUT", "source_vdom": "root", "source_kind": "interface",
        "source_name": "missing", "affected_count": 1, "decisions": [{"key": missing_key}]})

    def build(cursor):
        return build_ai_review_context(source_digest="s", target_digest="t", target_device="fw1",
            decisions=SimpleNamespace(decisions=tuple(decisions)),
            review_workflow={"review_groups": groups}, review_context={}, decision_candidates=candidates,
            auto_decisions={}, target_findings=(), operation="analysis", prompt_version="test",
            max_groups=20, cursor=cursor)

    first = build(0)
    second = build(first["next_cursor"])
    seen = [key for batch in (first, second) for key in batch["decision_refs"].values()]
    assert len(seen) == len(set(seen)) == 25
    assert first["next_cursor"] == 20 and second["next_cursor"] is None
    assert first["state_digest"] == second["state_digest"]
    assert first["candidate_backed_groups"] == 25
    assert first["insufficient_evidence"] == 1
    decisions[0].evidence_source = "ENGINEER"
    changed = build(20)
    assert changed["state_digest"] != first["state_digest"]


def test_analysis_batches_migration_families_before_impact_ordering():
    entries = [("zone", "inside", "target_zone", 90, None),
               ("interface", "port1", "target_interface", 2, "physical"),
               ("interface", "vlan10", "target_interface", 9, "vlan"),
               ("interface", "vpn1", "target_interface", 4, "tunnel"),
               ("vdom", "root", "vsys", 1, None),
               ("interface", "port2", "target_interface", 8, "physical")]
    decisions, groups, candidates, facts = [], [], {}, {}
    for kind, name, target_field, impact, source_type in entries:
        key = f"{kind}|{name}|{target_field}"
        decisions.append(SimpleNamespace(key=key, source_vdom="root", source_kind=kind, source_name=name,
            target_field=target_field, mode=SimpleNamespace(value="REQUIRED"),
            review_state=SimpleNamespace(value="PENDING"), value=None, suggested_value=None,
            evidence_type=None, evidence_value=None, evidence_source=None))
        groups.append({"queue": "CHOOSE_CANDIDATE", "source_vdom": "root", "source_kind": kind,
            "source_name": name, "affected_count": impact, "decisions": [{"key": key}]})
        candidates[key] = [{"value": f"target-{name}", "class": "POSSIBLE", "supporting_evidence": ["explicit candidate"]}]
        facts[key] = {"source_type": source_type} if source_type else {}
    result = build_ai_review_context(source_digest="s", target_digest="t", target_device="fw1",
        decisions=SimpleNamespace(decisions=tuple(decisions)), review_workflow={"review_groups": groups},
        review_context=facts, decision_candidates=candidates, auto_decisions={}, target_findings=(),
        operation="analysis", prompt_version="test", max_groups=20)
    ordered = [(item["source_kind"], item["source_name"]) for item in result["context"]["groups"]]
    assert ordered == [("vdom", "root"), ("interface", "port2"), ("interface", "port1"),
                       ("interface", "vlan10"), ("interface", "vpn1"), ("zone", "inside")]
    assert len(str(result["context"]).encode("utf-8")) < 16000


def test_requested_group_survives_the_first_page_limit():
    decisions, groups, candidates = [], [], {}
    for index in range(25):
        key = f"decision-{index}"
        decisions.append(SimpleNamespace(key=key, source_vdom="root", source_kind="interface",
            source_name=f"port{index}", target_field="target_interface",
            mode=SimpleNamespace(value="REQUIRED"), review_state=SimpleNamespace(value="PENDING")))
        groups.append({"queue": "CHOOSE_CANDIDATE", "source_vdom": "root", "source_kind": "interface",
            "source_name": f"port{index}", "affected_count": 1, "decisions": [{"key": key}]})
        candidates[key] = [{"value": f"ethernet1/{index}", "supporting_evidence": ["explicit option"]}]
    result = build_ai_review_context(source_digest="s", target_digest="t", target_device="fw1",
        decisions=SimpleNamespace(decisions=tuple(decisions)), review_workflow={"review_groups": groups},
        review_context={}, decision_candidates=candidates, auto_decisions={}, target_findings=(),
        operation="select", prompt_version="test", max_groups=20,
        group_identity=("root", "interface", "port24"))
    assert result["context"]["groups"][0]["source_name"] == "port24"


def test_analysis_does_not_offer_a_silent_first_eight_of_nine_options():
    candidates = tuple({"value": f"ethernet1/{index}", "supporting_evidence": ["explicit option"]}
                       for index in range(9))
    analysis = _state("CHOOSE_CANDIDATE", "analysis", candidates=candidates)
    assert not analysis["context"]["groups"]
    assert analysis["option_overflow"] == {"scope|interface|port1|target_interface": 9}
    selection = _state("CHOOSE_CANDIDATE", "select", candidates=candidates)
    assert selection["context"]["groups"][0]["decisions"][0]["unexamined_options"] == 1
