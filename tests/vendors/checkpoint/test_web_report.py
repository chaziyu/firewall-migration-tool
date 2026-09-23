from pathlib import Path
from copy import deepcopy

from fwmigrate.vendors.checkpoint.source_report import extract_checkpoint_source
from fwmigrate.vendors.checkpoint.web_report import build_checkpoint_preview


def test_web_report_has_typed_source_derived_validation_and_traceability():
    source = (Path(__file__).parents[2] / "fixtures" / "checkpoint" / "multidomain_full.json").read_text()
    result = extract_checkpoint_source(source)
    before = (result.config.model_dump(), deepcopy(result.derived), deepcopy(result.validation))
    preview = build_checkpoint_preview(result)
    assert preview["vendor"] == "checkpoint"
    assert "access_rules" in preview["source"]
    assert {"nat", "policy_traversal", "interfaces", "vpn"} <= set(preview["derived"])
    assert {"scope", "collection", "source_inventory", "unsupported", "validation"} <= set(preview)
    assert "No direct R81.00 equivalent" == preview["summary"]["capabilities"]["SD-WAN"]
    if preview["source"]["nat_rules"]:
        assert "original_source" in preview["source"]["nat_rules"][0]
    assert (result.config.model_dump(), result.derived, result.validation) == before


def test_web_preview_does_not_expose_secret_sentinel():
    secret = "web-report-secret-sentinel"
    preview = build_checkpoint_preview(extract_checkpoint_source(
        f'{{"objects":[{{"type":"host","name":"x","password":"{secret}"}}]}}'))
    assert secret not in str(preview)
