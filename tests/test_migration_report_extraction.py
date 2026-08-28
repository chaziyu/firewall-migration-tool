import json

from fwmigrate.parsers.checkpoint.extractor import extract_checkpoint_config
from fwmigrate.report.migration_report import MigrationReporter


def test_report_includes_source_only_rules_and_never_claims_all_converted():
    extraction = extract_checkpoint_config(json.dumps({
        "format": "checkpoint-export-v1",
        "selected_package": "Standard", "selected_access_layer": "Network",
        "responses": [{
            "command": "show-access-rulebase", "package": "Standard", "layer": "Network",
            "data": {"rulebase": [{
                "uid": "ask-rule", "rule-number": 1, "name": "Interactive_Ask",
                "source": ["Any"], "destination": ["Any"], "service": ["Any"],
                "action": "Ask", "enabled": True,
            }]},
        }],
    }))
    reporter = MigrationReporter(extraction.canonical_ir, extraction_result=extraction)
    report = reporter.generate_report()
    assert "Interactive_Ask" in report
    assert "unsupported-action:Ask" in report
    assert "All objects converted automatically" not in report
    assert reporter.generate_json_summary()["extraction_safety"]["PARTIALLY_NORMALIZED"] == 1
    html_report = reporter.generate_html_report()
    assert "Interactive_Ask" in html_report
    assert "Source Extraction Safety" in html_report
