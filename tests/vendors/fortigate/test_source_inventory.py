from types import SimpleNamespace

from fwmigrate.vendors.fortigate.extraction.coverage import (
    build_typed_source_inventory,
    extraction_status,
)
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


SOURCE = '''config vdom
    edit tenant-a
        config firewall unsupported-section
            edit source-only
                set known value
                append member one
                unset comment
                mystery raw
                config tagging
                    edit tag-a
                        set color blue
                    next
                end
            next
        end
    next
end
'''


def test_inventory_preserves_source_evidence_and_provenance():
    analysis = FortiGateSourceReporter().analyze_source(SOURCE)
    records = analysis.extracted.source_objects

    assert [
        (record.vdom, record.source_path, record.object_name, record.parent_objects)
        for record in records
    ] == [
        ("tenant-a", "firewall unsupported-section", "source-only", ()),
        ("tenant-a", "firewall unsupported-section tagging", "tag-a", ("source-only",)),
    ]
    parent, nested = records
    assert parent.values == {
        "known": "value",
        "member": ["one"],
        "unknown_command:mystery": ["raw"],
    }
    assert parent.explicit_fields == ()
    assert parent.unset_fields == ("comment",)
    assert [command.operation for command in parent.commands] == ["set", "append", "unset", "unknown"]
    assert all(command.line_number is not None for command in parent.commands)
    assert parent.start_line_number is not None and parent.end_line_number is not None
    assert nested.values == {"color": "blue"}


def test_typed_inventory_is_read_only_and_reports_coverage_states():
    analysis = FortiGateSourceReporter().analyze_source('''config system interface
    edit "port1"
        set ip 192.0.2.1 255.255.255.0
        set future-option keep
    next
end
''')
    config = analysis.extracted.config
    before = config.model_dump()
    inventory = build_typed_source_inventory(config)
    typed = inventory["system interface"][0]

    assert typed.model is config.interfaces[0]
    assert extraction_status(True, typed) == "TYPED_WITH_RAW_EXTRA"
    assert extraction_status(True, SimpleNamespace(model=SimpleNamespace(raw_extra={}))) == "TYPED"
    assert extraction_status(True, None) == "MODEL_GAP"
    assert extraction_status(False, None) == "SOURCE_ONLY"
    assert before == config.model_dump()
