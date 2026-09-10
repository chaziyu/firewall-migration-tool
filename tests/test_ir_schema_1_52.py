from fwmigrate.ir import IR_SCHEMA_VERSION
from fwmigrate.ir.io import load_ir_payload
from fwmigrate.ir.migrations import migrate_ir_payload


def test_schema_1_51_migrates_to_current_without_inventing_fields():
    payload = {
        "schema_version": "1.51",
        "metadata": {"hostname": "FW", "source_vendor": "fortigate"},
    }

    migrated = migrate_ir_payload(payload)

    assert IR_SCHEMA_VERSION == "1.58"
    assert migrated == {
        "schema_version": "1.58",
        "metadata": {"hostname": "FW", "source_vendor": "fortigate"},
    }
    assert payload["schema_version"] == "1.51"
    assert load_ir_payload(payload).schema_version == IR_SCHEMA_VERSION


def test_schema_1_52_migrates_to_current_without_inventing_fields():
    payload = {
        "schema_version": "1.52",
        "metadata": {"hostname": "FW", "source_vendor": "palo_alto"},
    }

    migrated = migrate_ir_payload(payload)

    assert migrated == {
        "schema_version": "1.58",
        "metadata": {"hostname": "FW", "source_vendor": "palo_alto"},
    }
    assert payload["schema_version"] == "1.52"
    assert load_ir_payload(payload).schema_version == IR_SCHEMA_VERSION
