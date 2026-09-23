from __future__ import annotations

from fwmigrate.vendors.checkpoint.extraction import CheckPointSourceRecord, extract_checkpoint_config
from fwmigrate.vendors.checkpoint.models import CheckPointExportBundle


def test_unknown_objects_are_inventory_evidence_and_secrets_are_redacted():
    secret = "checkpoint-inventory-secret"
    result = extract_checkpoint_config(CheckPointExportBundle.model_validate({"responses": [{
        "command": "show-future-objects",
        "data": {"objects": [{
            "uid": "future-1", "name": "future", "type": "future-object",
            "future-leaf": "keep-me", "password": secret,
        }]},
    }]}))

    record = result.source_objects[0]
    assert type(record) is CheckPointSourceRecord
    assert record.values["future-leaf"] == "keep-me"
    assert record.values["password"] == "[REDACTED]"
    assert secret not in str(result.config.model_dump())
    assert secret not in str(record.model_dump())


def test_known_unmodeled_live_command_stays_in_source_inventory():
    result = extract_checkpoint_config(CheckPointExportBundle.model_validate({"responses": [{
        "command": "show-network-feeds",
        "data": {"objects": [{"uid": "feed", "name": "feed", "type": "network-feed", "future-field": "preserve"}]},
    }]}))
    assert len(result.source_inventory) == 1
    assert result.source_inventory[0].values["future-field"] == "preserve"
