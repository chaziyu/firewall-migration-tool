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


def test_gaia_show_output_is_preserved_as_untyped_source_evidence():
    result = extract_checkpoint_config(CheckPointExportBundle.model_validate({
        "responses": [{
            "command": "gaia/show-route-static-all",
            "data": {"command_output": "10.0.0.0/8 via 192.0.2.1"},
            "gateway": "gw1",
            "collection_status": "SUCCESS_WITH_DATA",
        }],
    }))

    assert not result.config.gaia_static_routes
    assert len(result.source_inventory) == 1
    record = result.source_inventory[0]
    assert record.object_type == "gaia-show-evidence"
    assert record.command == "gaia/show-route-static-all"
    assert record.gateway == "gw1"
    assert record.values["raw"] == "10.0.0.0/8 via 192.0.2.1"
