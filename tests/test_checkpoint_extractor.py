import json
import pytest
from fwmigrate.parsers.checkpoint.extractor import extract_checkpoint_config
from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.extraction.sanitize import REDACTED_PLACEHOLDER
from tests.fixture_paths import CHECKPOINT_FIXTURE


def test_extract_minimal_bundle():
    with open(CHECKPOINT_FIXTURE, "r", encoding="utf-8") as f:
        content = f.read()

    result = extract_checkpoint_config(content)

    assert result.canonical_ir is not None
    assert result.canonical_ir.metadata.hostname == "CP-Enterprise-Gateway"
    assert len(result.source_sections) > 0
    assert len(result.inventory_items) > 0

    # Test Golden Invariant 3: Zero Silent Loss Leaf Accounting
    status_counts = {}
    for item in result.inventory_items:
        status_counts[item.status] = status_counts.get(item.status, 0) + 1

    total_leaf_items = sum(status_counts.values())
    assert total_leaf_items == len(result.inventory_items)
    assert status_counts.get(ExtractionStatus.NORMALIZED, 0) > 0


def test_secret_sanitization_in_extraction():
    bundle_with_secrets = json.dumps({
        "format": "checkpoint-export-v1",
        "responses": [
            {
                "command": "show-gateways-and-servers",
                "data": {
                    "objects": [
                        {
                            "name": "GW01",
                            "type": "simple-gateway",
                            "sic-name": "cn=cp_mgmt,o=myorg",
                            "one-time-password": "SecretPassword123!",
                            "vpn-settings": {
                                "shared-secret": "PresharedKey999!",
                                "token": "SecretSessionToken"
                            }
                        }
                    ]
                }
            }
        ]
    })

    result = extract_checkpoint_config(bundle_with_secrets)
    assert len(result.inventory_items) == 1
    item = result.inventory_items[0]
    attrs = item.source_attributes

    assert attrs.get("one-time-password") == REDACTED_PLACEHOLDER
    assert attrs.get("sic-name") == REDACTED_PLACEHOLDER
    vpn = attrs.get("vpn-settings", {})
    assert vpn.get("shared-secret") == REDACTED_PLACEHOLDER
    assert vpn.get("token") == REDACTED_PLACEHOLDER


def test_unsupported_object_recorded_in_extraction():
    bundle_with_unsupported = json.dumps({
        "format": "checkpoint-export-v1",
        "responses": [
            {
                "command": "show-objects",
                "data": {
                    "objects": [
                        {
                            "uid": "uid-dyn-001",
                            "name": "LocalGatewayDynamic",
                            "type": "dynamic-object",
                            "comments": "dynamic local obj"
                        }
                    ]
                }
            }
        ]
    })

    result = extract_checkpoint_config(bundle_with_unsupported)
    assert len(result.unsupported_items) == 1
    unsupp = result.unsupported_items[0]
    assert unsupp.source_name == "LocalGatewayDynamic"
    assert "dynamic-object" in unsupp.reason
    assert unsupp.requires_manual_review
