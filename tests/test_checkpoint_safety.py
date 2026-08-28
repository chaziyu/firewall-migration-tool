import json
import pytest
from fwmigrate.parsers.checkpoint.parser import CheckPointParser
from fwmigrate.parsers.checkpoint.errors import CheckPointParseError
from fwmigrate.ir.enums import PolicyAction

def test_malformed_json_raises_checkpoint_parse_error():
    malformed = "{\ninvalid json here: true"
    parser = CheckPointParser(malformed)
    with pytest.raises(CheckPointParseError):
        parser.parse()

def test_non_dict_root_raises_checkpoint_parse_error():
    parser = CheckPointParser("[\"array\", \"root\"]")
    with pytest.raises(CheckPointParseError):
        parser.parse()

def test_empty_json_creates_no_fake_zones_or_interfaces():
    empty_cfg = "{}"
    parser = CheckPointParser(empty_cfg)
    ir = parser.parse()
    assert ir.zones == []
    assert ir.interfaces == []
    assert ir.addresses == []
    assert ir.services == []
    assert ir.policies == []

def test_host_missing_address_does_not_become_fallback_ip():
    cfg = json.dumps({
        "objects": [
            {"type": "host", "name": "Host_Without_IP", "comments": "broken host"}
        ]
    })
    parser = CheckPointParser(cfg)
    ir = parser.parse()
    assert ir.addresses == []

def test_network_missing_mask_does_not_become_guessed_prefix():
    cfg = json.dumps({
        "objects": [
            {"type": "network", "name": "Net_Without_Mask", "subnet4": "192.168.1.0"}
        ]
    })
    parser = CheckPointParser(cfg)
    ir = parser.parse()
    assert ir.addresses == []

def test_network_missing_subnet_does_not_become_zero_ip():
    cfg = json.dumps({
        "objects": [
            {"type": "network", "name": "Net_Without_Subnet", "mask-length4": 24}
        ]
    })
    parser = CheckPointParser(cfg)
    ir = parser.parse()
    assert ir.addresses == []

def test_range_missing_endpoint_does_not_normalize():
    cfg = json.dumps({
        "objects": [
            {"type": "address-range", "name": "Range_Missing_Last", "ipv4-address-first": "10.0.0.1"}
        ]
    })
    parser = CheckPointParser(cfg)
    ir = parser.parse()
    assert ir.addresses == []

def test_service_missing_port_does_not_become_any():
    cfg = json.dumps({
        "objects": [
            {"type": "service-tcp", "name": "svc_missing_port"}
        ]
    })
    parser = CheckPointParser(cfg)
    ir = parser.parse()
    assert ir.services == []

def test_missing_or_empty_action_does_not_become_accept():
    cfg = json.dumps({
        "access-rulebase": [
            {
                "rule-number": 1,
                "name": "Rule_No_Action",
                "source": [{"name": "Net1"}],
                "destination": [{"name": "Host1"}],
                "service": [{"name": "svc1"}]
            }
        ]
    })
    parser = CheckPointParser(cfg)
    ir = parser.parse()
    assert ir.policies == []

def test_missing_or_empty_source_does_not_become_any():
    cfg = json.dumps({
        "access-rulebase": [
            {
                "rule-number": 1,
                "name": "Rule_No_Source",
                "source": [],
                "destination": [{"name": "Host1"}],
                "service": [{"name": "svc1"}],
                "action": "Accept",
                "enabled": True
            }
        ]
    })
    parser = CheckPointParser(cfg)
    ir = parser.parse()
    assert len(ir.policies) == 1
    assert ir.policies[0].requires_manual_review
    assert not ir.policies[0].safe_for_target_generation

def test_missing_or_empty_destination_does_not_become_any():
    cfg = json.dumps({
        "access-rulebase": [
            {
                "rule-number": 1,
                "name": "Rule_No_Dest",
                "source": [{"name": "Net1"}],
                "destination": [],
                "service": [{"name": "svc1"}],
                "action": "Accept",
                "enabled": True
            }
        ]
    })
    parser = CheckPointParser(cfg)
    ir = parser.parse()
    assert len(ir.policies) == 1
    assert ir.policies[0].requires_manual_review
    assert not ir.policies[0].safe_for_target_generation

def test_missing_or_empty_service_does_not_become_any():
    cfg = json.dumps({
        "access-rulebase": [
            {
                "rule-number": 1,
                "name": "Rule_No_Service",
                "source": [{"name": "Net1"}],
                "destination": [{"name": "Host1"}],
                "service": [],
                "action": "Accept",
                "enabled": True
            }
        ]
    })
    parser = CheckPointParser(cfg)
    ir = parser.parse()
    assert len(ir.policies) == 1
    assert ir.policies[0].requires_manual_review
    assert not ir.policies[0].safe_for_target_generation
