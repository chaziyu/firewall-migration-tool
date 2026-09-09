import pytest
from fwmigrate.validation.validators import DependencyValidator, SemanticValidator, CapacityValidator
from fwmigrate.ir.v2.models import IRConfigV2, SecurityRuleV2, AddressV2, ZoneV2
from fwmigrate.ir.v2.provenance import Provenance, FieldStatus
from fwmigrate.ir.enums import PolicyAction

def test_dependency_validator_catches_missing_zone():
    prov = Provenance(source_id="1", source_type="rule", conversion_status=FieldStatus.FULL)
    rule = SecurityRuleV2(name="rule1", action=PolicyAction.ALLOW, from_zone=["UnknownZone"], source=["any"], destination=["any"], service=["any"], provenance=prov)
    
    # Missing zone
    ir = IRConfigV2(policies=[rule])
    
    validator = DependencyValidator()
    issues = validator.validate(ir)
    
    assert len(issues) == 1
    assert issues[0].severity == "HIGH"
    assert issues[0].blocking is True
    assert "UnknownZone" in issues[0].message

def test_semantic_validator_overlapping_ips():
    prov = Provenance(source_id="1", source_type="addr", conversion_status=FieldStatus.FULL)
    addr1 = AddressV2(name="net1", type="ip-netmask", value="10.0.0.0/24", provenance=prov)
    addr2 = AddressV2(name="net2", type="ip-netmask", value="10.0.0.128/25", provenance=prov)
    
    ir = IRConfigV2(addresses=[addr1, addr2])
    
    validator = SemanticValidator()
    issues = validator.validate(ir)
    
    assert len(issues) == 1
    assert issues[0].severity == "LOW"
    assert issues[0].blocking is False
    assert "Overlaps" in issues[0].message

def test_capacity_validator():
    prov = Provenance(source_id="1", source_type="zone", conversion_status=FieldStatus.FULL)
    zones = [ZoneV2(name=f"zone{i}", provenance=prov) for i in range(5)]
    
    ir = IRConfigV2(zones=zones)
    
    validator = CapacityValidator(limits={'max_zones': 2})
    issues = validator.validate(ir)
    
    assert len(issues) == 1
    assert issues[0].severity == "CRITICAL"
    assert issues[0].blocking is True
    assert "Exceeded max_zones: configured 5, limit 2" in issues[0].message
