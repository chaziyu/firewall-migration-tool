from fwmigrate.validation.validators import DependencyValidator, SemanticValidator, CapacityValidator
from fwmigrate.ir import IRAddress, IRConfig, IRMetadata, IRPolicy, IRZone
from fwmigrate.ir.enums import AddressType, PolicyAction

def test_dependency_validator_catches_missing_zone():
    rule = IRPolicy(name="rule1", action=PolicyAction.ALLOW, from_zone=["UnknownZone"], source=["any"], destination=["any"], service=["any"])
    
    # Missing zone
    ir = IRConfig(metadata=IRMetadata(), policies=[rule])
    
    validator = DependencyValidator()
    issues = validator.validate(ir)
    
    assert len(issues) == 1
    assert issues[0].severity == "HIGH"
    assert issues[0].blocking is True
    assert "UnknownZone" in issues[0].message

def test_semantic_validator_overlapping_ips():
    addr1 = IRAddress(name="net1", type=AddressType.NETWORK, value="10.0.0.0/24")
    addr2 = IRAddress(name="net2", type=AddressType.NETWORK, value="10.0.0.128/25")
    
    ir = IRConfig(metadata=IRMetadata(), addresses=[addr1, addr2])
    
    validator = SemanticValidator()
    issues = validator.validate(ir)
    
    assert len(issues) == 1
    assert issues[0].severity == "LOW"
    assert issues[0].blocking is False
    assert "Overlaps" in issues[0].message


def test_semantic_validator_separates_ipv4_and_ipv6():
    ir = IRConfig(metadata=IRMetadata(), addresses=[
        IRAddress(name="ipv4", type=AddressType.NETWORK, value="10.0.0.0/24"),
        IRAddress(name="ipv6", type=AddressType.NETWORK, value="2001:db8::/64"),
    ])

    assert SemanticValidator().validate(ir) == []

def test_capacity_validator():
    zones = [IRZone(name=f"zone{i}") for i in range(5)]
    
    ir = IRConfig(metadata=IRMetadata(), zones=zones)
    
    validator = CapacityValidator(limits={'max_zones': 2})
    issues = validator.validate(ir)
    
    assert len(issues) == 1
    assert issues[0].severity == "CRITICAL"
    assert issues[0].blocking is True
    assert "Exceeded max_zones: configured 5, limit 2" in issues[0].message
