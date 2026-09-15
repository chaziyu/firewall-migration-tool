from fwmigrate.capabilities.schema import VendorCapabilityProfile, ObjectCapability, FeatureSupport, FieldCapability
from fwmigrate.capabilities.analyzer import CapabilityAnalyzer
from fwmigrate.ir import IRConfig, IRMetadata, IRPolicy
from fwmigrate.ir.enums import PolicyAction

def test_capability_mismatch_blocks_job():
    # Target profile supports rules but drops description
    target_profile = VendorCapabilityProfile(
        vendor_id="test_vendor",
        os_version="1.0",
        objects={
            "SecurityRule": ObjectCapability(
                support=FeatureSupport.FULL,
                fields={
                    "description": FieldCapability(support=FeatureSupport.UNSUPPORTED)
                }
            )
        }
    )
    
    analyzer = CapabilityAnalyzer(target_profile)
    
    # Create IR with description
    rule = IRPolicy(name="rule1", action=PolicyAction.ALLOW, description="my desc")
    
    ir = IRConfig(metadata=IRMetadata(), policies=[rule])
    
    issues = analyzer.analyze(ir)
    
    # Should flag the description drop as HIGH, but non-blocking
    assert len(issues) == 1
    assert issues[0].severity == "HIGH"
    assert issues[0].blocking is False
    assert "description" in issues[0].message

def test_unsupported_object_is_blocking():
    # Target profile does not support policies at all
    target_profile = VendorCapabilityProfile(
        vendor_id="test_vendor",
        os_version="1.0",
        objects={
            "SecurityRule": ObjectCapability(
                support=FeatureSupport.UNSUPPORTED
            )
        }
    )
    
    analyzer = CapabilityAnalyzer(target_profile)
    rule = IRPolicy(name="rule1", action=PolicyAction.ALLOW)
    
    ir = IRConfig(metadata=IRMetadata(), policies=[rule])
    issues = analyzer.analyze(ir)
    
    assert len(issues) == 1
    assert issues[0].severity == "CRITICAL"
    assert issues[0].blocking is True
    assert "Target platform does not support Security Rules" in issues[0].message
