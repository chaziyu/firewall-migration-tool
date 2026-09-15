from copy import deepcopy

from fwmigrate.capabilities.analyzer import CapabilityAnalyzer
from fwmigrate.capabilities.schema import (
    CapabilityStatus,
    FeatureSupport,
    FieldCapability,
    ObjectCapability,
    VendorCapabilityProfile,
)
from fwmigrate.ir import IRConfig, IRMetadata, IRPolicy
from fwmigrate.ir.enums import PolicyAction


def test_analyzer_uses_canonical_ir_without_mutation():
    profile = VendorCapabilityProfile(
        vendor_id="test_vendor",
        os_version="1",
        objects={
            "SecurityRule": ObjectCapability(
                support=FeatureSupport.FULL,
                fields={"description": FieldCapability(support=FeatureSupport.UNSUPPORTED)},
            )
        },
    )
    ir = IRConfig(
        metadata=IRMetadata(),
        policies=[IRPolicy(name="rule1", action=PolicyAction.ALLOW, description="keep")],
    )
    before = deepcopy(ir.model_dump())
    result = CapabilityAnalyzer(profile).analyze(ir, "test_vendor")

    assert result[0].status == CapabilityStatus.UNSUPPORTED
    assert result[0].blocks_generation is False
    assert ir.model_dump() == before
