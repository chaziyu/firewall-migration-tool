from fwmigrate.capabilities.analyzer import CapabilityAnalyzer
from fwmigrate.capabilities.loader import CapabilityLoader
from fwmigrate.capabilities.schema import (
    CapabilityStatus,
    FeatureSupport,
    FieldCapability,
    ObjectCapability,
    VendorCapabilityProfile,
)
from fwmigrate.ir import IRConfig, IRMetadata, IRPolicy
from fwmigrate.ir.enums import PolicyAction


def test_loader_prefers_version_profile_and_falls_back_to_default(tmp_path):
    vendor_dir = tmp_path / "test_vendor"
    vendor_dir.mkdir()
    (vendor_dir / "default.yaml").write_text(
        "vendor_id: test_vendor\nos_version: 'default'\nobjects: {}\n",
        encoding="utf-8",
    )
    (vendor_dir / "1.0.yaml").write_text(
        "vendor_id: test_vendor\nos_version: '1.0'\nobjects: {}\n",
        encoding="utf-8",
    )
    loader = CapabilityLoader(tmp_path)

    assert loader.load_profile("test_vendor", "1.0").os_version == "1.0"
    assert loader.load_profile("test_vendor").os_version == "default"
    assert loader.load_profile("test_vendor", "missing").os_version == "default"


def test_unsupported_field_uses_explicit_blocking_policy():
    profile = VendorCapabilityProfile(
        vendor_id="test_vendor",
        os_version="1",
        objects={
            "SecurityRule": ObjectCapability(
                support=FeatureSupport.FULL,
                fields={
                    "description": FieldCapability(
                        support=FeatureSupport.UNSUPPORTED,
                        blocks_generation=True,
                    ),
                },
            ),
        },
    )
    ir = IRConfig(
        metadata=IRMetadata(),
        policies=[IRPolicy(name="rule1", action=PolicyAction.ALLOW, description="keep")],
    )

    result = CapabilityAnalyzer(profile).analyze(ir, "test_vendor")

    assert result[0].status == CapabilityStatus.UNSUPPORTED
    assert result[0].blocks_generation is True


def test_loader_rejects_profile_vendor_mismatch(tmp_path):
    vendor_dir = tmp_path / "test_vendor"
    vendor_dir.mkdir()
    (vendor_dir / "default.yaml").write_text(
        "vendor_id: wrong_vendor\nos_version: default\nobjects: {}\n",
        encoding="utf-8",
    )

    try:
        CapabilityLoader(tmp_path).load_profile("test_vendor")
    except ValueError as exc:
        assert "vendor mismatch" in str(exc)
    else:
        raise AssertionError("vendor mismatch should be rejected")
