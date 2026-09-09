import fwmigrate.generators

from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.core import IRConfig, IRMetadata, IRNATRule, IRPolicy
from fwmigrate.ir.enums import NATTranslationMode, NATType, PolicyAction


def _unsafe_ir() -> IRConfig:
    return IRConfig(
        metadata=IRMetadata(hostname="generator-safety", source_vendor="checkpoint"),
        policies=[IRPolicy(
            name="UNSAFE_CHECKPOINT_POLICY", from_zone=["trust"], to_zone=["untrust"],
            source=["host-a"], destination=["host-b"], service=["https"],
            action=PolicyAction.ALLOW, migration_status="PARTIALLY_NORMALIZED",
            requires_manual_review=True, review_reasons=["mixed-zone-address-or-semantics"],
        )],
        nat_rules=[IRNATRule(
            name="UNSAFE_TRANSLATED_SERVICE_NAT", type=NATType.SOURCE,
            from_zone=["any"], to_zone=["any"], source=["any"], destination=["any"],
            services=["https"], translated_sources=["pool-a"], translated_services=["http"],
            source_translation_mode=NATTranslationMode.DYNAMIC_IP_AND_PORT,
            migration_status="PARTIALLY_NORMALIZED", requires_manual_review=True,
            review_reasons=["translated-service"],
        )],
    )


def test_all_cli_generators_withhold_unsafe_checkpoint_policy_and_nat():
    ir = _unsafe_ir()
    cases = {
        "palo_alto": ("xml", ['<entry name="UNSAFE_CHECKPOINT_POLICY"', '<entry name="UNSAFE_TRANSLATED_SERVICE_NAT"']),
        "fortigate": ("cli", ['set name "UNSAFE_CHECKPOINT_POLICY"', 'set name "UNSAFE_TRANSLATED_SERVICE_NAT"']),
        "cisco_asa": ("cli", ["access-list ", "nat ("]),
        "checkpoint": ("cli", ["mgmt_cli add access-rule", "mgmt_cli add nat-rule"]),
        "juniper_srx": ("set", ["set security policies", "set security nat"]),
    }
    for vendor, (format_name, forbidden) in cases.items():
        artifacts = PluginRegistry.get_generator(vendor).generate(ir, format=format_name)
        output = "\n".join(artifact.content for artifact in artifacts)
        for fragment in forbidden:
            assert fragment not in output, f"{vendor} emitted unsafe deployable syntax: {fragment}"


def test_terraform_generators_do_not_emit_unsafe_policy_resources():
    ir = _unsafe_ir()
    for vendor in ("palo_alto", "fortigate", "cisco_asa", "checkpoint", "juniper_srx"):
        artifacts = PluginRegistry.get_generator(vendor).generate(ir, format="terraform")
        output = "\n".join(artifact.content for artifact in artifacts)
        assert 'name = "UNSAFE_CHECKPOINT_POLICY"' not in output
        assert 'name     = "UNSAFE_CHECKPOINT_POLICY"' not in output
        assert 'name = "UNSAFE_TRANSLATED_SERVICE_NAT"' not in output
