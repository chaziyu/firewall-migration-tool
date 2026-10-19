import pytest

from fwmigrate.conversion.workflow_registry import (
    MigrationWorkflowRegistration,
    MigrationWorkflowRegistry,
)


def workflow(source="FortiGate", target="Juniper_SRX", handler=None):
    return MigrationWorkflowRegistration(
        pair_id=f"{source.casefold()}_to_{target.casefold()}",
        source_vendor=source,
        target_vendor=target,
        display_name="Test workflow",
        api_prefix="/api/migration/test",
        supported_formats=("SET",),
        export_available=True,
        destination_aware_available=False,
        deployment_available=False,
        cli_application=handler,
    )


def test_registry_normalizes_directional_vendor_keys_and_orders_stably():
    registry = MigrationWorkflowRegistry()
    first = workflow()
    second = workflow("Palo_Alto", "FortiGate")

    registry.register(first)
    registry.register(second)

    assert registry.get(" FORTIGATE ", "JUNIPER_SRX") is first
    assert [item.pair_id for item in registry.list()] == [
        "fortigate_to_juniper_srx",
        "palo_alto_to_fortigate",
    ]


def test_registry_rejects_duplicate_directional_pair_and_unknown_pair():
    registry = MigrationWorkflowRegistry()
    registry.register(workflow())

    with pytest.raises(ValueError, match="already registered"):
        registry.register(workflow("FORTIGATE", "juniper_srx"))
    with pytest.raises(KeyError, match="not implemented"):
        registry.get("fortigate", "cisco_asa")


def test_public_metadata_excludes_internal_cli_callable():
    handler = lambda **_kwargs: None
    registration = workflow(handler=handler)

    public = registration.public_metadata()

    assert public["supported_formats"] == ["set"]
    assert "cli_application" not in public
    assert handler not in public.values()
    assert public["supported_target_versions"] == []
    assert public["coverage_documentation"] is None
    assert public["mapping_workflow"] is None
    assert public["destination_comparison"] is None
    assert public["execution_mode"] is None
    assert public["activation_steps"] == []


def test_registration_requires_pair_id_to_match_direction():
    with pytest.raises(ValueError, match="pair_id"):
        MigrationWorkflowRegistration(
            pair_id="fortigate_to_cisco_asa",
            source_vendor="fortigate",
            target_vendor="juniper_srx",
            display_name="Test workflow",
            api_prefix="/api/migration/test",
            supported_formats=("set",),
            export_available=True,
            destination_aware_available=False,
            deployment_available=False,
        )
