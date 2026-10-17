"""Registration of built-in pair-specific migration planners."""

from fwmigrate.conversion.fortigate_to_palo_alto import FortiGateToPaloAltoPlanner
from .fortigate_to_juniper_srx import FortiGateToJuniperSRXPlanner
from .fortigate_to_juniper_srx.application.cli import run_cli as run_srx_cli
from .fortigate_to_cisco_asa import FortiGateToCiscoASAPlanner
from .fortigate_to_cisco_asa.application.cli import run_cli as run_asa_cli
from .fortigate_to_checkpoint import FortiGateToCheckPointPlanner
from .fortigate_to_checkpoint.application.cli import run_cli as run_checkpoint_cli
from .palo_alto_to_fortigate import PaloAltoToFortiGatePlanner

from .registry import migration_planners
from .workflow_registry import MigrationWorkflowRegistration, migration_workflows


_BUILTIN_PLANNERS = (
    FortiGateToPaloAltoPlanner(),
    PaloAltoToFortiGatePlanner(),
    FortiGateToJuniperSRXPlanner(),
    FortiGateToCiscoASAPlanner(),
    FortiGateToCheckPointPlanner(),
)
_BUILTIN_WORKFLOWS = (
    MigrationWorkflowRegistration(
        pair_id="fortigate_to_palo_alto",
        source_vendor="fortigate",
        target_vendor="palo_alto",
        display_name="FortiGate to Palo Alto PAN-OS",
        api_prefix="/api/migration",
        supported_formats=("set",),
        export_available=True,
        destination_aware_available=True,
        deployment_available=True,
    ),
    MigrationWorkflowRegistration(
        pair_id="palo_alto_to_fortigate",
        source_vendor="palo_alto",
        target_vendor="fortigate",
        display_name="Palo Alto PAN-OS to FortiGate",
        api_prefix="/api/migration/palo_alto_to_fortigate",
        supported_formats=("cli",),
        export_available=True,
        destination_aware_available=True,
        deployment_available=False,
    ),
    MigrationWorkflowRegistration(
        pair_id="fortigate_to_juniper_srx",
        source_vendor="fortigate",
        target_vendor="juniper_srx",
        display_name="FortiGate to Juniper SRX",
        api_prefix="/api/migration/fortigate_to_juniper_srx",
        supported_formats=("set",),
        export_available=True,
        destination_aware_available=False,
        deployment_available=False,
        cli_application=run_srx_cli,
    ),
    MigrationWorkflowRegistration(
        pair_id="fortigate_to_cisco_asa",
        source_vendor="fortigate",
        target_vendor="cisco_asa",
        display_name="FortiGate to Cisco ASA",
        api_prefix="/api/migration/fortigate_to_cisco_asa",
        supported_formats=("cfg",),
        export_available=True,
        destination_aware_available=False,
        deployment_available=False,
        cli_application=run_asa_cli,
    ),
    MigrationWorkflowRegistration(
        pair_id="fortigate_to_checkpoint",
        source_vendor="fortigate",
        target_vendor="checkpoint",
        display_name="FortiGate to Check Point",
        api_prefix="/api/migration/fortigate_to_checkpoint",
        supported_formats=("json",),
        export_available=True,
        destination_aware_available=False,
        deployment_available=False,
        cli_application=run_checkpoint_cli,
    ),
)


def register_builtin_migration_planners() -> None:
    for planner in _BUILTIN_PLANNERS:
        try:
            migration_planners.get(planner.source_vendor, planner.target_vendor)
        except KeyError:
            migration_planners.register(planner)


def register_builtin_migration_workflows() -> None:
    for workflow in _BUILTIN_WORKFLOWS:
        migration_planners.get(workflow.source_vendor, workflow.target_vendor)
        if not workflow.api_prefix or not workflow.supported_formats:
            raise ValueError(f"Export workflow '{workflow.pair_id}' requires an application path and format")
        try:
            migration_workflows.get(workflow.source_vendor, workflow.target_vendor)
        except KeyError:
            migration_workflows.register(workflow)


__all__ = ["register_builtin_migration_planners", "register_builtin_migration_workflows"]
