"""Registration of built-in pair-specific migration planners."""

from fwmigrate.conversion.fortigate_to_palo_alto import FortiGateToPaloAltoPlanner
from .fortigate_to_juniper_srx import FortiGateToJuniperSRXPlanner
from .fortigate_to_juniper_srx.application.cli import run_cli as run_srx_cli
from .fortigate_to_cisco_asa import FortiGateToCiscoASAPlanner
from .fortigate_to_cisco_asa.application.cli import run_cli as run_asa_cli
from .fortigate_to_checkpoint import FortiGateToCheckPointPlanner
from .fortigate_to_checkpoint.application.cli import run_cli as run_checkpoint_cli
from .palo_alto_to_fortigate import PaloAltoToFortiGatePlanner
from .palo_alto_to_juniper_srx import PaloAltoToJuniperSRXPlanner
from .palo_alto_to_juniper_srx.application.cli import run_cli as run_panos_srx_cli
from .palo_alto_to_cisco_asa import PaloAltoToCiscoASAPlanner
from .palo_alto_to_cisco_asa.application.cli import run_cli as run_panos_asa_cli
from .palo_alto_to_checkpoint import PaloAltoToCheckPointPlanner
from .palo_alto_to_checkpoint.application.cli import run_cli as run_panos_checkpoint_cli
from .palo_alto_to_cisco_ftd import PaloAltoToCiscoFTDPlanner
from .palo_alto_to_cisco_ftd.application.cli import run_cli as run_panos_ftd_cli

from .registry import migration_planners
from .workflow_registry import MigrationWorkflowRegistration, migration_workflows


_BUILTIN_PLANNERS = (
    FortiGateToPaloAltoPlanner(),
    PaloAltoToFortiGatePlanner(),
    PaloAltoToJuniperSRXPlanner(),
    PaloAltoToCiscoASAPlanner(),
    PaloAltoToCheckPointPlanner(),
    PaloAltoToCiscoFTDPlanner(),
    FortiGateToJuniperSRXPlanner(),
    FortiGateToCiscoASAPlanner(),
    FortiGateToCheckPointPlanner(),
)
_BUILTIN_WORKFLOWS = (
    MigrationWorkflowRegistration(
        pair_id="palo_alto_to_cisco_ftd", source_vendor="palo_alto", target_vendor="cisco_ftd",
        display_name="Palo Alto PAN-OS to Cisco FTD", api_prefix="/api/migration/palo_alto_to_cisco_ftd",
        supported_formats=("json",), supported_target_versions=("FMC REST API 7.7.0",),
        export_available=True, destination_aware_available=True, deployment_available=False,
        mapping_workflow="Review one PAN-OS VSYS, target FMC domain UUID, and fresh Access Control Policy name; existing mode supports object comparison only.",
        destination_comparison="Optional complete FMC REST export bundles support exact address, port, and security zone reuse. Existing policy insertion stays blocked.",
        execution_mode="Offline FMC REST API request specification, response ID bindings, and shell script; no live execution.",
        activation_steps=("Review exact operations and dependencies", "Approve and download offline request bundle", "Execute API requests via curl or automation", "Assign security zones to FTD device interfaces", "Assign Access Control Policy and deploy via FMC explicitly outside this tool"),
        coverage_documentation="documentation/migration-support-matrix.md", cli_application=run_panos_ftd_cli,
    ),
    MigrationWorkflowRegistration(
        pair_id="palo_alto_to_checkpoint", source_vendor="palo_alto", target_vendor="checkpoint",
        display_name="Palo Alto PAN-OS to Check Point", api_prefix="/api/migration/palo_alto_to_checkpoint",
        supported_formats=("json",), supported_target_versions=("Management API 1.8.1",),
        export_available=True, destination_aware_available=True, deployment_available=False,
        mapping_workflow="Review one PAN-OS VSYS and a separate fresh policy package; existing mode supports object comparison only.",
        destination_comparison="Optional scoped native Management snapshots support exact address/group UID reuse. Existing policy insertion and Gaia stay blocked.",
        execution_mode="Offline API request specification, response UID bindings and fresh-package commands; no live execution.",
        activation_steps=("Review exact operations and dependencies", "Approve and download offline files", "Validate and apply manually", "Publish and install policy explicitly outside this tool"),
        coverage_documentation="documentation/migration-support-matrix.md", cli_application=run_panos_checkpoint_cli,
    ),
    MigrationWorkflowRegistration(
        pair_id="palo_alto_to_cisco_asa", source_vendor="palo_alto", target_vendor="cisco_asa",
        display_name="Palo Alto PAN-OS to Cisco ASA", api_prefix="/api/migration/palo_alto_to_cisco_asa",
        supported_formats=("cfg",), supported_target_versions=("9.20",),
        export_available=True, destination_aware_available=True, deployment_available=False,
        mapping_workflow="Review one PAN-OS VSYS, ASA 9.20 routed single context, physical ports, nameifs and security levels.",
        destination_comparison="Optional complete native ASA object snapshots support exact reuse; existing-target traffic placement stays blocked.",
        execution_mode="Offline ASA CLI export. Routing proof and atomic ACL/binding approval required for traffic.",
        activation_steps=("Review exact changes and dependencies", "Approve and download offline configuration", "Apply, validate and save manually"),
        coverage_documentation="documentation/migration-support-matrix.md", cli_application=run_panos_asa_cli,
    ),
    MigrationWorkflowRegistration(
        pair_id="fortigate_to_palo_alto",
        mapping_workflow="Assisted mapping with evidence-based suggestions and engineer confirmation.",
        destination_comparison="Native XML comparison, reuse and approved additive configuration; unsupported dependencies remain blocked.",
        execution_mode="Reviewed candidate push with separate validation and explicit commit.",
        activation_steps=("Review target evidence and mappings", "Approve the current design", "Push and validate the candidate", "Explicitly commit"),
        supported_target_versions=("11.1",),
        coverage_documentation="documentation/migration-support-matrix.md",
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
        mapping_workflow="Automatic target proposals with reviewed placement, verified source behavior and grouped remaining choices.",
        destination_comparison="Exact reuse and explicitly empty target tables; populated traffic placement stays blocked.",
        execution_mode="Offline CLI export; live execution unavailable.",
        activation_steps=("Review and approve the export", "Apply and validate on the device manually", "Activate and save manually"),
        supported_target_versions=("7.4.6",),
        coverage_documentation="documentation/migration-support-matrix.md",
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
        pair_id="palo_alto_to_juniper_srx",
        mapping_workflow="Choose one standalone PAN-OS VSYS and review Junos interface and zone placement.",
        destination_comparison="Optional Junos 25.2R1 root standalone snapshots support family-complete exact reuse checks; policy, NAT and routing ambiguity stays blocked.",
        execution_mode="Offline Junos set export only; live execution unavailable.",
        activation_steps=("Review and approve the export", "Load and run commit check manually", "Commit explicitly on the device"),
        supported_target_versions=("25.2R1",),
        coverage_documentation="documentation/migration-support-matrix.md",
        source_vendor="palo_alto",
        target_vendor="juniper_srx",
        display_name="Palo Alto PAN-OS to Juniper SRX",
        api_prefix="/api/migration/palo_alto_to_juniper_srx",
        supported_formats=("set",),
        export_available=True,
        destination_aware_available=True,
        deployment_available=False,
        cli_application=run_panos_srx_cli,
    ),
    MigrationWorkflowRegistration(
        pair_id="fortigate_to_juniper_srx",
        mapping_workflow="New-device interface and zone proposals with engineer review; version-verified FortiGate source defaults. Hardware fit remains unverified.",
        destination_comparison="Exact reuse and verified absence; new policies require complete empty policy evidence without NAT or routing-instance ambiguity. Populated placement stays blocked.",
        execution_mode="Offline Junos set export; live execution unavailable.",
        activation_steps=("Review and approve the export", "Load and run commit check manually", "Commit explicitly on the device"),
        supported_target_versions=("25.2R1",),
        coverage_documentation="documentation/migration-support-matrix.md",
        source_vendor="fortigate",
        target_vendor="juniper_srx",
        display_name="FortiGate to Juniper SRX",
        api_prefix="/api/migration/fortigate_to_juniper_srx",
        supported_formats=("set",),
        export_available=True,
        destination_aware_available=True,
        deployment_available=False,
        cli_application=run_srx_cli,
    ),
    MigrationWorkflowRegistration(
        pair_id="fortigate_to_cisco_asa",
        mapping_workflow="Manual interface, nameif and target choices.",
        destination_comparison="Exact address and physical-interface reuse; existing NAT blocks traffic export. Completeness alone does not prove compatibility.",
        execution_mode="Offline ASA CLI export; live execution unavailable.",
        activation_steps=("Review and approve the export", "Apply and validate on the device manually", "Save configuration manually"),
        supported_target_versions=("9.20",),
        coverage_documentation="documentation/migration-support-matrix.md",
        source_vendor="fortigate",
        target_vendor="cisco_asa",
        display_name="FortiGate to Cisco ASA",
        api_prefix="/api/migration/fortigate_to_cisco_asa",
        supported_formats=("cfg",),
        export_available=True,
        destination_aware_available=True,
        deployment_available=False,
        cli_application=run_asa_cli,
    ),
    MigrationWorkflowRegistration(
        pair_id="fortigate_to_checkpoint",
        mapping_workflow="New target: propose a new policy package without a target upload. Existing target: review domain, gateway and rule placement.",
        destination_comparison="Optional for existing targets: exact object reuse by UID and cleanup-only Drop rulebase insertion. Management evidence does not verify Gaia routes.",
        execution_mode="Offline Management commands, API request specification and Gaia Clish export; live execution unavailable.",
        activation_steps=("Review operations and included dependencies", "Approve and generate offline files", "Execute requests and validate manually", "Publish, install policy and save Gaia configuration manually"),
        supported_target_versions=("Management API 1.8.1",),
        coverage_documentation="documentation/migration-support-matrix.md",
        source_vendor="fortigate",
        target_vendor="checkpoint",
        display_name="FortiGate to Check Point",
        api_prefix="/api/migration/fortigate_to_checkpoint",
        supported_formats=("json",),
        export_available=True,
        destination_aware_available=True,
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
