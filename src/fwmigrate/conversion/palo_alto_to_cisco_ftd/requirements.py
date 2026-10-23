"""Decision requirements for Cisco FTD target mapping."""

from .models import FTDMigrationDecision
from .planning.source_scope import source_scopes


def build_mapping_requirements(source, options):
    scopes = source_scopes(source)
    return (
        FTDMigrationDecision(
            key="source_scope",
            source_scope=options.source_scope,
            source_kind="source_scope",
            source_name=options.source_scope or "",
            target_field="source_scope",
            label="Source PAN-OS VSYS Scope",
            value=options.source_scope,
            choices=scopes,
        ),
        FTDMigrationDecision(
            key="target_mode",
            source_scope=options.source_scope,
            source_kind="target_mode",
            source_name=options.target_mode,
            target_field="target_mode",
            label="Target FMC Mode",
            value=options.target_mode,
            choices=("new", "existing"),
        ),
        FTDMigrationDecision(
            key="domain_id",
            source_scope=options.source_scope,
            source_kind="domain_id",
            source_name=options.domain_id or "",
            target_field="domain_id",
            label="Target FMC Domain UUID",
            value=options.domain_id,
        ),
        FTDMigrationDecision(
            key="domain_name",
            source_scope=options.source_scope,
            source_kind="domain_name",
            source_name=options.domain_name or "",
            target_field="domain_name",
            label="Target FMC Domain Name (optional)",
            value=options.domain_name,
        ),
        FTDMigrationDecision(
            key="policy_name",
            source_scope=options.source_scope,
            source_kind="policy_name",
            source_name=options.policy_name or "",
            target_field="policy_name",
            label="Target Access Control Policy Name",
            value=options.policy_name,
        ),
        FTDMigrationDecision(
            key="manager_target",
            source_scope=options.source_scope,
            source_kind="manager_target",
            source_name=options.manager_target or "",
            target_field="manager_target",
            label="Target FMC Hostname or IP",
            value=options.manager_target,
        ),
        FTDMigrationDecision(
            key="fmc_api_version",
            source_scope=options.source_scope,
            source_kind="fmc_api_version",
            source_name=options.fmc_api_version or "7.7.0",
            target_field="fmc_api_version",
            label="FMC REST API Version",
            value=options.fmc_api_version or "7.7.0",
            choices=("7.7.0",),
        ),
    )
