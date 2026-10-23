"""Proposals for a fresh FMC Access Control Policy and objects."""

from dataclasses import replace

from ..planning.source_scope import source_scopes


def propose_new_target(source, options):
    scopes = source_scopes(source)
    scope = options.source_scope or (scopes[0] if len(scopes) == 1 else None)
    proposed = replace(
        options,
        source_scope=scope,
        fmc_api_version=options.fmc_api_version or "7.7.0",
    )
    if proposed.target_mode == "new":
        default_policy_name = f"PAN_Migrated_{scope.replace(':', '_')}" if scope else "PAN_Migrated_ACP"
        return replace(
            proposed,
            policy_name=options.policy_name or default_policy_name,
        )
    return proposed
