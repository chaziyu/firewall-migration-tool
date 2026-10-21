"""Proposals for a separate new package; never target-state evidence."""

from dataclasses import replace

from ..planning.naming import target_name
from ..planning.source_scope import source_scopes


def propose_new_target(source, options):
    scopes = source_scopes(source)
    scope = options.source_scope or (scopes[0] if len(scopes) == 1 else None)
    proposed = replace(options, source_scope=scope,
                       management_api_version=options.management_api_version or "1.8.1")
    if proposed.target_mode == "new":
        return replace(proposed, policy_package=options.policy_package or (
            target_name("package", scope, "migration") if scope else None),
            access_layer=None, insertion_anchor=None, insertion_relation=None, target_cleanup_action=None)
    return proposed
