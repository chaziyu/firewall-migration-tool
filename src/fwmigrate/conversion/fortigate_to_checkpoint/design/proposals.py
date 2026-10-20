"""Offline creation proposals; these do not describe an existing device."""

from dataclasses import replace

from ..planning.naming import target_name
from ..requirements import source_vdoms


def propose_new_target(source, options):
    if options.target_mode != "new":
        return options
    vdoms = source_vdoms(source)
    vdom = options.source_vdom or (vdoms[0] if len(vdoms) == 1 else None)
    return replace(options, source_vdom=vdom,
                   management_api_version=options.management_api_version or "1.8.1",
                   policy_package=options.policy_package or (target_name("package", vdom, vdom) if vdom else None),
                   access_layer=None, insertion_anchor=None, insertion_relation=None,
                   target_cleanup_action=None)
