"""Create a separate package and an explicit Drop anchor for new targets."""

from ..models import CPMigrationItem
from .naming import item_key, target_name


def package_keys(scope):
    return (item_key(scope, "package", "new"), item_key(scope, "cleanup", "new"),
            item_key(scope, "layer", "new"))


def plan_new_package(scope, options, context_blockers):
    package_key, cleanup_key, layer_key = package_keys(scope)
    layer = {"$response_binding": f"{package_key}.layer_uid"}
    package = CPMigrationItem(package_key, "package", scope, scope, options.policy_package,
        (("management_operation", {
            "path": "/web_api/add-package",
            "request_body_template": {"name": options.policy_package, "access": True,
                                      "threat-prevention": False, "details-level": "full"},
            "response_binding": {"binding_id": f"{package_key}.layer_uid",
                                 "json_pointer": "/access-layers/0/uid", "value_type": "layer_uid"},
        }),), blockers=tuple(context_blockers))
    configured_layer = CPMigrationItem(layer_key, "layer", scope, "New firewall layer",
        target_name("layer", scope, "new"), (("management_operation", {
            "path": "/web_api/set-access-layer",
            "request_body_template": {"uid": layer, "firewall": True,
                "applications-and-url-filtering": False, "content-awareness": False,
                "mobile-access": False, "detect-using-x-forward-for": False,
                "implicit-cleanup-action": "drop", "shared": False, "details-level": "full"},
            "response_binding": {"binding_id": layer_key + ".uid", "json_pointer": "/uid", "value_type": "layer_uid"},
        }),), dependencies=(package_key,), blockers=tuple(context_blockers))
    cleanup = CPMigrationItem(cleanup_key, "cleanup", scope, "New Drop cleanup",
        target_name("cleanup", scope, "drop"), (("management_operation", {
            "path": "/web_api/add-access-rule",
            "request_body_template": {"layer": layer, "position": "top",
                "name": target_name("cleanup", scope, "drop"), "action": "Drop",
                "source": ["Any"], "destination": ["Any"], "service": ["Any"],
                "source-negate": False, "destination-negate": False, "service-negate": False,
                "enabled": True, "time": ["Any"], "vpn": "Any",
                "install-on": list(options.install_on) or ["Policy Targets"], "track": {"type": "None"}},
            "response_binding": {"binding_id": f"{cleanup_key}.uid",
                                 "json_pointer": "/uid", "value_type": "rule_uid"},
        }),), dependencies=(package_key, layer_key), blockers=tuple(context_blockers))
    return [package, configured_layer, cleanup]
