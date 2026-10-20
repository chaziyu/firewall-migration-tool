"""Create a separate package and an explicit Drop anchor for new targets."""

from ..models import CPMigrationItem
from .naming import item_key, target_name


def package_keys(vdom):
    return item_key(vdom, "package", "new"), item_key(vdom, "cleanup", "new")


def plan_new_package(vdom, options, context_blockers):
    package_key, cleanup_key = package_keys(vdom)
    layer = {"$response_binding": f"{package_key}.layer_uid"}
    package = CPMigrationItem(package_key, "package", vdom, vdom, options.policy_package,
        (("management_operation", {
            "path": "/web_api/add-package",
            "request_body_template": {"name": options.policy_package, "access": True,
                                      "threat-prevention": False, "details-level": "full"},
            "response_binding": {"binding_id": f"{package_key}.layer_uid",
                                 "json_pointer": "/access-layers/0/uid", "value_type": "layer_uid"},
        }),), blockers=tuple(context_blockers))
    cleanup = CPMigrationItem(cleanup_key, "cleanup", vdom, "New Drop cleanup",
        target_name("cleanup", vdom, "drop"), (("management_operation", {
            "path": "/web_api/add-access-rule",
            "request_body_template": {"layer": layer, "position": "top",
                "name": target_name("cleanup", vdom, "drop"), "action": "Drop",
                "source": ["Any"], "destination": ["Any"], "service": ["Any"],
                "source-negate": False, "destination-negate": False, "service-negate": False,
                "enabled": True, "time": ["Any"], "vpn": "Any",
                "install-on": list(options.install_on) or ["Policy Targets"], "track": {"type": "None"}},
            "response_binding": {"binding_id": f"{cleanup_key}.uid",
                                 "json_pointer": "/uid", "value_type": "rule_uid"},
        }),), dependencies=(package_key,))
    return [package, cleanup]
