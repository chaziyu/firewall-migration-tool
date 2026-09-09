"""PAN-OS predefined service references."""

PAN_PREDEFINED_SERVICES = frozenset({"service-http", "service-https"})
PAN_RULE_SERVICE_BUILTINS = frozenset({"any", "application-default"}) | PAN_PREDEFINED_SERVICES
