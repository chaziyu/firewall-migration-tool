"""FortiOS 7.4.6 firewall IP resource contract."""

FORTIOS_746_IPPOOL_TYPES = frozenset({
    "overload",
    "one-to-one",
    "fixed-port-range",
    "port-block-allocation",
    "cgn-resource-allocation",
})

FORTIOS_746_IPPOOL_FIELDS = frozenset({
    "add_nat64_route",
    "arp_intf",
    "arp_reply",
    "associated_interface",
    "block_size",
    "cgn_block_size",
    "cgn_client_endip",
    "cgn_client_ipv6shift",
    "cgn_client_startip",
    "cgn_fixedalloc",
    "cgn_overload",
    "cgn_port_end",
    "cgn_port_start",
    "cgn_spa",
    "comments",
    "endip",
    "endport",
    "exclude_ip",
    "nat64",
    "num_blocks_per_user",
    "pba_interim_log",
    "pba_timeout",
    "permit_any_host",
    "port_per_user",
    "source_endip",
    "source_startip",
    "startip",
    "startport",
    "subnet_broadcast_in_ippool",
    "type",
    "utilization_alarm_clear",
    "utilization_alarm_raise",
})

FORTIOS_746_IPPOOL_INT_RANGES = {
    "block_size": (64, 4096),
    "cgn_block_size": (64, 4096),
    "cgn_client_ipv6shift": (0, 127),
    "cgn_port_start": (1024, 65535),
    "cgn_port_end": (1024, 65535),
    "endport": (5117, 65533),
    "num_blocks_per_user": (1, 128),
    "pba_timeout": (3, 86400),
    "startport": (5117, 65533),
    "utilization_alarm_clear": (40, 100),
    "utilization_alarm_raise": (50, 100),
}

FORTIOS_746_IPPOOL_ZERO_OR_RANGES = {
    "pba_interim_log": (600, 86400),
    "port_per_user": (32, 60417),
}

FORTIOS_746_IPPOOL_DEFAULTS = {
    "add_nat64_route": "enable",
    "arp_reply": "enable",
    "block_size": 128,
    "cgn_block_size": 128,
    "cgn_client_ipv6shift": 0,
    "cgn_fixedalloc": "disable",
    "cgn_overload": "disable",
    "cgn_port_start": 5117,
    "cgn_port_end": 65530,
    "cgn_spa": "disable",
    "endip": "0.0.0.0",
    "endport": 65533,
    "nat64": "disable",
    "num_blocks_per_user": 8,
    "pba_interim_log": 0,
    "pba_timeout": 30,
    "permit_any_host": "disable",
    "port_per_user": 0,
    "source_startip": "0.0.0.0",
    "source_endip": "0.0.0.0",
    "startip": "0.0.0.0",
    "startport": 5117,
    "subnet_broadcast_in_ippool": "enable",
    "type": "overload",
    "utilization_alarm_clear": 80,
    "utilization_alarm_raise": 100,
}

FORTIOS_746_IPPOOL6_FIELDS = frozenset({
    "add_nat46_route",
    "comments",
    "endip",
    "nat46",
    "startip",
})

FORTIOS_746_IPPOOL6_DEFAULTS = {
    "add_nat46_route": "enable",
    "endip": "::",
    "nat46": "disable",
    "startip": "::",
}

