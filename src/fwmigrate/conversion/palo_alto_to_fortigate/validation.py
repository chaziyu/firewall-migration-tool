"""Detect invalid FortiOS plans without repairing them."""
import re
from .options import safe_text
from .plan_dependencies import render_blockers


def validate_plan(plan):
    required = {
        "firewall address": {"type"}, "firewall addrgrp": {"member"}, "firewall service custom": {"protocol"},
        "firewall service group": {"member"}, "firewall schedule recurring": {"day", "start", "end"},
        "firewall schedule onetime": {"start", "end"}, "system interface": {"ip"}, "system zone": {"interface", "intrazone"},
        "router static": {"dst", "gateway", "distance", "device"}, "firewall ippool": {"type", "startip", "endip", "arp-reply"},
        "firewall policy": {"action", "srcintf", "dstintf", "srcaddr", "dstaddr", "service", "schedule", "status", "nat", "utm-status"},
        "firewall central-snat-map": {"orig-addr", "dst-addr", "srcintf", "dstintf", "status", "nat"},
        "firewall vip": {"type", "extip", "mappedip", "extintf", "srcintf-filter", "status", "portforward", "arp-reply", "nat-source-vip"},
    }
    keys = set()
    targets = set()
    for item in plan.items:
        if item.key in keys:
            raise ValueError("Duplicate migration item identity")
        keys.add(item.key)
        target = (item.global_scope, item.target_vdom, item.section, item.target_name)
        if target in targets and item.family != "manual":
            raise ValueError("Conflicting target ownership or names")
        targets.add(target)
        if item.disposition not in {"CREATE", "CONFIGURE", "REUSE", "BLOCK"}:
            raise ValueError("Invalid render disposition")
        if not item.reasons and not plan.findings and item.disposition != "BLOCK":
            settings = dict(item.settings)
            if item.section not in required or required[item.section] - set(settings) or any(not values for values in settings.values()):
                raise ValueError("Incomplete or unsupported target command section")
            if item.section == "firewall address" and not {"subnet", "start-ip", "fqdn"} & set(settings):
                raise ValueError("Address requires an explicit target value")
            if item.section == "firewall service custom" and not {"tcp-portrange", "udp-portrange"} & set(settings):
                raise ValueError("Service requires explicit target ports")
        safe_text(item.target_name)
        if item.target_vdom:
            safe_text(item.target_vdom)
        for key, values in item.settings:
            if not re.fullmatch(r"[a-z0-9-]+", key):
                raise ValueError("Invalid target CLI field")
            for value in values:
                safe_text(value, limit=4096, allow_empty=True)
    return render_blockers(plan)
