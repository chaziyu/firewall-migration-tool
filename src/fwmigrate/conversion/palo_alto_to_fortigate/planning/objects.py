"""Restricted lossless object conversion to FortiOS sections."""
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network
import re

from .context import unsupported_fields
from .source_scope import in_scope


def plan_addresses(ctx):
    result = []
    for obj in ctx.source.addresses:
        if not in_scope(obj, ctx.scope):
            continue
        reasons = unsupported_fields(obj, {"ip_netmask", "ip_range", "fqdn"})
        settings = {}
        if sum(value is not None for value in (obj.ip_netmask, obj.ip_range, obj.fqdn, obj.ip_wildcard)) != 1:
            reasons.append("Exactly one supported explicit address type is required.")
        try:
            if obj.ip_netmask is not None:
                net = IPv4Network(obj.ip_netmask, strict=False)
                settings = {"type": "ipmask", "subnet": (str(net.network_address), str(net.netmask))}
            elif obj.ip_range is not None:
                start, end = obj.ip_range.split("-")
                if IPv4Address(start) > IPv4Address(end):
                    raise ValueError
                settings = {"type": "iprange", "start-ip": start, "end-ip": end}
            elif obj.fqdn is not None and re.fullmatch(r"[A-Za-z0-9_.-]{1,253}", obj.fqdn):
                settings = {"type": "fqdn", "fqdn": obj.fqdn}
            else:
                reasons.append("Address type or value is unsupported.")
        except ValueError:
            reasons.append("Malformed IPv4 address value.")
        if obj.description is not None:
            settings["comment"] = obj.description
        result.append(ctx.item(obj, "address", "firewall address", settings, reasons=reasons))
    for obj in ctx.source.address_groups:
        if not in_scope(obj, ctx.scope):
            continue
        values, deps, errors = ctx.resolve(obj, "static_members", obj.static_members, ("address", "address_group"))
        reasons = unsupported_fields(obj, {"static_members"}) + list(errors)
        if obj.dynamic_filter is not None:
            reasons.append("Dynamic address groups require manual implementation.")
        result.append(ctx.item(obj, "address_group", "firewall addrgrp", {"member": values}, deps, reasons))
    return result


def ports(value):
    if not isinstance(value, str):
        raise ValueError("Missing explicit destination ports")
    result = []
    for entry in value.split(","):
        if not re.fullmatch(r"\d+(?:-\d+)?", entry):
            raise ValueError("Unsupported service port syntax")
        numbers = [int(n) for n in entry.split("-")]
        if any(not 1 <= n <= 65535 for n in numbers) or numbers[0] > numbers[-1]:
            raise ValueError("Invalid service port range")
        result.append(entry)
    return result


def plan_services(ctx):
    result = []
    for obj in ctx.source.services:
        if not in_scope(obj, ctx.scope):
            continue
        reasons = unsupported_fields(obj, {"tcp", "udp"})
        settings = {"protocol": "TCP/UDP/SCTP"}
        if (obj.tcp is None) == (obj.udp is None):
            reasons.append("Exactly one TCP or UDP branch is required.")
        for protocol in ("tcp", "udp"):
            branch = getattr(obj, protocol)
            if branch is None:
                continue
            if branch.raw_extra or branch.override is not None:
                reasons.append("Service overrides or unknown protocol settings are unsupported.")
            try:
                destinations = ports(branch.port)
                sources = ports(branch.source_port) if branch.source_port is not None else [None]
                if len(sources) > 1:
                    raise ValueError("Multiple source-port intervals require manual conversion")
                settings[protocol + "-portrange"] = tuple(p + (":" + sources[0] if sources[0] else "") for p in destinations)
            except ValueError as exc:
                reasons.append(str(exc))
        result.append(ctx.item(obj, "service", "firewall service custom", settings, reasons=reasons))
    for obj in ctx.source.service_groups:
        if not in_scope(obj, ctx.scope):
            continue
        values, deps, errors = ctx.resolve(obj, "members", obj.members, ("service", "service_group"))
        result.append(ctx.item(obj, "service_group", "firewall service group", {"member": values}, deps,
                               unsupported_fields(obj, {"members"}) + list(errors)))
    return result


def plan_schedules(ctx):
    result = []
    for obj in ctx.source.schedules:
        if not in_scope(obj, ctx.scope):
            continue
        reasons = unsupported_fields(obj, {"recurring", "non_recurring"})
        # No timezone conversion: the engineer must confirm the same local clock context on both firewalls.
        if not re.fullmatch(r"UTC|[A-Za-z_+-]+(?:/[A-Za-z0-9_+-]+){1,2}", ctx.options.timezone):
            reasons.append("Confirm matching source and destination timezone identifiers before schedule conversion.")
        settings, section = {}, "firewall schedule recurring"
        if obj.recurring is not None and obj.non_recurring is None:
            recurring = obj.recurring
            if recurring.raw_extra:
                reasons.append("Unsupported recurring schedule settings.")
            days = ("sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday")
            intervals = recurring.daily
            selected = days
            if recurring.weekly is not None and recurring.daily is None:
                selected = tuple(day for day in days if day in recurring.weekly)
                unique = {tuple(v) for v in recurring.weekly.values()}
                intervals = list(next(iter(unique))) if len(unique) == 1 else None
            if not selected or not intervals or len(intervals) != 1 or not re.fullmatch(r"\d{2}:\d{2}-\d{2}:\d{2}", intervals[0]):
                reasons.append("Only a single uniform recurring time interval is supported.")
            else:
                start, end = intervals[0].split("-")
                try:
                    datetime.strptime(start, "%H:%M")
                    datetime.strptime(end, "%H:%M")
                    if start >= end:
                        raise ValueError
                    settings = {"day": selected, "start": start, "end": end}
                except ValueError:
                    reasons.append("Invalid or overnight recurring interval.")
        elif obj.non_recurring is not None and obj.recurring is None and len(obj.non_recurring) == 1:
            section = "firewall schedule onetime"
            try:
                start, end = [datetime.strptime(v, "%Y/%m/%d@%H:%M") for v in obj.non_recurring[0].split("-")]
                if start >= end:
                    raise ValueError
                settings = {"start": (start.strftime("%H:%M"), start.strftime("%Y/%m/%d")),
                            "end": (end.strftime("%H:%M"), end.strftime("%Y/%m/%d"))}
            except ValueError:
                reasons.append("Invalid one-time schedule interval.")
        else:
            reasons.append("Schedule structure is unsupported or missing.")
        result.append(ctx.item(obj, "schedule", section, settings, reasons=reasons))
    return result
