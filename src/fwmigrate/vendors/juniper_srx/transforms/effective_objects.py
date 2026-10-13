"""Typed, read-only effective Junos object inventory.

This transform evaluates sanitized effective SET statements into a private
vendor-native config solely to project derived rows. The returned rows are
plain dictionaries and never replace or mutate explicit VendorConfig state.
"""

from __future__ import annotations

from copy import deepcopy
import shlex
from typing import Any

from ..activation import JunosActivationState
from ..extraction import sanitize_tokens
from ..group_resolver import resolve_group_commands
from ..group_syntax import is_group_command
from ..parser import JuniperSRXParser
from ..tokenizer import JunosOperation


def _scope(context) -> str:
    return "root" if context.context_type == "root" else f"{context.context_type} {context.name}"


def _context(config, context):
    return config.contexts.get(config.context_storage_key(context.name, context.context_type))


def _effective_config(source_commands):
    commands = deepcopy(list(source_commands))
    if not commands:
        return None

    activation = JunosActivationState()
    activation.apply(deepcopy(commands))
    resolved = resolve_group_commands(commands)
    lines: list[str] = []
    for command in resolved:
        if command.operation is not JunosOperation.SET or command.access_denied:
            continue
        if is_group_command(command.tokens[1:]):
            continue
        path = tuple(command.target_path or command.tokens[1:])
        if activation.is_inactive(path):
            continue
        safe = sanitize_tokens(command.tokens)
        lines.append(shlex.join(safe))

    if not lines:
        return None
    return JuniperSRXParser("\n".join(lines)).extract_source()


def _attributes(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return value.model_dump(
            mode="json",
            exclude={
                "field_provenance",
                "field_candidate_history",
                "member_candidate_history",
                "non_effective_candidate_history",
                "provenance",
            },
        )
    return dict(getattr(value, "__dict__", {}))


def build_effective_object_views(explicit_config, source_commands=()) -> tuple[dict[str, Any], ...]:
    """Return typed effective-object rows, clearly separated from explicit source."""
    effective = _effective_config(source_commands)
    if effective is None:
        return ()

    rows: list[dict[str, Any]] = []

    def add(context, object_type, name, value, explicit: bool, owner=None):
        rows.append({
            "context": _scope(context),
            "object_type": object_type,
            "name": name,
            "owner": owner,
            "source_presence": "EXPLICIT" if explicit else "INHERITED_ONLY",
            "attributes": _attributes(value),
        })

    for context in effective.iter_contexts():
        explicit_context = _context(explicit_config, context)

        for name, item in context.interfaces.items():
            add(context, "interface", name, item,
                bool(explicit_context and name in explicit_context.interfaces))
        for name, item in context.zones.items():
            add(context, "security-zone", name, item,
                bool(explicit_context and name in explicit_context.zones))

        for book_name, book in context.address_books.items():
            explicit_book = (
                explicit_context.address_books.get(book_name)
                if explicit_context else None
            )
            for name, item in book.addresses.items():
                add(context, "address", name, item,
                    bool(explicit_book and name in explicit_book.addresses), book_name)
            for name, item in book.address_sets.items():
                add(context, "address-set", name, item,
                    bool(explicit_book and name in explicit_book.address_sets), book_name)

        for name, item in context.applications.items():
            add(context, "application", name, item,
                bool(explicit_context and name in explicit_context.applications))
        for name, item in context.application_sets.items():
            add(context, "application-set", name, item,
                bool(explicit_context and name in explicit_context.application_sets))
        for name, item in context.schedulers.items():
            add(context, "scheduler", name, item,
                bool(explicit_context and name in explicit_context.schedulers))

        explicit_policy_keys = set()
        if explicit_context:
            explicit_policy_keys = {
                (item.policy_scope, item.from_zone, item.to_zone, item.name)
                for item in (*explicit_context.policies, *explicit_context.global_policies)
            }
        for item in (*context.policies, *context.global_policies):
            key = (item.policy_scope, item.from_zone, item.to_zone, item.name)
            add(context, "security-policy", item.name, item, key in explicit_policy_keys,
                f"{item.from_zone or '*'}->{item.to_zone or '*'}")

        for nat_type, pools, rule_sets in (
            ("source", context.nat.source_pools, context.nat.source_rule_sets),
            ("destination", context.nat.destination_pools, context.nat.destination_rule_sets),
            ("static", {}, context.nat.static_rule_sets),
        ):
            explicit_nat = explicit_context.nat if explicit_context else None
            explicit_pools = (
                explicit_nat.source_pools if explicit_nat and nat_type == "source"
                else explicit_nat.destination_pools if explicit_nat and nat_type == "destination"
                else {}
            )
            explicit_sets = (
                explicit_nat.source_rule_sets if explicit_nat and nat_type == "source"
                else explicit_nat.destination_rule_sets if explicit_nat and nat_type == "destination"
                else explicit_nat.static_rule_sets if explicit_nat else {}
            )
            for name, item in pools.items():
                add(context, f"{nat_type}-nat-pool", name, item, name in explicit_pools)
            for set_name, rule_set in rule_sets.items():
                explicit_set = explicit_sets.get(set_name)
                explicit_rules = {rule.name for rule in explicit_set.rules} if explicit_set else set()
                for rule in rule_set.rules:
                    add(context, f"{nat_type}-nat-rule", rule.name, rule,
                        rule.name in explicit_rules, set_name)

        explicit_routes = {
            (item.routing_instance, item.rib, item.destination)
            for item in explicit_context.routes
        } if explicit_context else set()
        for item in context.routes:
            key = (item.routing_instance, item.rib, item.destination)
            add(context, "static-route", item.destination, item, key in explicit_routes,
                item.routing_instance or item.rib)

        vpn_pairs = (
            ("ike-proposal", context.vpn.ike_proposals, explicit_context.vpn.ike_proposals if explicit_context else {}),
            ("ike-policy", context.vpn.ike_policies, explicit_context.vpn.ike_policies if explicit_context else {}),
            ("ike-gateway", context.vpn.ike_gateways, explicit_context.vpn.ike_gateways if explicit_context else {}),
            ("ipsec-proposal", context.vpn.ipsec_proposals, explicit_context.vpn.ipsec_proposals if explicit_context else {}),
            ("ipsec-policy", context.vpn.ipsec_policies, explicit_context.vpn.ipsec_policies if explicit_context else {}),
            ("ipsec-vpn", context.vpn.ipsec_vpns, explicit_context.vpn.ipsec_vpns if explicit_context else {}),
        )
        for object_type, values, explicit_values in vpn_pairs:
            for name, item in values.items():
                add(context, object_type, name, item, name in explicit_values)

        profile_pairs = (
            ("utm-policy", context.utm_policies, explicit_context.utm_policies if explicit_context else {}),
            ("idp-policy", context.idp_policies, explicit_context.idp_policies if explicit_context else {}),
            ("antivirus-profile", context.antivirus_profiles, explicit_context.antivirus_profiles if explicit_context else {}),
            ("web-filtering-profile", context.web_filtering_profiles, explicit_context.web_filtering_profiles if explicit_context else {}),
            ("content-filtering-profile", context.content_filtering_profiles, explicit_context.content_filtering_profiles if explicit_context else {}),
            ("anti-spam-profile", context.anti_spam_profiles, explicit_context.anti_spam_profiles if explicit_context else {}),
        )
        for object_type, values, explicit_values in profile_pairs:
            for name, item in values.items():
                add(context, object_type, name, item, name in explicit_values)

    return tuple(rows)
