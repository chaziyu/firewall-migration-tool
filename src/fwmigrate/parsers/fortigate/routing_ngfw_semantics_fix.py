"""FortiGate static-route and policy-based NGFW semantic corrections.

This installer composes with the existing FortiGate extension stack. It preserves
FortiOS-only source semantics without widening portable policy intent.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Optional

from fwmigrate.ir.core import IRFortiGateSourceRule


_PREMATCH_FAMILY = "ngfw-pre-match-policy"
_POLICY_BASED_REVIEW = (
    "VDOM uses policy-based NGFW mode; firewall policy is an SSL inspection/"
    "authentication pre-match rule and is not portable firewall-policy intent"
)


def _is_policy_based(transformer: Any, policy: Any) -> bool:
    if str(getattr(policy, "ngfw_mode", "") or "").strip().lower() == "policy-based":
        return True

    source_context = getattr(policy, "source_context", "root")
    for context in getattr(transformer.fg, "execution_contexts", []) or []:
        if (
            getattr(context, "vdom", "root") == source_context
            and str(getattr(context, "ngfw_mode", "") or "").strip().lower()
            == "policy-based"
        ):
            return True
    return False


def _structured_policy_source(transformer: Any, policy: Any) -> Optional[Any]:
    source_id = str(getattr(policy, "id", ""))
    source_context = getattr(policy, "source_context", "root")
    for source_object in getattr(transformer.fg, "structured_source_objects", []) or []:
        if (
            getattr(source_object, "source_path", None) == "firewall policy"
            and getattr(source_object, "source_context", "root") == source_context
            and str(getattr(source_object, "source_id", "") or "") == source_id
        ):
            return source_object
    return None


def _explicit_command_keys(source_object: Optional[Any]) -> set[str]:
    if source_object is None:
        return set()
    root = getattr(source_object, "root", None)
    return {
        str(getattr(command, "key", "") or "").strip().lower()
        for command in getattr(root, "commands", []) or []
        if str(getattr(command, "operation", "") or "").strip().lower() in {"set", "unset"}
    }


def _pre_match_attributes(transformer: Any, policy: Any) -> dict[str, Any]:
    attributes: dict[str, Any] = {}
    list_fields = (
        "srcintf",
        "dstintf",
        "srcaddr",
        "dstaddr",
        "srcaddr6",
        "dstaddr6",
        "service",
        "users",
        "groups",
        "fsso_groups",
    )
    scalar_fields = (
        "uuid",
        "ssl_ssh_profile",
        "inspection_mode",
        "profile_protocol_options",
        "auth_cert",
        "auth_path",
        "auth_redirect_addr",
        "comments",
    )

    for field in list_fields:
        value = getattr(policy, field, None)
        if value:
            attributes[field] = list(value)
    for field in scalar_fields:
        value = getattr(policy, field, None)
        if value not in (None, ""):
            attributes[field] = value

    extra_settings = dict(getattr(policy, "extra_settings", {}) or {})
    if extra_settings:
        attributes["extra_settings"] = extra_settings

    source_object = _structured_policy_source(transformer, policy)
    if source_object is not None:
        attributes["source_tree"] = source_object.root.model_dump()

    # Do not copy policy.action or policy.schedule from the typed model here.
    # FGPolicy historically contains a profile-mode action default. In policy-
    # based NGFW mode that default is not valid pre-match semantics. Exact source
    # commands remain available above in source_tree.
    return attributes


def _pre_match_rule(
    transformer: Any,
    policy: Any,
    source_order: int,
) -> IRFortiGateSourceRule:
    source_object = _structured_policy_source(transformer, policy)
    explicit_keys = _explicit_command_keys(source_object)
    review_reasons = [_POLICY_BASED_REVIEW]
    if "action" in explicit_keys:
        review_reasons.append(
            "policy-based NGFW pre-match contains an action command; retained as source evidence only"
        )
    if "schedule" in explicit_keys:
        review_reasons.append(
            "policy-based NGFW pre-match contains a schedule command; retained as source evidence only"
        )

    return IRFortiGateSourceRule(
        family=_PREMATCH_FAMILY,
        source_id=str(policy.id),
        name=policy.name,
        source_order=source_order,
        source_context=getattr(policy, "source_context", "root"),
        enabled=str(getattr(policy, "status", "enable") or "enable").lower() != "disable",
        effective_action=None,
        source_attributes=_pre_match_attributes(transformer, policy),
        migration_status="EXTRACT_ONLY",
        requires_manual_review=True,
        review_reasons=review_reasons,
    )


def install_routing_ngfw_semantics_fix(transformer_module: Any) -> None:
    """Install lossless static6 devindex and policy-based NGFW pre-match handling."""
    transformer_cls = transformer_module.FGToIRTransformer

    original_transform_policies = transformer_cls._transform_policies
    if getattr(original_transform_policies, "_routing_ngfw_semantics_fix", False):
        return

    original_transform_nat = transformer_cls._transform_nat
    original_transform_routes = transformer_cls._transform_routes

    def _portable_policies(transformer: Any, policies: list[Any]) -> list[Any]:
        return [
            policy
            for policy in policies
            if not _is_policy_based(transformer, policy)
        ]

    def _transform_policies(self: Any) -> None:
        all_policies = list(self.fg.policies)
        portable_policies = _portable_policies(self, all_policies)
        context_order: dict[str, int] = defaultdict(int)

        self.fg.policies = portable_policies
        try:
            original_transform_policies(self)
        finally:
            self.fg.policies = all_policies

        for policy in all_policies:
            context = getattr(policy, "source_context", "root")
            context_order[context] += 1
            if _is_policy_based(self, policy):
                self.ir.source_only_rules.append(
                    _pre_match_rule(self, policy, context_order[context])
                )

    def _transform_nat(self: Any) -> None:
        # The legacy NAT transform correlates source policies with ir.policies
        # positionally. Once policy-based pre-match rules are withheld from
        # ir.policies, filter the source side identically so positional pairing
        # cannot cross VDOM/mode boundaries.
        all_policies = list(self.fg.policies)
        self.fg.policies = _portable_policies(self, all_policies)
        try:
            original_transform_nat(self)
        finally:
            self.fg.policies = all_policies

    def _transform_routes(self: Any) -> None:
        original_transform_routes(self)

        source_routes: dict[tuple[str, int], Any] = {
            (getattr(route, "source_context", "root"), route.id): route
            for route in self.fg.static_routes
        }
        for ir_route in self.ir.routes:
            source_route_id = getattr(ir_route, "source_route_id", None)
            if source_route_id is None:
                continue
            source_route = source_routes.get(
                (
                    getattr(ir_route, "source_context", "root"),
                    source_route_id,
                )
            )
            if source_route is None or getattr(source_route, "address_family", "ipv4") != "ipv6":
                continue

            devindex = getattr(source_route, "devindex", None)
            if devindex is not None:
                # source_attributes is already part of canonical IR provenance.
                # Keep devindex source-specific rather than inventing a portable
                # route/interface semantic.
                ir_route.source_attributes["devindex"] = devindex

    _transform_policies._routing_ngfw_semantics_fix = True
    _transform_nat._routing_ngfw_semantics_fix = True
    _transform_routes._routing_ngfw_semantics_fix = True

    transformer_cls._transform_policies = _transform_policies
    transformer_cls._transform_nat = _transform_nat
    transformer_cls._transform_routes = _transform_routes
