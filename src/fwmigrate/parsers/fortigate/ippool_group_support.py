"""FortiGate IP-pool group extraction and fail-closed NAT correlation.

FortiOS ``config firewall ippool_grp`` groups named IPv4 IP pools.  The group
is retained as typed source/canonical evidence, but it is not flattened into a
portable translated address range because target-neutral equivalence is not
proven.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field, SerializeAsAny

from fwmigrate.parsers.fortigate import model as model_module
from fwmigrate.parsers.fortigate.model import FGContextualModel


IPPOOL_GROUP_REVIEW_REASON = (
    "FortiGate IP-pool group semantics are retained for inventory and "
    "correlation only; target NAT translation is withheld."
)


class FGIPPoolGroup(FGContextualModel):
    """Typed FortiOS ``config firewall ippool_grp`` source object."""

    name: str
    member: List[str] = Field(default_factory=list)
    source_explicit_fields: Set[str] = Field(default_factory=set)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class IRIPPoolGroup(BaseModel):
    """Canonical source-preserving IP-pool group inventory."""

    name: str
    source_context: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    unresolved_members: List[str] = Field(default_factory=list)
    source_explicit_fields: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


def _mark_nat_rule_for_group_review(rule: Any, reason: str) -> None:
    rule.requires_manual_review = True
    rule.migration_status = "PARTIALLY_NORMALIZED"
    reasons = list(getattr(rule, "review_reasons", []) or [])
    if reason not in reasons:
        reasons.append(reason)
    rule.review_reasons = reasons


def _source_policy_map(transformer: Any) -> Dict[tuple[str, str], Any]:
    return {
        (
            str(getattr(policy, "source_context", "root") or "root"),
            str(getattr(policy, "id", "")),
        ): policy
        for policy in getattr(transformer.fg, "policies", []) or []
    }


def install_ippool_group_support(
    parser_module: Any,
    transformer_module: Any,
    dependencies_module: Any,
    coverage_module: Any,
    extractor_module: Any,
) -> None:
    """Install typed IP-pool-group support on the final FortiGate adapter."""

    parser_cls = parser_module.FortiGateParser
    if getattr(parser_cls.build_model, "_ippool_group_support", False):
        return

    active_fg_root = parser_module.FGConfig

    class FGConfigIPPoolGroups(active_fg_root):
        ip_pool_groups: List[SerializeAsAny[FGIPPoolGroup]] = Field(
            default_factory=list
        )

    active_nat_rule = transformer_module.IRNATRule

    class IRNATRuleIPPoolGroup(active_nat_rule):
        source_pool_group_references: List[str] = Field(default_factory=list)

    active_ir_root = transformer_module.IRConfig

    class IRConfigIPPoolGroups(active_ir_root):
        ip_pool_groups: List[SerializeAsAny[IRIPPoolGroup]] = Field(
            default_factory=list
        )
        nat_rules: List[SerializeAsAny[IRNATRuleIPPoolGroup]] = Field(
            default_factory=list
        )

    # Bind the final active source/IR models before any parser/transformer
    # instance is constructed.  The subclasses are strict supersets of the
    # already-installed FortiGate specializations.
    model_module.FGConfig = FGConfigIPPoolGroups
    parser_module.FGConfig = FGConfigIPPoolGroups
    parser_module.FGIPPoolGroup = FGIPPoolGroup
    transformer_module.IRNATRule = IRNATRuleIPPoolGroup
    transformer_module.IRConfig = IRConfigIPPoolGroups

    parser_module.CONTEXTUAL_MODEL_SECTIONS.add("firewall ippool_grp")
    parser_module.SECTION_EXPLICIT_FIELDS["firewall ippool_grp"] = {"member"}
    parser_module.SECTION_LIST_FIELDS.setdefault(
        "firewall ippool_grp", set()
    ).add("member")

    original_init = parser_cls.__init__

    def __init__(self: Any, tokenizer: Any) -> None:
        original_init(self, tokenizer)
        # Parsing has not started yet.  Replace only the empty root object with
        # a strict superset so all earlier extension fields remain available.
        self.config = FGConfigIPPoolGroups()

    __init__._ippool_group_support = True
    parser_cls.__init__ = __init__

    original_build_model = parser_cls.build_model

    def build_model(
        self: Any,
        section_path: str,
        attributes: Dict[str, Any],
    ) -> Any:
        if section_path == "firewall ippool_grp":
            attributes["extra_settings"] = parser_module._extract_extra_settings(
                attributes,
                set(FGIPPoolGroup.model_fields),
            )
            self.config.ip_pool_groups.append(FGIPPoolGroup(**attributes))
            return None
        return original_build_model(self, section_path, attributes)

    build_model._ippool_group_support = True
    parser_cls.build_model = build_model

    # Source accounting remains explicit and source-only.  The canonical group
    # exists to preserve evidence; it is not portable target NAT semantics.
    coverage_module.TYPED_SECTIONS.add("firewall ippool_grp")
    if hasattr(coverage_module, "TYPED_EXTRACT_ONLY_SECTIONS"):
        coverage_module.TYPED_EXTRACT_ONLY_SECTIONS.add("firewall ippool_grp")
    if hasattr(coverage_module, "SEMANTIC_SUPPORT_LEVELS"):
        coverage_module.SEMANTIC_SUPPORT_LEVELS[
            "firewall ippool_grp"
        ] = "TYPED_EXTRACT_ONLY"
    if hasattr(coverage_module, "_COLLECTIONS"):
        coverage_module._COLLECTIONS[
            "firewall ippool_grp"
        ] = ("ip_pool_groups", "ip_pool_groups")

    original_classify = coverage_module.classify_section_coverage

    def classify_with_ippool_groups(
        source_sections: list[Any],
        fg_config: Any,
        ir_config: Any,
    ) -> None:
        original_classify(source_sections, fg_config, ir_config)
        for section in source_sections:
            if section.path != "firewall ippool_grp":
                continue
            context = section.source_context or "root"
            parsed = [
                group
                for group in getattr(fg_config, "ip_pool_groups", []) or []
                if (getattr(group, "source_context", "root") or "root") == context
            ]
            section.object_count_parsed = len(parsed)
            section.object_count_normalized = None
            section.status = coverage_module.ExtractionStatus.EXTRACT_ONLY
            section.parser_handler = "FortiGateParser.build_model"
            note = (
                "Typed FortiGate IP-pool groups are preserved as source-only "
                "NAT inventory and dependency evidence."
            )
            if note not in section.notes:
                section.notes.append(note)

    classify_with_ippool_groups._ippool_group_support = True
    coverage_module.classify_section_coverage = classify_with_ippool_groups
    extractor_module.classify_section_coverage = classify_with_ippool_groups

    # Group members are always IPv4 pools.  Policy poolname may legally name a
    # pool group; the final dependency safety wrapper will keep same-context
    # pool-vs-group name collisions unresolved instead of selecting one.
    group_source_path = "firewall ippool-grp"
    dependencies_module.REFERENCE_RULES[
        (group_source_path, "member")
    ] = "firewall ippool"
    dependencies_module.REFERENCE_TARGET_SECTIONS[
        (group_source_path, "member")
    ] = {"firewall ippool"}
    dependencies_module.REFERENCE_TARGET_SECTIONS.setdefault(
        ("firewall policy", "poolname"),
        {"firewall ippool"},
    ).add("firewall ippool_grp")

    transformer_cls = transformer_module.FGToIRTransformer
    original_transform_ip_pools = transformer_cls._transform_ip_pools

    def _transform_ip_pools(self: Any) -> None:
        original_transform_ip_pools(self)
        pool_keys = {
            (
                str(getattr(pool, "source_context", "root") or "root"),
                str(pool.name),
            )
            for pool in getattr(self.fg, "ip_pools", []) or []
        }
        for group in getattr(self.fg, "ip_pool_groups", []) or []:
            context = str(getattr(group, "source_context", "root") or "root")
            unresolved = [
                member
                for member in group.member
                if (context, str(member)) not in pool_keys
            ]
            reasons = [IPPOOL_GROUP_REVIEW_REASON]
            if unresolved:
                reasons.append(
                    "Unresolved same-context IP-pool members: "
                    + ", ".join(str(member) for member in unresolved)
                    + "."
                )
            self.ir.ip_pool_groups.append(
                IRIPPoolGroup(
                    name=group.name,
                    source_context=context,
                    members=list(group.member),
                    unresolved_members=unresolved,
                    source_explicit_fields=sorted(group.source_explicit_fields),
                    review_reasons=reasons,
                    source_attributes=dict(group.extra_settings),
                )
            )

    _transform_ip_pools._ippool_group_support = True
    transformer_cls._transform_ip_pools = _transform_ip_pools

    original_transform_nat = transformer_cls._transform_nat

    def _transform_nat(self: Any) -> None:
        original_transform_nat(self)

        group_keys = {
            (
                str(getattr(group, "source_context", "root") or "root"),
                str(group.name),
            )
            for group in getattr(self.fg, "ip_pool_groups", []) or []
        }
        pool_keys = {
            (
                str(getattr(pool, "source_context", "root") or "root"),
                str(pool.name),
            )
            for pool in getattr(self.fg, "ip_pools", []) or []
        }
        policies = _source_policy_map(self)

        for rule in self.ir.nat_rules:
            policy_ref = getattr(rule, "source_policy_reference", None)
            if policy_ref is None:
                continue
            context = str(getattr(rule, "source_context", "root") or "root")
            policy = policies.get((context, str(policy_ref)))
            if policy is None:
                continue

            group_refs: List[str] = []
            ambiguous_refs: List[str] = []
            for reference in list(getattr(policy, "poolname", []) or []):
                key = (context, str(reference))
                if key not in group_keys:
                    continue
                group_refs.append(str(reference))
                if key in pool_keys:
                    ambiguous_refs.append(str(reference))

            if not group_refs:
                continue

            rule.source_pool_group_references = list(dict.fromkeys(group_refs))

            direct_refs = list(getattr(rule, "source_pool_references", []) or [])
            if ambiguous_refs:
                reason = (
                    "FortiGate policy poolname matches both firewall ippool and "
                    "firewall ippool_grp in the same context: "
                    + ", ".join(dict.fromkeys(ambiguous_refs))
                    + "."
                )
            else:
                group_ref_set = set(group_refs)
                rule.source_pool_references = [
                    reference
                    for reference in direct_refs
                    if reference not in group_ref_set
                ]
                reason = IPPOOL_GROUP_REVIEW_REASON

            # Never keep an address expansion that may have been derived from a
            # pool-group name.  The original group/member evidence remains on
            # the rule and in self.ir.ip_pool_groups for audit.
            rule.translated_sources = []
            if hasattr(rule, "translated_source"):
                rule.translated_source = None
            _mark_nat_rule_for_group_review(rule, reason)

    _transform_nat._ippool_group_support = True
    transformer_cls._transform_nat = _transform_nat
