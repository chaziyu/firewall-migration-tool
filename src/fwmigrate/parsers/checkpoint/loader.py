"""Check Point command-aware export bundle loader and validation."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from fwmigrate.parsers.checkpoint.errors import CheckPointParseError
from fwmigrate.parsers.checkpoint.models import (
    CheckPointExportBundle,
    CheckPointResponse,
    collection_status_is_success,
    ScopeSelectionResult,
    RulebaseSafetyState,
)


def canonicalize_command(cmd: str) -> str:
    """Normalize command names like 'show hosts', 'show_hosts', 'show-hosts' to 'show-hosts'."""
    if not isinstance(cmd, str):
        return ""
    normalized = cmd.strip().lower()
    normalized = re.sub(r"[\s_]+", "-", normalized)
    return normalized


def load_checkpoint_input(content: str) -> Tuple[CheckPointExportBundle, ScopeSelectionResult]:
    """Parse JSON string or Gaia CLI text into a validated CheckPointExportBundle and compute ScopeSelectionResult."""
    stripped = content.strip()
    if not stripped.startswith("{") and (stripped.startswith(("set ", "add ", "#", "show ", "create ")) or "\nset " in content or "\nadd " in content):
        bundle = CheckPointExportBundle(
            format="checkpoint-export-v1",
            responses=[
                CheckPointResponse(
                    command="gaia/show-configuration",
                    data={"cli_text": content},
                )
            ]
        )
        return bundle, ScopeSelectionResult()

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise CheckPointParseError(
            f"Invalid Check Point JSON at line {exc.lineno}, column {exc.colno}"
        ) from exc
    except Exception as exc:
        raise CheckPointParseError(f"Failed to parse Check Point JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise CheckPointParseError("Check Point configuration root must be a JSON object")

    bundle: CheckPointExportBundle

    if "responses" in data or data.get("format") == "checkpoint-export-v1":
        bundle = CheckPointExportBundle.model_validate(data)
        for gaia in bundle.gaia_responses:
            if not isinstance(gaia, dict):
                continue
            gaia_data = gaia.get("data") if isinstance(gaia.get("data"), dict) else {
                "cli_text": gaia.get("cli_text") or gaia.get("output") or gaia.get("text") or ""
            }
            gaia_command = canonicalize_command(str(gaia.get("command") or "gaia/show-configuration"))
            if not gaia_command.startswith("gaia/"):
                gaia_command = "gaia/show-configuration"
            bundle.responses.append(CheckPointResponse(
                command=gaia_command,
                data=gaia_data,
                domain=gaia.get("domain") or bundle.domain,
                gateway=gaia.get("gateway") or bundle.gateway,
                source_response=gaia.get("source_response"),
                cluster_member=gaia.get("cluster_member"),
                collection_status=gaia.get("collection_status", "OK"),
                error=gaia.get("error"),
            ))
        for resp in bundle.responses:
            resp.command = canonicalize_command(resp.command)
            # Sync pagination metadata from inner data if present
            if resp.from_index is None and "from" in resp.data:
                resp.from_index = resp.data.get("from")
            if resp.to_index is None and "to" in resp.data:
                resp.to_index = resp.data.get("to")
            if resp.total is None and "total" in resp.data:
                resp.total = resp.data.get("total")
    else:
        # Legacy synthetic format handling
        # If an ambiguous top-level "rulebase" exists without explicit command or access-rulebase:
        if "rulebase" in data and "access-rulebase" not in data and not data.get("command"):
            raise CheckPointParseError(
                "Ambiguous Check Point rulebase: command identity is required"
            )

        responses: List[CheckPointResponse] = []
        domain = data.get("domain")
        gateway = data.get("name") or data.get("gateway")

        # Handle objects list
        objects = data.get("objects")
        if objects:
            if isinstance(objects, dict):
                objects = list(objects.values())
            responses.append(CheckPointResponse(
                command="show-objects",
                data={"objects": objects, "from": 1, "to": len(objects), "total": len(objects)},
                domain=domain,
                gateway=gateway,
            ))

        # Handle explicit access-rulebase
        access_rulebase = data.get("access-rulebase")
        if access_rulebase:
            # Legacy synthetic input defines omitted VPN as unrestricted. Make
            # that compatibility convention explicit before transformation.
            legacy_access_rulebase = []
            for rule in access_rulebase:
                if isinstance(rule, dict):
                    explicit_rule = dict(rule)
                    explicit_rule.setdefault("vpn", "Any")
                    legacy_access_rulebase.append(explicit_rule)
                else:
                    legacy_access_rulebase.append(rule)
            responses.append(CheckPointResponse(
                command="show-access-rulebase",
                package=data.get("package", "Standard"),
                layer=data.get("layer", "Network"),
                domain=domain,
                gateway=gateway,
                data={
                    "rulebase": legacy_access_rulebase,
                    "from": 1,
                    "to": len(access_rulebase),
                    "total": len(access_rulebase),
                },
            ))

        # Handle explicit nat-rulebase
        nat_rulebase = data.get("nat-rulebase")
        if nat_rulebase:
            responses.append(CheckPointResponse(
                command="show-nat-rulebase",
                package=data.get("package", "Standard"),
                domain=domain,
                gateway=gateway,
                data={
                    "rulebase": nat_rulebase,
                    "from": 1,
                    "to": len(nat_rulebase),
                    "total": len(nat_rulebase),
                },
            ))

        bundle = CheckPointExportBundle(
            format="checkpoint-export-v1",
            api_version=data.get("api_version"),
            domain=domain,
            gateway=gateway,
            selected_domain=data.get("selected_domain") or domain,
            selected_package=data.get("selected_package"),
            selected_access_layer=data.get("selected_access_layer"),
            selected_gateway=data.get("selected_gateway") or gateway,
            responses=responses,
        )

    # A bundle-level domain/gateway is inherited by responses that omit repeated
    # scope metadata. Explicit per-response scope always wins.
    for resp in bundle.responses:
        if resp.domain is None:
            resp.domain = bundle.domain
        if resp.gateway is None:
            resp.gateway = bundle.gateway

    scope_result = _resolve_scope(bundle)
    return bundle, scope_result


def _resolve_scope(bundle: CheckPointExportBundle) -> ScopeSelectionResult:
    """Diagnose domain, package, access layer, and gateway scope."""
    packages = {resp.package for resp in bundle.responses if resp.package}
    layers = {resp.layer for resp in bundle.responses if resp.layer}
    domains = {resp.domain for resp in bundle.responses if resp.domain}
    if bundle.domain:
        domains.add(bundle.domain)
    gateways = {resp.gateway for resp in bundle.responses if resp.gateway}
    if bundle.gateway:
        gateways.add(bundle.gateway)

    sel_domain = bundle.selected_domain
    sel_package = bundle.selected_package
    sel_layer = bundle.selected_access_layer
    sel_layer_uid = bundle.selected_access_layer_uid
    sel_gw = bundle.selected_gateway

    ambiguous = False
    reasons: List[str] = []

    # Domain scope
    if not sel_domain:
        if len(domains) == 1:
            sel_domain = next(iter(domains))
        elif len(domains) > 1:
            ambiguous = True
            reasons.append("multiple-domains-without-selector")

    # Package scope
    if not sel_package:
        if len(packages) == 1:
            sel_package = next(iter(packages))
        elif len(packages) > 1:
            ambiguous = True
            reasons.append("multiple-packages-without-selector")

    # Layer scope
    if not sel_layer:
        if len(layers) == 1:
            sel_layer = next(iter(layers))
        elif len(layers) > 1:
            ambiguous = True
            reasons.append("multiple-access-layers-without-selector")

    # Gateway scope
    if not sel_gw:
        if len(gateways) == 1:
            sel_gw = next(iter(gateways))
        elif len(gateways) > 1:
            ambiguous = True
            reasons.append("multiple-gateways-without-selector")

    return ScopeSelectionResult(
        selected_domain=sel_domain,
        selected_package=sel_package,
        selected_access_layer=sel_layer,
        selected_access_layer_uid=sel_layer_uid,
        selected_gateway=sel_gw,
        ambiguous=ambiguous,
        reasons=reasons,
    )


def group_response_pages(
    target: Union[CheckPointExportBundle, List[CheckPointResponse]],
) -> Dict[Tuple[str, Optional[str], Optional[str], Optional[str], Optional[str]], List[CheckPointResponse]]:
    """Group responses by unique operation signature (command, domain, package, layer, gateway)."""
    responses = target.responses if isinstance(target, CheckPointExportBundle) else target
    grouped: Dict[Tuple[str, Optional[str], Optional[str], Optional[str], Optional[str]], List[CheckPointResponse]] = {}
    for resp in responses:
        cmd = canonicalize_command(resp.command)
        key = (cmd, resp.domain, resp.package, resp.layer, resp.gateway)
        grouped.setdefault(key, []).append(resp)
    return grouped


def build_rulebase_safety_map(
    target: Union[CheckPointExportBundle, List[CheckPointResponse]],
) -> Dict[Tuple[str, Optional[str], Optional[str], Optional[str], Optional[str]], RulebaseSafetyState]:
    """Validate every grouped response before any rule transformation occurs."""
    safety: Dict[Tuple[str, Optional[str], Optional[str], Optional[str], Optional[str]], RulebaseSafetyState] = {}
    for key, pages in group_response_pages(target).items():
        valid, reason = validate_pagination(pages)
        reasons = [] if valid else ["incomplete-pagination", str(reason)]
        if any(not collection_status_is_success(page.collection_status) for page in pages):
            valid = False
            reasons.extend(["collection-error", "failed-source-command"])
        safety[key] = RulebaseSafetyState(complete=valid, reasons=list(dict.fromkeys(reasons)))
    return safety


def validate_pagination(pages: List[CheckPointResponse]) -> Tuple[bool, Optional[str]]:
    """
    Validate that a sequence of response pages forms a complete, contiguous range.
    Returns (True, None) if complete, or (False, reason) if incomplete or inconsistent.
    """
    if not pages:
        return True, None

    # Check total consistency
    totals = {p.total for p in pages if p.total is not None}
    has_page_indices = any(p.from_index is not None or p.to_index is not None for p in pages)
    if not totals and not has_page_indices:
        if len(pages) == 1:
            return True, None
        return False, "multiple-unpaged-responses-without-pagination-metadata"

    if len(totals) > 1:
        return False, f"Inconsistent total counts across pages: {totals}"

    total = next(iter(totals)) if totals else None
    if total is not None and total < 0:
        return False, f"Invalid negative pagination total: {total}"

    if total == 0 and len(pages) == 1:
        page = pages[0]
        payload = page.data.get("objects", page.data.get("rulebase"))
        if payload in ([], {}):
            # R81 commands may encode an empty native range as 1..0 (and some
            # exported bundles use 0..0). Both are legitimate empty success.
            if (page.from_index, page.to_index) in ((1, 0), (0, 0)):
                return True, None

    # Sort pages by from_index
    valid_paged = [p for p in pages if p.from_index is not None and p.to_index is not None]
    if len(valid_paged) != len(pages):
        return False, "Some pages are missing from/to pagination indices"

    valid_paged.sort(key=lambda p: p.from_index or 0)

    expected_from = 1
    for page in valid_paged:
        f = page.from_index or 0
        t = page.to_index or 0
        if f < 1:
            return False, f"Invalid page range: from={f} is less than 1"
        if total is not None and t > total:
            return False, f"Invalid page range: to={t} exceeds total={total}"
        if f < expected_from:
            return False, f"Overlap in pagination: expected from={expected_from}, got from={f}"
        if f > expected_from:
            return False, f"Gap in pagination: expected from={expected_from}, got from={f}"
        if t < f:
            return False, f"Invalid page range: from={f} is greater than to={t}"
        objects = page.data.get("objects")
        if isinstance(objects, (list, dict)):
            actual_count = len(objects)
            expected_count = t - f + 1
            if actual_count != expected_count:
                return False, "Pagination metadata does not match payload count"
        elif "rulebase" in page.data:
            # R81 rulebase responses represent section ranges as nested
            # containers, while from/to counts the contained native rule units.
            # Only this documented section representation is flattened here;
            # inline-layer responses remain separate command responses.
            rulebase = page.data.get("rulebase")
            if not isinstance(rulebase, list):
                return False, "Rulebase pagination payload is not a list"
            from fwmigrate.parsers.checkpoint.rulebase import flatten_rulebase
            actual_count = len(flatten_rulebase(rulebase))
            expected_count = t - f + 1
            if actual_count != expected_count:
                return False, "Rulebase pagination metadata does not match native payload count"
        expected_from = t + 1

    if total is not None and (expected_from - 1) < total:
        return False, f"Incomplete pagination: collected up to {expected_from - 1} of total {total}"

    return True, None
