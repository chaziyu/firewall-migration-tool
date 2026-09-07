"""Phase 41 shared FortiGate security-profile command evaluation.

Typed profile models expose the effective FortiOS configuration while the
recursive FGSourceNode/FGSourceCommand tree remains the lossless source of
truth.  Command semantics are evaluated once here and profile families only
declare field types.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fwmigrate.parsers.fortigate.extraction import sanitize_source_attributes
from fwmigrate.parsers.fortigate.model import (
    FGApplicationEntry,
    FGApplicationFilter,
    FGApplicationList,
    FGApplicationOverride,
    FGAntivirusProfile,
    FGAntivirusProfileConfig,
    FGAntivirusProtocol,
    FGDNSFilterAction,
    FGDNSFilterBotnet,
    FGDNSFilterCategory,
    FGDNSFilterDomainFilter,
    FGDNSFilterProfile,
    FGProfileNestedSection,
    FGSSLSSHCertificate,
    FGSSLSSHExemption,
    FGSSLSSHProfile,
    FGSSLSSHProtocolInspection,
    FGWebFilterCategory,
    FGWebFilterOverride,
    FGWebFilterProfile,
    FGWebFilterURLFilter,
)
from fwmigrate.parsers.fortigate.source_tree import FGSourceNode


PROFILE_SECURITY_SECRET_FIELDS = {
    "password",
    "passwd",
    "secret",
    "psksecret",
    "token",
    "key",
    "key2",
    "key3",
    "api_key",
    "key_string",
    "private_key",
    "encryption_key",
    "authentication_key",
    "auth_key",
    "secondary_key",
    "tertiary_key",
    "bind_password",
    "bind_secret",
    "tertiary_secret",
    "shared_secret",
}


# Field meaning is declared per typed profile model.  The evaluator below only
# implements FortiOS command operations; it does not infer list/scalar meaning.
PROFILE_FIELD_SPECS: Dict[Any, Dict[str, set[str]]] = {
    FGAntivirusProfile: {
        "scalar_fields": {"comment", "status", "inspection_mode"},
    },
    FGAntivirusProtocol: {
        "scalar_fields": {"status", "action", "scan", "comment"},
    },
    FGAntivirusProfileConfig: {
        "scalar_fields": {"status", "action", "scan", "log", "comment"},
    },
    FGWebFilterProfile: {
        "scalar_fields": {"comment", "status", "inspection_mode"},
    },
    FGWebFilterCategory: {
        "scalar_fields": {"category", "action", "status", "log", "override"},
    },
    FGWebFilterOverride: {
        "scalar_fields": {"category", "action", "status", "authentication"},
    },
    FGWebFilterURLFilter: {
        "scalar_fields": {"url", "action", "status", "type"},
        "list_fields": {"auth_users"},
    },
    FGDNSFilterProfile: {
        "scalar_fields": {"comment", "status"},
    },
    FGDNSFilterCategory: {
        "scalar_fields": {"category", "action", "redirect", "status"},
    },
    FGDNSFilterDomainFilter: {
        "scalar_fields": {"domain", "action", "redirect", "status"},
    },
    FGDNSFilterBotnet: {
        "scalar_fields": {"action", "redirect", "status"},
    },
    FGDNSFilterAction: {
        "scalar_fields": {"action", "redirect", "status"},
    },
    FGApplicationList: {
        "scalar_fields": {"comment"},
    },
    FGApplicationEntry: {
        "scalar_fields": {"action", "status"},
        "integer_list_fields": {"application", "category", "risk"},
    },
    FGApplicationFilter: {
        "scalar_fields": {"action", "status"},
        "integer_list_fields": {"category", "risk"},
    },
    FGApplicationOverride: {
        "scalar_fields": {"action", "status"},
        "integer_list_fields": {"application", "category"},
    },
    FGSSLSSHProfile: {
        "scalar_fields": {"comment", "inspection_mode"},
    },
    FGSSLSSHProtocolInspection: {
        "scalar_fields": {"status", "action"},
        "list_fields": {"ports"},
    },
    FGSSLSSHCertificate: {
        "scalar_fields": {"certificate", "status"},
    },
    FGSSLSSHExemption: {
        "scalar_fields": {"address", "category", "action", "status"},
    },
}


_PROFILE_PATHS = {
    "antivirus profile": ("antivirus_profiles", FGAntivirusProfile),
    "webfilter profile": ("webfilter_profiles", FGWebFilterProfile),
    "dnsfilter profile": ("dnsfilter_profiles", FGDNSFilterProfile),
    "application list": ("application_lists", FGApplicationList),
    "application custom": ("application_lists", FGApplicationList),
    "firewall ssl-ssh-profile": ("ssl_ssh_profiles", FGSSLSSHProfile),
}


def _profile_field_spec(model: Optional[Any] = None) -> Dict[str, set[str]]:
    declared = PROFILE_FIELD_SPECS.get(model, {})
    return {
        "scalar_fields": set(declared.get("scalar_fields", set())),
        "list_fields": set(declared.get("list_fields", set())),
        "integer_fields": set(declared.get("integer_fields", set())),
        "integer_list_fields": set(declared.get("integer_list_fields", set())),
        "secret_fields": PROFILE_SECURITY_SECRET_FIELDS
        | set(declared.get("secret_fields", set())),
    }


def _raw_value(values: List[str], *, scalar: bool = False) -> Any:
    if not values:
        return True
    if len(values) == 1:
        return values[0]
    return " ".join(values) if scalar else list(values)


def _append_unparsed(
    extra_settings: Dict[str, Any],
    target: str,
    values: List[Any],
) -> None:
    if not values:
        return
    current = extra_settings.get(target)
    if current is None:
        extra_settings[target] = values[0] if len(values) == 1 else list(values)
        return
    if not isinstance(current, list):
        current = [current]
    current.extend(values)
    extra_settings[target] = current


def _effective_node_attributes(
    source: FGSourceNode,
    model: Optional[Any] = None,
    field_spec: Optional[Dict[str, set[str]]] = None,
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """Evaluate commands in source order without mutating source evidence.

    Returns ``(effective, extra_settings)``.  Known fields use their declared
    types. Unknown fields are retained as source-only effective settings.
    ``append`` is only interpreted for explicitly declared list fields.
    """

    spec = _profile_field_spec(model)
    if field_spec:
        for category in (
            "scalar_fields",
            "list_fields",
            "integer_fields",
            "integer_list_fields",
            "secret_fields",
        ):
            if category in field_spec:
                spec[category] = set(field_spec[category])

    scalar_fields = spec["scalar_fields"]
    list_fields = spec["list_fields"]
    integer_fields = spec["integer_fields"]
    integer_list_fields = spec["integer_list_fields"]
    secret_fields = spec["secret_fields"]
    typed_fields = scalar_fields | list_fields | integer_fields | integer_list_fields

    effective: Dict[str, Any] = {}
    extra_settings: Dict[str, Any] = {}

    for command in source.commands:
        key = command.key.replace("-", "_")
        operation = getattr(command, "operation", "set")
        values = list(command.values)
        unparsed_key = f"unparsed_{key}"
        unparsed_append_key = f"unparsed_append_{key}"

        # Source commands stay in FGSourceNode. Profile projections never copy
        # credential material into typed fields or extra_settings.
        if key in secret_fields:
            effective.pop(key, None)
            extra_settings.pop(key, None)
            extra_settings.pop(unparsed_key, None)
            extra_settings.pop(unparsed_append_key, None)
            continue

        if operation == "unset":
            effective.pop(key, None)
            extra_settings.pop(key, None)
            extra_settings.pop(unparsed_key, None)
            extra_settings.pop(unparsed_append_key, None)
            continue

        if operation not in {"set", "append"}:
            _append_unparsed(
                extra_settings,
                f"unparsed_operation_{operation}_{key}",
                values or [True],
            )
            continue

        if key in integer_list_fields:
            parsed: List[int] = []
            malformed: List[Any] = []
            for value in values:
                try:
                    parsed.append(int(value))
                except (TypeError, ValueError):
                    malformed.append(value)

            if operation == "set":
                effective[key] = parsed
                extra_settings.pop(unparsed_key, None)
                extra_settings.pop(unparsed_append_key, None)
                if malformed:
                    # Existing application-control behavior retains malformed
                    # integer-list members as a list.
                    extra_settings[unparsed_key] = list(malformed)
            else:
                current = effective.get(key, [])
                if not isinstance(current, list):
                    current = []
                effective[key] = [*current, *parsed]
                if malformed:
                    current_bad = extra_settings.get(unparsed_append_key, [])
                    if not isinstance(current_bad, list):
                        current_bad = [current_bad]
                    extra_settings[unparsed_append_key] = [
                        *current_bad,
                        *malformed,
                    ]
            continue

        if key in integer_fields:
            if operation == "append":
                _append_unparsed(
                    extra_settings,
                    unparsed_append_key,
                    values or [True],
                )
                continue

            effective.pop(key, None)
            extra_settings.pop(unparsed_key, None)
            extra_settings.pop(unparsed_append_key, None)
            if len(values) != 1:
                extra_settings[unparsed_key] = _raw_value(values)
                continue
            try:
                effective[key] = int(values[0])
            except (TypeError, ValueError):
                extra_settings[unparsed_key] = values[0]
            continue

        if key in list_fields:
            if operation == "set":
                effective[key] = list(values)
                extra_settings.pop(unparsed_key, None)
                extra_settings.pop(unparsed_append_key, None)
            else:
                current = effective.get(key, [])
                if not isinstance(current, list):
                    current = []
                effective[key] = [*current, *values]
            continue

        if key in scalar_fields:
            if operation == "set":
                effective[key] = _raw_value(values, scalar=True)
                extra_settings.pop(unparsed_key, None)
                extra_settings.pop(unparsed_append_key, None)
            else:
                _append_unparsed(
                    extra_settings,
                    unparsed_append_key,
                    values or [True],
                )
            continue

        # Unknown fields are retained, but append is not assigned semantics
        # until the profile declares that field to be a list.
        if operation == "set":
            raw = _raw_value(values)
            effective[key] = raw
            extra_settings[key] = raw
            extra_settings.pop(unparsed_append_key, None)
        else:
            _append_unparsed(
                extra_settings,
                unparsed_append_key,
                values or [True],
            )

    for key in effective:
        if key not in typed_fields:
            extra_settings[key] = effective[key]

    return (
        sanitize_source_attributes(effective),
        sanitize_source_attributes(extra_settings),
    )


def _effective_profile_settings(
    source: FGSourceNode,
    model: Any,
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    effective, extra_settings = _effective_node_attributes(source, model=model)
    settings = dict(effective)
    settings.update(
        {
            key: value
            for key, value in extra_settings.items()
            if key.startswith("unparsed_")
        }
    )
    return settings, extra_settings


def _typed_values(settings: Dict[str, Any], model: Any) -> Dict[str, Any]:
    return {
        key: value
        for key, value in settings.items()
        if key in model.model_fields
        and key not in {"name", "settings", "extra_settings"}
    }


def _effective_nested_profile_edits(
    source: FGSourceNode,
    model: Any,
) -> List[Dict[str, Any]]:
    """Return ordered effective nested edits with their original source node."""

    projections: List[Dict[str, Any]] = []
    for source_order, entry in enumerate(
        (child for child in source.children if child.node_type == "edit"),
        start=1,
    ):
        settings, extra_settings = _effective_profile_settings(entry, model)
        projections.append(
            {
                "name": entry.name,
                "source_order": source_order,
                "settings": settings,
                "values": _typed_values(settings, model),
                "extra_settings": extra_settings,
                "source": entry,
            }
        )
    return projections


def _typed_profile_node(node: FGSourceNode) -> FGProfileNestedSection:
    settings, extra_settings = _effective_profile_settings(
        node,
        FGProfileNestedSection,
    )
    return FGProfileNestedSection(
        name=node.name,
        settings=settings,
        entries=[_typed_profile_node(child) for child in node.children],
        extra_settings=extra_settings,
    )


def _application_diagnostics(
    parser: Any,
    *,
    source_path: str,
    section_name: str,
    profile_name: str,
    projection: Dict[str, Any],
    fields: tuple[str, ...],
) -> None:
    """Preserve existing manual-review/status behavior for malformed IDs."""

    entry = projection["source"]
    for field in fields:
        raw_effective, _ = _effective_node_attributes(
            entry,
            field_spec={"list_fields": {field}},
        )
        if field not in raw_effective:
            continue
        diagnostic_settings = {field: list(raw_effective[field])}
        parser._parse_and_record_application_control_ints(
            source_path=source_path,
            section_name=section_name,
            profile_name=profile_name,
            entry_name=projection["name"],
            settings=diagnostic_settings,
            field=field,
        )


def _build_antivirus_or_webfilter(
    parser: Any,
    source_path: str,
    collection_name: str,
    model: Any,
    top_edits: List[FGSourceNode],
) -> None:
    for node in top_edits:
        profile_settings, profile_extra = _effective_profile_settings(node, model)
        profile = model(
            name=node.name,
            **_typed_values(profile_settings, model),
        )
        profile.extra_settings = profile_extra

        for child in node.children:
            child_name = child.name.lower().replace("-", "_")
            child_entries = [
                entry for entry in child.children if entry.node_type == "edit"
            ]

            if model is FGAntivirusProfile:
                if child_name in {
                    "http",
                    "ftp",
                    "smtp",
                    "imap",
                    "pop3",
                    "nntp",
                    "ssh",
                }:
                    settings, extra_settings = _effective_profile_settings(
                        child,
                        FGAntivirusProtocol,
                    )
                    protocol = FGAntivirusProtocol(
                        name=child.name,
                        settings=settings,
                        entries=[_typed_profile_node(entry) for entry in child_entries],
                        extra_settings=extra_settings,
                        **_typed_values(settings, FGAntivirusProtocol),
                    )
                    for nested in child.children:
                        if nested.node_type != "config":
                            continue
                        for projection in _effective_nested_profile_edits(
                            nested,
                            FGAntivirusProfileConfig,
                        ):
                            protocol.configs.append(
                                FGAntivirusProfileConfig(
                                    name=projection["name"],
                                    settings=projection["settings"],
                                    extra_settings=projection["extra_settings"],
                                    **projection["values"],
                                )
                            )
                    profile.protocols.append(protocol)
                else:
                    settings, extra_settings = _effective_profile_settings(
                        child,
                        FGAntivirusProfileConfig,
                    )
                    profile.configs.append(
                        FGAntivirusProfileConfig(
                            name=child.name,
                            settings=settings,
                            extra_settings=extra_settings,
                            **_typed_values(settings, FGAntivirusProfileConfig),
                        )
                    )
                continue

            def add_webfilter_nodes(source: FGSourceNode) -> None:
                source_name = source.name.lower().replace("-", "_")
                target_model = (
                    FGWebFilterOverride
                    if "override" in source_name
                    else FGWebFilterURLFilter
                    if "url" in source_name
                    else FGWebFilterCategory
                )
                target_bucket = (
                    profile.overrides
                    if target_model is FGWebFilterOverride
                    else profile.url_filters
                    if target_model is FGWebFilterURLFilter
                    else profile.categories
                )
                for projection in _effective_nested_profile_edits(
                    source,
                    target_model,
                ):
                    target_bucket.append(
                        target_model(
                            name=projection["name"],
                            settings=projection["settings"],
                            extra_settings=projection["extra_settings"],
                            **projection["values"],
                        )
                    )
                for nested in source.children:
                    if nested.node_type == "config":
                        add_webfilter_nodes(nested)

            add_webfilter_nodes(child)

        getattr(parser.config, collection_name).append(profile)


def _build_dns_app_ssl(
    parser: Any,
    source_path: str,
    collection_name: str,
    model: Any,
    top_edits: List[FGSourceNode],
) -> None:
    for node in top_edits:
        profile_settings, profile_extra = _effective_profile_settings(node, model)
        profile = model(
            name=node.name,
            **_typed_values(profile_settings, model),
        )
        profile.extra_settings = profile_extra

        def add_nested(source: FGSourceNode) -> None:
            source_name = source.name.lower().replace("-", "_")

            if model is FGSSLSSHProfile and source.commands and source_name in {
                "http",
                "https",
                "ftp",
                "ftps",
                "smtp",
                "smtps",
                "imap",
                "pop3",
                "ssh",
            }:
                settings, extra_settings = _effective_profile_settings(
                    source,
                    FGSSLSSHProtocolInspection,
                )
                profile.protocols.append(
                    FGSSLSSHProtocolInspection(
                        name=source.name,
                        settings=settings,
                        extra_settings=extra_settings,
                        **_typed_values(settings, FGSSLSSHProtocolInspection),
                    )
                )

            if model is FGDNSFilterProfile:
                target_model = (
                    FGDNSFilterBotnet
                    if "botnet" in source_name
                    else FGDNSFilterDomainFilter
                    if "domain" in source_name
                    else FGDNSFilterCategory
                    if (
                        "categor" in source_name
                        or "filter" in source_name
                        or "ftgd" in source_name
                    )
                    else FGDNSFilterAction
                )
                target_bucket = (
                    profile.botnet
                    if target_model is FGDNSFilterBotnet
                    else profile.domain_filters
                    if target_model is FGDNSFilterDomainFilter
                    else profile.categories
                    if target_model is FGDNSFilterCategory
                    else profile.actions
                )
            elif model is FGApplicationList:
                target_model = (
                    FGApplicationOverride
                    if "override" in source_name
                    else FGApplicationFilter
                    if "filter" in source_name
                    else FGApplicationEntry
                )
                target_bucket = (
                    profile.overrides
                    if target_model is FGApplicationOverride
                    else profile.filters
                    if target_model is FGApplicationFilter
                    else profile.entries
                )
            else:
                target_model = (
                    FGSSLSSHCertificate
                    if "cert" in source_name
                    else FGSSLSSHExemption
                    if "exempt" in source_name
                    else FGSSLSSHProtocolInspection
                )
                target_bucket = (
                    profile.certificates
                    if target_model is FGSSLSSHCertificate
                    else profile.exemptions
                    if target_model is FGSSLSSHExemption
                    else profile.protocols
                )

            for projection in _effective_nested_profile_edits(
                source,
                target_model,
            ):
                settings = projection["settings"]
                if model is FGApplicationList:
                    if target_model is FGApplicationEntry:
                        _application_diagnostics(
                            parser,
                            source_path=source_path,
                            section_name=source_name,
                            profile_name=node.name,
                            projection=projection,
                            fields=("application", "category", "risk"),
                        )
                        if "application" in settings:
                            settings["application_id"] = (
                                settings["application"][0]
                                if settings["application"]
                                else None
                            )
                    elif target_model is FGApplicationFilter:
                        _application_diagnostics(
                            parser,
                            source_path=source_path,
                            section_name=source_name,
                            profile_name=node.name,
                            projection=projection,
                            fields=("category", "risk"),
                        )
                    else:
                        _application_diagnostics(
                            parser,
                            source_path=source_path,
                            section_name=source_name,
                            profile_name=node.name,
                            projection=projection,
                            fields=("application", "category"),
                        )

                values = _typed_values(settings, target_model)
                target_bucket.append(
                    target_model(
                        name=projection["name"],
                        **values,
                        **(
                            {"settings": settings}
                            if "settings" in target_model.model_fields
                            else {}
                        ),
                        extra_settings=projection["extra_settings"],
                    )
                )

            for nested in source.children:
                if nested.node_type == "config":
                    add_nested(nested)

        for child in node.children:
            add_nested(child)
        getattr(parser.config, collection_name).append(profile)


def install_phase_41_security_profile_support(parser_module: Any) -> None:
    """Install the shared Phase 41 evaluator for security-profile families."""

    parser_cls = parser_module.FortiGateParser
    current = parser_cls._build_structured_typed_parents
    if getattr(current, "_phase_41_wrapped", False):
        return

    original = current

    def build_structured_typed_parents(
        self: Any,
        source_path: str,
        top_edits: List[FGSourceNode],
    ) -> None:
        target = _PROFILE_PATHS.get(source_path)
        if target is None:
            return original(self, source_path, top_edits)

        collection_name, model = target
        if model in {FGAntivirusProfile, FGWebFilterProfile}:
            _build_antivirus_or_webfilter(
                self,
                source_path,
                collection_name,
                model,
                top_edits,
            )
            return

        _build_dns_app_ssl(
            self,
            source_path,
            collection_name,
            model,
            top_edits,
        )

    build_structured_typed_parents._phase_41_wrapped = True
    parser_cls._build_structured_typed_parents = build_structured_typed_parents

    # Expose the shared helpers from parser.py's public module namespace so
    # profile tests and later phases consume the same implementation.
    parser_module.PROFILE_FIELD_SPECS = PROFILE_FIELD_SPECS
    parser_module._effective_node_attributes = _effective_node_attributes
    parser_module._effective_nested_profile_edits = _effective_nested_profile_edits
