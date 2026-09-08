"""FortiOS 7.4.6 authentication-scheme parser/dependency extensions."""

from __future__ import annotations

from typing import Optional

from fwmigrate.ir.core import IRIdentityDependency
from fwmigrate.parsers.fortigate import model as model_module


AUTHENTICATION_REFERENCE_RULES = {
    ("authentication scheme", "domain-controller"): "user domain-controller",
    ("authentication scheme", "fsso-agent-for-ntlm"): "user fsso",
    ("authentication scheme", "kerberos-keytab"): "user krb-keytab",
    ("authentication scheme", "saml-server"): "user saml",
    ("authentication scheme", "ssh-ca"): "vpn certificate ca",
    ("authentication scheme", "user-database"): "user ldap",
}

AUTHENTICATION_TARGET_SECTIONS = {
    ("authentication scheme", "domain-controller"): {"user domain-controller"},
    ("authentication scheme", "fsso-agent-for-ntlm"): {"user fsso", "user fsso-polling"},
    ("authentication scheme", "kerberos-keytab"): {"user krb-keytab"},
    ("authentication scheme", "saml-server"): {"user saml"},
    ("authentication scheme", "ssh-ca"): {"vpn certificate ca"},
    ("authentication scheme", "user-database"): {"user ldap"},
}

AUTHENTICATION_METHODS = {
    "ntlm", "basic", "digest", "form", "negotiate",
    "fsso", "rsso", "ssh-publickey", "cert", "saml",
}

AUTHENTICATION_SWITCH_FIELDS = {
    "fsso_guest", "negotiate_ntlm", "require_tfa", "user_cert",
}

AUTHENTICATION_STRING_LIMITS = {
    "domain_controller": 35,
    "fsso_agent_for_ntlm": 35,
    "kerberos_keytab": 35,
    "saml_server": 35,
    "ssh_ca": 35,
}

AUTHENTICATION_SOURCE_ONLY_FIELDS = (
    "method",
    "user_database",
    "domain_controller",
    "fsso_agent_for_ntlm",
    "fsso_guest",
    "kerberos_keytab",
    "negotiate_ntlm",
    "require_tfa",
    "saml_server",
    "saml_timeout",
    "ssh_ca",
    "user_cert",
)


def _normalized(value: str) -> str:
    return " ".join(value.lower().replace("_", "-").split())


def install_authentication_scheme_support(
    parser_module,
    dependencies_module,
    extractor_module,
    transformer_module,
) -> None:
    """Install typed authentication-scheme fields and scoped references.

    Fields that are typed on the FortiGate source model but do not yet have
    dedicated portable IR fields remain copied into IR ``source_attributes``.
    This preserves the parser's zero-silent-loss contract while still allowing
    dependency validation and typed source access.
    """

    base_scheme = parser_module.FGAuthenticationScheme

    class FGAuthenticationSchemePhase4(base_scheme):
        domain_controller: Optional[str] = None
        fsso_agent_for_ntlm: Optional[str] = None
        fsso_guest: Optional[str] = None
        kerberos_keytab: Optional[str] = None
        negotiate_ntlm: Optional[str] = None
        require_tfa: Optional[str] = None
        saml_server: Optional[str] = None
        saml_timeout: Optional[int] = None
        ssh_ca: Optional[str] = None
        user_cert: Optional[str] = None

    parser_module.FGAuthenticationScheme = FGAuthenticationSchemePhase4
    model_module.FGAuthenticationScheme = FGAuthenticationSchemePhase4

    parser_cls = parser_module.FortiGateParser
    if not getattr(parser_cls.build_model, "_authentication_scheme_phase4_wrapped", False):
        original_build_model = parser_cls.build_model

        def build_model(self, section_path, attributes):
            if section_path == "authentication scheme":
                self._normalize_optional_int(attributes, "saml_timeout")
                timeout = attributes.get("saml_timeout")
                if timeout is not None and not 30 <= timeout <= 1200:
                    attributes["unparsed_saml_timeout"] = attributes.pop("saml_timeout")

                methods = attributes.get("method", [])
                invalid_methods = [value for value in methods if value not in AUTHENTICATION_METHODS]
                if invalid_methods:
                    attributes["method"] = [value for value in methods if value in AUTHENTICATION_METHODS]
                    attributes["unparsed_method"] = invalid_methods

                for field in AUTHENTICATION_SWITCH_FIELDS:
                    value = attributes.get(field)
                    if value is not None and value not in {"enable", "disable"}:
                        attributes[f"unparsed_{field}"] = attributes.pop(field)

                for field, limit in AUTHENTICATION_STRING_LIMITS.items():
                    value = attributes.get(field)
                    if value is not None and (not isinstance(value, str) or len(value) > limit):
                        attributes[f"unparsed_{field}"] = attributes.pop(field)

                databases = attributes.get("user_database", [])
                invalid_databases = [
                    value for value in databases
                    if not isinstance(value, str) or len(value) > 79
                ]
                if invalid_databases:
                    attributes["user_database"] = [
                        value for value in databases if value not in invalid_databases
                    ]
                    attributes["unparsed_user_database"] = invalid_databases
            return original_build_model(self, section_path, attributes)

        build_model._authentication_scheme_phase4_wrapped = True
        parser_cls.build_model = build_model

    transformer_cls = transformer_module.FGToIRTransformer
    if not getattr(
        transformer_cls._transform_authentication_inventory,
        "_authentication_scheme_phase4_wrapped",
        False,
    ):
        original_transform_authentication_inventory = (
            transformer_cls._transform_authentication_inventory
        )

        def _transform_authentication_inventory(self):
            start_index = len(self.ir.authentication_schemes)
            result = original_transform_authentication_inventory(self)
            new_items = self.ir.authentication_schemes[start_index:]
            ldap_names = {item.name for item in self.ir.user_ldap_servers}
            for source, target in zip(self.fg.authentication_schemes, new_items):
                for field in AUTHENTICATION_SOURCE_ONLY_FIELDS:
                    value = getattr(source, field, None)
                    if value is not None:
                        target.source_attributes.setdefault(field, value)

                target.user_database_dependencies = []
                target.resolved_user_databases = []
                target.unresolved_user_databases = []
                for reference in source.user_database:
                    is_local = _normalized(reference) == "local"
                    resolved = is_local or reference in ldap_names
                    target.user_database_dependencies.append(IRIdentityDependency(
                        reference=reference,
                        dependency_type="local" if is_local else "ldap-server",
                        resolved=resolved,
                        target_name=reference if resolved else None,
                        source_context=f"authentication scheme {source.name}",
                    ))
                    bucket = (
                        target.resolved_user_databases
                        if resolved else target.unresolved_user_databases
                    )
                    bucket.append(reference)

                audit_id = f"identity:authentication-scheme:{source.name}:user-database"
                self.ir.audit_entries = [
                    entry for entry in self.ir.audit_entries if entry.id != audit_id
                ]
                if target.unresolved_user_databases:
                    self._add_identity_audit(
                        audit_id,
                        f"Authentication scheme '{source.name}' contains unresolved LDAP "
                        f"reference(s): {', '.join(target.unresolved_user_databases)}. "
                        "Source values were preserved and require manual review.",
                    )
            return result

        _transform_authentication_inventory._authentication_scheme_phase4_wrapped = True
        transformer_cls._transform_authentication_inventory = (
            _transform_authentication_inventory
        )

    dependencies_module.REFERENCE_RULES.update(AUTHENTICATION_REFERENCE_RULES)
    dependencies_module.REFERENCE_TARGET_SECTIONS.update(AUTHENTICATION_TARGET_SECTIONS)

    if not getattr(
        dependencies_module.build_dependency_registry,
        "_authentication_scheme_phase4_wrapped",
        False,
    ):
        original_build_dependency_registry = dependencies_module.build_dependency_registry

        def build_dependency_registry(items):
            records = original_build_dependency_registry(items)
            for index, record in enumerate(records):
                if (
                    _normalized(record.source_path) == "authentication scheme"
                    and _normalized(record.source_field) == "user-database"
                    and _normalized(record.reference) == "local"
                ):
                    updates = {
                        "result": "RESOLVED",
                        "target_path": "fortigate built-in local user database",
                        "notes": "FortiOS built-in local authentication database.",
                    }
                    if hasattr(record, "model_copy"):
                        records[index] = record.model_copy(update=updates)
                    else:
                        for key, value in updates.items():
                            setattr(record, key, value)
            return records

        build_dependency_registry._authentication_scheme_phase4_wrapped = True
        dependencies_module.build_dependency_registry = build_dependency_registry
        extractor_module.build_dependency_registry = build_dependency_registry
