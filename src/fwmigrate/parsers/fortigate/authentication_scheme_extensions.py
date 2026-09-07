"""FortiOS 7.4.6 authentication-scheme parser/dependency extensions."""

from __future__ import annotations

from typing import Optional

from fwmigrate.parsers.fortigate import model as model_module


AUTHENTICATION_REFERENCE_RULES = {
    ("authentication scheme", "domain-controller"): "user domain-controller",
    ("authentication scheme", "fsso-agent-for-ntlm"): "user fsso",
    ("authentication scheme", "kerberos-keytab"): "user krb-keytab",
    ("authentication scheme", "saml-server"): "user saml",
    ("authentication scheme", "ssh-ca"): "vpn certificate ca",
    ("authentication scheme", "user-database"): "user",
}

AUTHENTICATION_TARGET_SECTIONS = {
    ("authentication scheme", "domain-controller"): {"user domain-controller"},
    ("authentication scheme", "fsso-agent-for-ntlm"): {"user fsso", "user fsso-polling"},
    ("authentication scheme", "kerberos-keytab"): {"user krb-keytab"},
    ("authentication scheme", "saml-server"): {"user saml"},
    ("authentication scheme", "ssh-ca"): {"vpn certificate ca"},
    ("authentication scheme", "user-database"): {"user"},
}


def _normalized(value: str) -> str:
    return " ".join(value.lower().replace("_", "-").split())


def install_authentication_scheme_support(
    parser_module,
    dependencies_module,
    extractor_module,
) -> None:
    """Install typed authentication-scheme fields and scoped references."""

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
            return original_build_model(self, section_path, attributes)

        build_model._authentication_scheme_phase4_wrapped = True
        parser_cls.build_model = build_model

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
