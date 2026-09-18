"""FortiGate identity and security builders."""

from fwmigrate.parsers.fortigate import parser as parser_module

globals().update({
    name: getattr(parser_module, name)
    for name in dir(parser_module)
    if not name.startswith("__")
})

from fwmigrate.parsers.fortigate.builders.antivirus import _build_antivirus_profiles
from fwmigrate.parsers.fortigate.builders.webfilter import _build_webfilter_profiles
from fwmigrate.parsers.fortigate.builders.dnsfilter import _build_dnsfilter_profiles
from fwmigrate.parsers.fortigate.builders.application_control import _build_application_lists
from fwmigrate.parsers.fortigate.builders.security_profiles_extra import (
    _build_ssl_ssh_profile,
    _refresh_interface_ipv6_from_source,
    _refresh_policy_address_families,
)

def build_security(self: Any, section_path: str, attributes: Dict[str, Any]) -> bool:
    if section_path == "user ldap":
        for key in ("port", "source_port", "timeout", "connect_timeout", "query_timeout"):
            self._normalize_optional_int(attributes, key)
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGUserLDAP.model_fields) | {"schema"},
        )
        self.config.user_ldap_servers.append(FGUserLDAP(**attributes))
        return True

    if section_path == "user fsso":
        provider_has_password = attributes.get("has_password", False)
        endpoints = []
        for index in range(1, 6):
            suffix = "" if index == 1 else str(index)
            server = attributes.get(f"server{suffix}")
            port = attributes.get(f"port{suffix}")
            password = attributes.pop(f"password{suffix}", None)
            password_configured = attributes.pop(
                f"has_password{suffix}",
                attributes.get("has_password", False) if index == 1 else False,
            )
            if server is not None or port is not None or password is not None or password_configured:
                self._normalize_optional_int(attributes, f"port{suffix}")
                endpoints.append(FGFSSOEndpoint(
                    index=index,
                    server=server,
                    port=attributes.get(f"port{suffix}"),
                    has_password=bool(password) or bool(password_configured),
                ))
        attributes["endpoints"] = endpoints
        attributes["has_password"] = provider_has_password
        for field in ("group_poll_interval", "ldap_poll_interval", "logon_timeout"):
            self._normalize_optional_int(attributes, field)
        self._normalize_optional_int(attributes, "vrf_select")
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGFSSOServer.model_fields),
        )
        self.config.fsso_servers.append(FGFSSOServer(**attributes))
        return True

    if section_path == "user local":
        self._normalize_optional_int(attributes, "id")
        self._normalize_optional_int(attributes, "auth_concurrent_value")
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGLocalUser.model_fields),
        )
        self.config.local_users.append(FGLocalUser(**attributes))
        return True

    if section_path == "user group":
        if "type" in attributes:
            attributes["group_type"] = attributes.pop("type")
        raw_matches = attributes.pop("match", [])
        raw_guests = attributes.pop("guests", [])
        matches = []
        for entry in raw_matches:
            if entry.get("name") == str(entry.get("id")):
                entry.pop("name", None)
            matches.append(FGUserGroupMatch(**entry))
        attributes["match"] = matches
        guests = []
        for entry in raw_guests:
            entry["id"] = entry.get("id", entry.get("name"))
            self._normalize_optional_int(entry, "id")
            if entry.get("name") == str(entry.get("id")):
                entry.pop("name", None)
            entry["extra_settings"] = _extract_extra_settings(
                entry, set(FGUserGroupGuest.model_fields)
            )
            guests.append(FGUserGroupGuest(**entry))
        attributes["guests"] = guests
        for field in ("id", "auth_concurrent_value", "authtimeout", "expire", "max_accounts"):
            self._normalize_optional_int(attributes, field)
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGUserGroup.model_fields),
        )
        self.config.user_groups.append(FGUserGroup(**attributes))
        return True

    if section_path == "vpn ssl web portal":
        for field in {
            "default_window_height", "default_window_width",
        }:
            self._normalize_optional_int(attributes, field)
        self._normalize_ssl_vpn_nested(attributes)
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGSSLVPNPortal.model_fields),
        )
        self.config.ssl_vpn_portals.append(FGSSLVPNPortal(**attributes))
        return True

    if section_path in {"firewall DoS-policy", "firewall DoS-policy6"}:
        if attributes.get("name") == str(attributes.get("id")):
            attributes.pop("name", None)
        attributes["source_context"] = self.current_context
        attributes["address_family"] = (
            "ipv6" if section_path == "firewall DoS-policy6" else "ipv4"
        )
        raw_anomalies = attributes.pop("anomalies", [])
        anomalies = []
        for entry in raw_anomalies:
            self._normalize_optional_int(entry, "threshold")
            self._normalize_optional_int(entry, "threshold_default")
            entry["extra_settings"] = _extract_extra_settings(
                entry,
                set(FGDoSAnomaly.model_fields),
            )
            anomalies.append(FGDoSAnomaly(**entry))
        attributes["anomalies"] = anomalies
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGDoSPolicy.model_fields),
        )
        self.config.dos_policies.append(FGDoSPolicy(**attributes))
        return True

    return False
