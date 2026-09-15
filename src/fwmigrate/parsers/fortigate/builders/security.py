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
    _build_ips_sensor,
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

    if section_path == "system admin":
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGAdministrator.model_fields),
        )
        self.config.administrators.append(FGAdministrator(**attributes))
        return True

    if section_path == "system accprofile":
        raw_permission_blocks = attributes.pop("permission_blocks", [])
        permission_blocks = []
        known_permission_settings = {
            "fwgrp_permission": {"policy", "address", "service", "schedule", "others"},
            "loggrp_permission": {"config", "data_access", "report_access", "threat_weight"},
            "netgrp_permission": {"cfg", "packet_capture", "route_cfg"},
            "sysgrp_permission": {"admin", "upd", "cfg", "mnt"},
        }
        for block in raw_permission_blocks:
            settings = dict(block.get("settings", {}))
            known_keys = known_permission_settings.get(
                block["name"].replace("-", "_"), set(settings)
            )
            permission_blocks.append(
                FGAdminProfilePermissionBlock(
                    name=block["name"],
                    settings={key: value for key, value in settings.items() if key in known_keys},
                    extra_settings=sanitize_source_attributes({
                        key: value for key, value in settings.items() if key not in known_keys
                    }),
                )
            )
        attributes["permission_blocks"] = permission_blocks
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGAdminProfile.model_fields),
        )
        self.config.admin_profiles.append(FGAdminProfile(**attributes))
        return True

    if section_path == "user fortitoken":
        attributes["serial"] = attributes.pop("name")
        attributes.pop("id", None)
        if "user" in attributes:
            attributes["assigned_user"] = attributes.pop("user")
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGFortiToken.model_fields),
        )
        self.config.fortitokens.append(FGFortiToken(**attributes))
        return True

    if section_path == "vpn ssl web portal":
        for field in {
            "default_window_height", "default_window_width",
        }:
            self._normalize_optional_int(attributes, field)
        self._normalize_ssl_vpn_nested(attributes)
        raw_checks = attributes.pop("host_checks", [])
        host_checks = []
        for entry in raw_checks:
            entry["extra_settings"] = _extract_extra_settings(
                entry,
                set(FGSSLVPNHostCheckSoftware.model_fields),
            )
            host_checks.append(FGSSLVPNHostCheckSoftware(**entry))
        attributes["host_checks"] = host_checks
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGSSLVPNPortal.model_fields),
        )
        self.config.ssl_vpn_portals.append(FGSSLVPNPortal(**attributes))
        return True

    if section_path == "vpn ssl web host-check-software":
        raw_items = attributes.pop("check_items", [])
        check_items = []
        for entry in raw_items:
            if entry.get("name") == str(entry.get("id")):
                entry.pop("name", None)
            entry["extra_settings"] = _extract_extra_settings(
                entry,
                set(FGSSLVPNHostCheckItem.model_fields),
            )
            check_items.append(FGSSLVPNHostCheckItem(**entry))
        attributes["check_items"] = check_items
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGSSLVPNHostCheckSoftware.model_fields),
        )
        self.config.ssl_vpn_host_check_software.append(
            FGSSLVPNHostCheckSoftware(**attributes)
        )
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

    if section_path == "firewall sniffer":
        if attributes.get("name") == str(attributes.get("id")):
            attributes.pop("name", None)
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGFirewallSniffer.model_fields),
        )
        self.config.firewall_sniffers.append(FGFirewallSniffer(**attributes))
        return True

    if section_path == "system session-helper":
        if attributes.get("name") == str(attributes.get("id")):
            attributes["name"] = None
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGSessionHelper.model_fields),
        )
        self.config.session_helpers.append(FGSessionHelper(**attributes))
        return True

    if section_path == "system session-ttl port":
        if attributes.get("name") == str(attributes.get("id")):
            attributes.pop("name", None)
        raw_timeout = attributes.get("timeout")
        if isinstance(raw_timeout, str):
            if raw_timeout.lower() == "never":
                attributes["timeout"] = None
                attributes["timeout_never"] = True
            else:
                try:
                    attributes["timeout"] = int(raw_timeout)
                except ValueError:
                    attributes.setdefault("extra_settings", {})["unparsed_timeout"] = raw_timeout
                    attributes["timeout"] = None
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGSessionTTLOverride.model_fields),
        )
        self.config.session_ttl_overrides.append(
            FGSessionTTLOverride(**attributes)
        )
        return True

    if section_path == "system dhcp server":
        if attributes.get("name") == str(attributes.get("id")):
            attributes.pop("name", None)

        # A malformed edit identifier remains in source inventory. It
        # cannot safely become a typed object whose identity is numeric.
        if "id" not in attributes:
            return True

        for key in FG_DHCP_SERVER_INT_FIELDS:
            self._normalize_optional_int(attributes, key)

        raw_ip_ranges = attributes.pop("ip_ranges", [])
        ip_ranges = []
        for range_attributes in raw_ip_ranges:
            if range_attributes.get("name") == str(range_attributes.get("id")):
                range_attributes.pop("name", None)
            if "id" not in range_attributes:
                continue
            range_attributes.setdefault(
                "source_context", attributes.get("source_context", self.current_context)
            )
            for key in FG_DHCP_RANGE_INT_FIELDS:
                self._normalize_optional_int(range_attributes, key)
            range_attributes["extra_settings"] = _extract_extra_settings(
                range_attributes,
                set(FGDHCPIPRange.model_fields),
            )
            ip_ranges.append(FGDHCPIPRange(**range_attributes))

        raw_exclude_ranges = attributes.pop("exclude_ranges", [])
        exclude_ranges = []
        for range_attributes in raw_exclude_ranges:
            if range_attributes.get("name") == str(range_attributes.get("id")):
                range_attributes.pop("name", None)
            if "id" not in range_attributes:
                continue
            range_attributes.setdefault(
                "source_context", attributes.get("source_context", self.current_context)
            )
            for key in FG_DHCP_RANGE_INT_FIELDS:
                self._normalize_optional_int(range_attributes, key)
            range_attributes["extra_settings"] = _extract_extra_settings(
                range_attributes,
                set(FGDHCPExcludeRange.model_fields),
            )
            exclude_ranges.append(FGDHCPExcludeRange(**range_attributes))

        raw_reservations = attributes.pop("reserved_addresses", [])
        reserved_addresses = []
        for reservation_attributes in raw_reservations:
            if reservation_attributes.get("name") == str(reservation_attributes.get("id")):
                reservation_attributes.pop("name", None)
            if "id" not in reservation_attributes:
                continue
            reservation_attributes.setdefault(
                "source_context", attributes.get("source_context", self.current_context)
            )
            reservation_attributes["extra_settings"] = _extract_extra_settings(
                reservation_attributes,
                set(FGDHCPReservation.model_fields),
            )
            reserved_addresses.append(FGDHCPReservation(**reservation_attributes))

        raw_options = attributes.pop("options", [])
        options = []
        for option_attributes in raw_options:
            if option_attributes.get("name") == str(option_attributes.get("id")):
                option_attributes.pop("name", None)
            if "id" not in option_attributes:
                continue
            option_attributes.setdefault(
                "source_context", attributes.get("source_context", self.current_context)
            )
            for key in FG_DHCP_OPTION_INT_FIELDS:
                self._normalize_optional_int(option_attributes, key)
            raw_ips = option_attributes.get("ip", [])
            if not isinstance(raw_ips, list):
                raw_ips = [raw_ips]
            option_attributes["ips"] = list(raw_ips)
            option_attributes["ip"] = raw_ips[0] if len(raw_ips) == 1 else None
            option_attributes["extra_settings"] = _extract_extra_settings(
                option_attributes,
                set(FGDHCPOption.model_fields),
            )
            options.append(FGDHCPOption(**option_attributes))

        attributes["ip_ranges"] = ip_ranges
        attributes["exclude_ranges"] = exclude_ranges
        attributes["reserved_addresses"] = reserved_addresses
        attributes["options"] = options
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGDHCPServer.model_fields),
        )
        self.config.dhcp_servers.append(FGDHCPServer(**attributes))
        return True

    if section_path == "system dns64":
        attributes.pop("name", None)
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGDns64.model_fields),
        )
        self.config.dns64_settings.append(FGDns64(**attributes))
        return True

    return False
