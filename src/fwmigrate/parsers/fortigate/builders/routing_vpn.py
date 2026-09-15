"""FortiGate routing, VPN, and SD-WAN builders."""

from fwmigrate.parsers.fortigate import parser as parser_module

globals().update({
    name: getattr(parser_module, name)
    for name in dir(parser_module)
    if not name.startswith("__")
})

def build_routing_vpn(self: Any, section_path: str, attributes: Dict[str, Any]) -> bool:
    if section_path in POLICY_ROUTE_FAMILIES:
        self._source_order += 1
        route_id = attributes.pop("id", None)
        route_name = attributes.pop("name", None)
        context = attributes.pop("source_context", self.current_context)
        nested_configs = attributes.pop("nested_configs", [])
        source_explicit_fields = attributes.pop("source_explicit_fields", set())
        source_attributes = sanitize_source_attributes({
            key: (
                str(value)
                if spec and key in spec.integer_fields and value is not None
                else value
            )
            for key, value in attributes.items()
        })
        if route_id is None and route_name is not None:
            attributes["unparsed_id"] = route_name
        attributes["extra_settings"] = _extract_extra_settings(
            attributes, set(FGPolicyRoute.model_fields)
        )
        self.config.policy_routes.append(
            FGPolicyRoute(
                id=route_id,
                family=POLICY_ROUTE_FAMILIES[section_path],
                source_order=self._source_order,
                source_context=context,
                nested_configs=nested_configs,
                source_attributes=source_attributes,
                source_explicit_fields=source_explicit_fields,
                **attributes,
            )
        )
        return True

    if section_path in SOURCE_ONLY_RULE_FAMILIES:
        self._source_order += 1
        rule_id = attributes.pop("id", None)
        name = attributes.pop("name", None)
        context = attributes.pop("source_context", self.current_context)
        status = attributes.get("status")
        nested_configs = attributes.pop("nested_configs", [])
        settings = sanitize_source_attributes(attributes)
        rule_type = FGSourceOnlyRule
        if section_path in {"firewall local-in-policy", "firewall local-in-policy6"}:
            rule_type = FGLocalInPolicy
        elif section_path == "firewall security-policy":
            rule_type = FGSecurityPolicy
        elif section_path == "firewall shaping-policy":
            rule_type = FGShapingPolicy
        elif section_path == "vpn ipsec phase1":
            rule_type = FGPhase1Policy
        elif section_path == "vpn ipsec phase2":
            rule_type = FGPhase2Policy
        elif section_path == "system dhcp6 server":
            rule_type = FGDHCP6Server
        typed_attributes = {}
        if rule_type is not FGSourceOnlyRule:
            inherited_fields = {
                "family", "id", "name", "source_order", "status",
                "source_context", "settings", "nested_configs", "extra_settings",
                "source_explicit_fields",
            }
            semantic_fields = set(rule_type.model_fields) - inherited_fields
            typed_attributes = {
                key: value
                for key, value in settings.items()
                if key in semantic_fields
            }
            if "source_explicit_fields" in rule_type.model_fields:
                typed_attributes["source_explicit_fields"] = set(
                    settings.get("source_explicit_fields", set())
                )
            if rule_type is FGLocalInPolicy:
                typed_attributes["address_family"] = (
                    "ipv6" if section_path.endswith("6") else "ipv4"
                )
            typed_attributes["extra_settings"] = {
                key: value
                for key, value in settings.items()
                if key not in semantic_fields and key not in inherited_fields
            }
            if rule_type is FGSecurityPolicy:
                typed_attributes["ngfw_mode"] = self._execution_context().ngfw_mode
                for key in ("application", "app_category"):
                    self._normalize_int_list(typed_attributes, key)
                    if f"unparsed_{key}" in typed_attributes:
                        typed_attributes["extra_settings"][f"unparsed_{key}"] = typed_attributes.pop(
                            f"unparsed_{key}"
                        )
            if rule_type is FGShapingPolicy:
                for key in ("application", "app_category"):
                    self._normalize_int_list(typed_attributes, key)
                    if f"unparsed_{key}" in typed_attributes:
                        typed_attributes["extra_settings"][f"unparsed_{key}"] = typed_attributes.pop(
                            f"unparsed_{key}"
                        )
            if "dhgrp" in typed_attributes:
                self._normalize_int_list(typed_attributes, "dhgrp")
            for key in (
                "aggregate_weight", "dpd_retrycount", "dpd_retryinterval",
                "auto_discovery_offer_interval",
                "fragmentation_mtu", "idle_timeoutinterval", "ipv6_prefix",
                "keepalive", "keylife", "negotiate_timeout", "priority",
                "distance", "ip_delay_interval", "keylifeseconds",
                "keylifekbs", "initiator_autoclose", "network_id",
            ):
                self._normalize_optional_int(typed_attributes, key)
            if rule_type is FGDHCP6Server:
                self._normalize_optional_int(typed_attributes, "lease_time")
                raw_ip_ranges = attributes.get("ip_ranges", [])
                ip_ranges = []
                for r in raw_ip_ranges:
                    self._normalize_optional_int(r, "id")
                    r["extra_settings"] = _extract_extra_settings(r, set(FGDHCP6IPRange.model_fields))
                    ip_ranges.append(FGDHCP6IPRange(**r))
                typed_attributes["ip_ranges"] = ip_ranges
                raw_prefixes = attributes.get("prefix_ranges", [])
                prefix_ranges = []
                for p in raw_prefixes:
                    self._normalize_optional_int(p, "id")
                    self._normalize_optional_int(p, "prefix_length")
                    p["extra_settings"] = _extract_extra_settings(p, set(FGDHCP6PrefixRange.model_fields))
                    prefix_ranges.append(FGDHCP6PrefixRange(**p))
                typed_attributes["prefix_ranges"] = prefix_ranges
                raw_options = attributes.get("options", [])
                options = []
                for o in raw_options:
                    self._normalize_optional_int(o, "id")
                    self._normalize_optional_int(o, "code")
                    raw_ip6 = o.get("ip6", [])
                    if isinstance(raw_ip6, list):
                        o["ip6"] = raw_ip6[0] if raw_ip6 else None
                    o["extra_settings"] = _extract_extra_settings(o, set(FGDHCP6Option.model_fields))
                    options.append(FGDHCP6Option(**o))
                typed_attributes["options"] = options
        rule = rule_type(
            family=SOURCE_ONLY_RULE_FAMILIES[section_path],
            id=rule_id,
            name=name,
            source_order=self._source_order,
            status=status,
            source_context=context,
            settings=settings,
            nested_configs=nested_configs,
            **typed_attributes,
        )
        target = {
            "firewall security-policy": self.config.security_policies,
            "router policy": self.config.policy_routes,
            "router policy6": self.config.policy_routes,
            "firewall local-in-policy": self.config.local_in_policies,
            "firewall local-in-policy6": self.config.local_in_policies,
            "firewall proxy-policy": self.config.proxy_policies,
            "firewall shaping-policy": self.config.shaping_policies,
            "vpn ipsec phase1": self.config.phase1_policies,
            "vpn ipsec phase2": self.config.phase2_policies,
            "system dhcp6 server": self.config.dhcp6_servers,
        }.get(section_path, self.config.source_only_rules)
        target.append(rule)
        return True

    if section_path == "ips sensor":
        raw_entries = attributes.pop("entries", [])
        entries = []

        for raw_entry in raw_entries:
            entry = dict(raw_entry)
            if entry.get("name") == str(entry.get("id")):
                entry.pop("name", None)

            raw_rules = entry.pop("rule", [])
            if not isinstance(raw_rules, list):
                raw_rules = [raw_rules]

            rules = []
            unparsed_rules = []
            for value in raw_rules:
                try:
                    rules.append(int(value))
                except (TypeError, ValueError):
                    unparsed_rules.append(value)

            entry["rules"] = rules
            if unparsed_rules:
                entry["unparsed_rule_values"] = unparsed_rules

            for numeric_field in (
                "rate_count",
                "rate_duration",
            ):
                raw_value = entry.get(numeric_field)
                if raw_value is None:
                    continue
                try:
                    entry[numeric_field] = int(raw_value)
                except (TypeError, ValueError):
                    entry.pop(numeric_field, None)
                    entry[
                        f"unparsed_{numeric_field}"
                    ] = raw_value

            raw_vuln_types = entry.get("vuln_type", [])
            vuln_types = []
            for value in raw_vuln_types:
                try:
                    vuln_types.append(int(value))
                except (TypeError, ValueError):
                    entry.setdefault("unparsed_vuln_type", []).append(value)
            entry["vuln_type"] = vuln_types
            entry["exempt_ips"] = [
                FGIPSSensorExemptIP(**exempt)
                for exempt in entry.get("exempt_ips", [])
            ]

            entry["extra_settings"] = _extract_extra_settings(
                entry,
                set(FGIPSSensorEntry.model_fields),
            )
            entries.append(FGIPSSensorEntry(**entry))

        attributes["entries"] = entries
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGIPSSensor.model_fields),
        )
        self.config.ips_sensors.append(
            FGIPSSensor(**attributes)
        )
        return True

    if section_path == "vpn ipsec phase1-interface":
        self._normalize_int_list(attributes, "dhgrp")
        for key in (
            "aggregate_weight", "dpd_retrycount", "dpd_retryinterval",
            "auto_discovery_offer_interval",
            "fragmentation_mtu", "idle_timeoutinterval", "ipv6_prefix",
            "keepalive", "keylife", "negotiate_timeout", "priority",
            "distance", "ip_delay_interval", "network_id",
        ):
            self._normalize_optional_int(attributes, key)
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGPhase1Interface.model_fields),
        )
        self.config.phase1_interfaces.append(
            FGPhase1Interface(**attributes)
        )
        return True

    if section_path == "vpn ipsec phase2-interface":
        for key in (
            "keylife", "keylifeseconds", "keylifekbs",
            "initiator_autoclose", "network_id",
        ):
            self._normalize_optional_int(attributes, key)
        self._normalize_int_list(attributes, "dhgrp")
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGPhase2Interface.model_fields),
        )
        self.config.phase2_interfaces.append(
            FGPhase2Interface(**attributes)
        )
        return True

    if section_path in {
        "vpn certificate remote",
        "vpn certificate local",
        "vpn certificate ca",
        "certificate remote",
        "certificate local",
        "certificate ca",
    }:
        attributes["certificate_type"] = section_path.rsplit(" ", 1)[-1]
        raw_last_updated = attributes.get("last_updated")
        if raw_last_updated is not None:
            try:
                attributes["last_updated"] = int(raw_last_updated)
            except (TypeError, ValueError):
                attributes.pop("last_updated", None)
                attributes["last_updated_raw"] = raw_last_updated

        public_certificate = attributes.get("public_certificate")

        if public_certificate:
            attributes.update(
                parse_certificate_metadata(public_certificate)
            )

        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGCertificate.model_fields),
        )
        self.config.certificates.append(
            FGCertificate(**attributes)
        )
        return True

    if section_path in {
        "firewall ssh local-key",
        "firewall ssh local-ca",
    }:
        attributes["key_type"] = section_path.rsplit(" ", 1)[-1]
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGSSHKey.model_fields),
        )
        self.config.ssh_keys.append(FGSSHKey(**attributes))
        return True

    if section_path in {"router static", "router static6"}:
        if attributes.get("name") == str(attributes.get("id")):
            attributes.pop("name", None)
        if isinstance(attributes.get("dst"), list):
            attributes["dst"] = " ".join(attributes["dst"])
        attributes["address_family"] = (
            "ipv6" if section_path == "router static6" else "ipv4"
        )
        for field in (
            "distance",
            "priority",
            "weight",
            "vrf",
            "tag",
            "internet_service",
            "devindex",
        ):
            self._normalize_optional_int(attributes, field)
            # Do not let an invalid explicitly supplied value fall back
            # to the FortiOS effective default.  The unparsed value is
            # retained in extra_settings for manual review.
            if f"unparsed_{field}" in attributes:
                attributes[field] = None
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGStaticRoute.model_fields),
        )
        self.config.static_routes.append(
            FGStaticRoute(**attributes)
        )
        return True

    if section_path == "system sdwan zone":
        sdwan = self._sdwan_for_current_context()
        attributes["source_context"] = sdwan.source_context
        self._normalize_optional_int(attributes, "minimum_sla_meet_members")

        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGSDWanZone.model_fields),
        )
        sdwan.zones.append(
            FGSDWanZone(**attributes)
        )
        return True

    if section_path == "system sdwan members":
        sdwan = self._sdwan_for_current_context()
        attributes["source_context"] = sdwan.source_context

        if attributes.get("name") == str(attributes.get("id")):
            attributes.pop("name", None)
        for field in (
            "cost",
            "weight",
            "priority",
            "priority6",
            "spillover_threshold",
            "ingress_spillover_threshold",
            "transport_group",
            "volume_ratio",
        ):
            self._normalize_optional_int(attributes, field)
            if f"unparsed_{field}" in attributes:
                attributes[field] = None
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGSDWanMember.model_fields),
        )
        sdwan.members.append(
            FGSDWanMember(**attributes)
        )
        return True

    if section_path == "system sdwan health-check":
        sdwan = self._sdwan_for_current_context()
        attributes["source_context"] = sdwan.source_context
        self._normalize_int_list(attributes, "members")
        for field in FG_SDWAN_HEALTH_CHECK_INT_FIELDS:
            self._normalize_optional_int(attributes, field)
        servers = list(attributes.get("server", []))
        attributes["servers"] = servers
        attributes["server"] = servers[0] if len(servers) == 1 else None
        raw_sla = attributes.pop("sla", [])
        sla = []
        for entry in raw_sla:
            entry["source_context"] = sdwan.source_context
            if entry.get("name") == str(entry.get("id")):
                entry.pop("name", None)
            self._normalize_optional_int(entry, "id")
            for field in FG_SDWAN_HEALTH_CHECK_SLA_INT_FIELDS:
                self._normalize_optional_int(entry, field)
            entry["source_explicit_fields"] = set(entry.get("source_explicit_fields", set()))
            entry["extra_settings"] = _extract_extra_settings(
                entry,
                set(FGSDWanSLA.model_fields),
            )
            sla.append(FGSDWanSLA(**entry))
        attributes["sla"] = sla
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGSDWanHealthCheck.model_fields),
        )
        sdwan.health_checks.append(
            FGSDWanHealthCheck(**attributes)
        )
        return True

    if section_path == "system sdwan service":
        sdwan = self._sdwan_for_current_context()
        attributes["source_context"] = sdwan.source_context
        if attributes.get("name") == str(attributes.get("id")):
            attributes["name"] = None
        for field in FG_SDWAN_SERVICE_INT_FIELDS:
            self._normalize_optional_int(attributes, field)
        for field in FG_SDWAN_SERVICE_INT_LIST_FIELDS:
            self._normalize_int_list(attributes, field)
        raw_sla = attributes.pop("sla", [])
        sla = []
        for entry in raw_sla:
            entry["source_context"] = sdwan.source_context
            source_name = str(entry.get("name", entry.get("id", "")))
            entry["name"] = source_name
            self._normalize_optional_int(entry, "id")
            entry["source_explicit_fields"] = set(entry.get("source_explicit_fields", set()))
            entry["extra_settings"] = _extract_extra_settings(
                entry,
                set(FGSDWanServiceSLA.model_fields),
            )
            sla.append(FGSDWanServiceSLA(**entry))
        attributes["sla"] = sla
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGSDWanService.model_fields),
        )
        sdwan.services.append(FGSDWanService(**attributes))
        return True

    if section_path == "system sdwan duplication":
        sdwan = self._sdwan_for_current_context()
        attributes["source_context"] = sdwan.source_context
        if attributes.get("name") == str(attributes.get("id")):
            attributes.pop("name", None)
        self._normalize_optional_int(attributes, "service_id")
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGSDWanDuplication.model_fields),
        )
        sdwan.duplication_rules.append(
            FGSDWanDuplication(**attributes)
        )
        return True

    if section_path == "system sdwan neighbor":
        sdwan = self._sdwan_for_current_context()
        attributes["source_context"] = sdwan.source_context
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGSDWanNeighbor.model_fields),
        )
        sdwan.neighbors.append(FGSDWanNeighbor(**attributes))
        return True

    return False

