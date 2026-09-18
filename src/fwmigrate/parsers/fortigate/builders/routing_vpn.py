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
        rule_type = {
            "firewall security-policy": FGSecurityPolicy,
            "vpn ipsec phase1": FGPhase1Policy,
            "vpn ipsec phase2": FGPhase2Policy,
        }.get(section_path)
        if rule_type is None:
            return False
        settings = sanitize_source_attributes(attributes)
        inherited_fields = {
            "family", "id", "name", "source_order", "status",
            "source_context", "nested_configs", "extra_settings",
            "source_explicit_fields",
        }
        semantic_fields = set(rule_type.model_fields) - inherited_fields
        typed_attributes = {
            key: value for key, value in settings.items() if key in semantic_fields
        }
        typed_attributes["source_explicit_fields"] = set(
            settings.get("source_explicit_fields", set())
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
        if "dhgrp" in typed_attributes:
            self._normalize_int_list(typed_attributes, "dhgrp")
        for key in (
            "aggregate_weight", "dpd_retrycount", "dpd_retryinterval",
            "auto_discovery_offer_interval", "fragmentation_mtu",
            "idle_timeoutinterval", "ipv6_prefix", "keepalive", "keylife",
            "negotiate_timeout", "priority", "distance", "ip_delay_interval",
            "keylifeseconds", "keylifekbs", "initiator_autoclose", "network_id",
        ):
            self._normalize_optional_int(typed_attributes, key)
        rule = rule_type(
            family=SOURCE_ONLY_RULE_FAMILIES[section_path],
            id=rule_id,
            name=name,
            source_order=self._source_order,
            status=status,
            source_context=context,
            nested_configs=nested_configs,
            extra_settings=typed_attributes.pop("extra_settings", {}),
            **typed_attributes,
        )
        target = {
            "firewall security-policy": self.config.security_policies,
            "vpn ipsec phase1": self.config.phase1_policies,
            "vpn ipsec phase2": self.config.phase2_policies,
        }.get(section_path)
        if target is None:
            return False
        target.append(rule)
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
