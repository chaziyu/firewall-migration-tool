"""FortiGate object and topology builders."""

from fwmigrate.parsers.fortigate import parser as parser_module

globals().update({
    name: getattr(parser_module, name)
    for name in dir(parser_module)
    if not name.startswith("__")
})

def build_objects(self: Any, section_path: str, attributes: Dict[str, Any]) -> bool:
    if section_path == "system interface":
        spec = get_section_spec(section_path)
        attributes.setdefault("has_pppoe_password", False)
        attributes.setdefault("pppoe_password_format", None)
        explicit_vdom = attributes.get("vdom")
        effective_vdom = explicit_vdom or self.current_context
        attributes["vdom"] = effective_vdom
        attributes["source_context"] = effective_vdom
        if "vlanid" in attributes:
            vlan_raw = attributes.get("vlanid")
            if not 0 <= vlan_raw <= 4094:
                attributes["unparsed_vlanid"] = attributes.pop("vlanid")

        if "interface" in attributes:
            intf_val = attributes.get("interface")
            if intf_val is True:
                attributes["unparsed_interface"] = attributes.pop("interface")
            elif isinstance(intf_val, list):
                if len(intf_val) == 1 and isinstance(intf_val[0], str) and len(intf_val[0].split()) == 1:
                    attributes["interface"] = intf_val[0].strip()
                else:
                    attributes["unparsed_interface"] = attributes.pop("interface")
            elif isinstance(intf_val, str):
                if len(intf_val.split()) > 1:
                    attributes["unparsed_interface"] = attributes.pop("interface")
            else:
                attributes["unparsed_interface"] = attributes.pop("interface")

        # FortiOS calls this command ``member`` while the typed model uses
        # the plural form to make the ordered relationship explicit.
        # Keep the source command in inventory, but do not leave a second
        # generic copy in source_attributes.
        if "member" in attributes:
            attributes["members"] = attributes.pop("member")
        for source_key, model_key in {
            "aggregate": "aggregate_parent",
            "redundant_interface": "redundant_interface_parent",
        }.items():
            if source_key in attributes:
                attributes[model_key] = attributes.pop(source_key)
        raw_secondary_ips = attributes.pop("secondary_ips", [])
        secondary_ips = []
        for raw_item in raw_secondary_ips:
            item = dict(raw_item)
            if "id" not in item and item.get("name", "").isdigit():
                item["id"] = int(item["name"])
            if item.get("name") == str(item.get("id")):
                item.pop("name", None)

            item["extra_settings"] = _extract_extra_settings(
                item,
                set(FGInterfaceSecondaryIP.model_fields),
            )
            secondary_ips.append(FGInterfaceSecondaryIP(**item))

        attributes["secondary_ips"] = secondary_ips
        raw_extra_addresses = attributes.pop("ipv6_extra_addresses", [])
        attributes["ipv6_extra_addresses"] = [
            item if isinstance(item, FGInterfaceIPv6ExtraAddress)
            else FGInterfaceIPv6ExtraAddress(**item)
            for item in raw_extra_addresses
        ]

        explicit_settings = {
            key: (
                str(value)
                if spec and key in spec.integer_fields and value is not None
                else value
            )
            for key, value in attributes.items()
            if key not in {
                "name",
                "id",
                "members",
                "source_explicit_fields",
                "lacp_mode",
                "lacp_ha_secondary",
                "system_id_type",
                "system_id",
                "lacp_speed",
                "min_links",
                "min_links_down",
                "algorithm",
                "aggregate_type",
                "priority_override",
                "aggregate_parent",
                "redundant_interface_parent",
                "secondary_ips",
                "client_options",
                "dhcp_snooping_server_list",
                "tagging",
                "vrrp",
                "egress_queues",
                "l2tp_client_settings",
                "ipv6_extra_addresses",
                "ipv6_prefix_advertisements",
                "ipv6_delegated_prefix_advertisements",
                "dhcp6_iapd",
                "vrrp6",
                "nested_configs",
                "ipv6_source_settings",
                "ip6_address",
                "ip6_allowaccess",
                "ip6_mode",
                "ip6_send_adv",
                "ip6_manage_flag",
                "ip6_other_flag",
                "ipv6_autoconf", *FG_INTERFACE_IPV6_SCALAR_FIELDS,
                *FG_INTERFACE_IPV6_LIST_FIELDS,
                "has_pppoe_password",
                "pppoe_password_format",
            }
        }

        attributes["source_attributes"] = (
            sanitize_source_attributes(
                explicit_settings
            )
        )
        attributes.pop("password", None)

        self.config.interfaces.append(
            FGInterface(**attributes)
        )
        return True

    if section_path == "firewall address":
        attributes["extra_settings"] = (
            _extract_extra_settings(
                attributes,
                set(FGAddress.model_fields),
            )
        )

        self.config.addresses.append(
            FGAddress(**attributes)
        )
        return True

    if section_path == "firewall address6":
        attributes["is_ipv6"] = True
        self._normalize_address_nested_entries(attributes)
        attributes["extra_settings"] = (
            _extract_extra_settings(
                attributes,
                set(FGAddress.model_fields)
            )
        )

        self.config.addresses.append(
            FGAddress(**attributes)
        )
        return True

    if section_path == "firewall address6-template":
        attributes["extra_settings"] = _extract_extra_settings(
            attributes, set(FGAddress6Template.model_fields)
        )
        self.config.address6_templates.append(FGAddress6Template(**attributes))
        return True

    if section_path == "firewall multicast-address6":
        attributes["is_ipv6"] = True
        attributes["is_multicast"] = True
        attributes.setdefault("ip6", "::/0")
        self._normalize_address_nested_entries(attributes)
        attributes["extra_settings"] = (
            _extract_extra_settings(
                attributes,
                set(FGAddress.model_fields)
            )
        )

        self.config.addresses.append(
            FGAddress(**attributes)
        )
        return True

    if section_path == "firewall multicast-address":
        attributes["is_multicast"] = True
        attributes.setdefault("type", "multicastrange")
        self._normalize_address_nested_entries(attributes)
        attributes["extra_settings"] = (
            _extract_extra_settings(
                attributes,
                set(FGAddress.model_fields)
            )
        )

        self.config.addresses.append(
            FGAddress(**attributes)
        )
        return True

    if section_path in {"firewall addrgrp", "firewall addrgrp6"}:
        tagging = []
        for entry in attributes.get("tagging", []):
            entry["extra_settings"] = _extract_extra_settings(
                entry, set(FGAddressGroupTaggingEntry.model_fields)
            )
            tagging.append(FGAddressGroupTaggingEntry(**entry))
        attributes["tagging"] = tagging
        attributes["is_ipv6"] = section_path == "firewall addrgrp6"
        attributes["extra_settings"] = (
            _extract_extra_settings(
                attributes,
                set(FGAddressGroup.model_fields),
            )
        )

        self.config.address_groups.append(
            FGAddressGroup(**attributes)
        )
        return True

    if section_path == "firewall service custom":
        attributes["source_protocol_configured"] = attributes.get(
            "protocol"
        )
        attributes["extra_settings"] = (
            _extract_extra_settings(
                attributes,
                set(FGService.model_fields),
            )
        )

        self.config.services.append(
            FGService(**attributes)
        )
        if self.config.services[-1].session_ttl is not None:
            self.config.services[-1].extra_settings["session_ttl"] = str(
                self.config.services[-1].session_ttl
            )
        return True

    if section_path in {
        "firewall schedule recurring",
        "firewall schedule onetime",
    }:
        schedule_model = FGSchedule
        attributes["type"] = (
            "onetime" if section_path.endswith("onetime") else "recurring"
        )
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(schedule_model.model_fields),
        )
        self.config.schedules.append(
            schedule_model(**attributes)
        )
        return True

    if section_path == "firewall shaper traffic-shaper":
        for key in (
            "guaranteed_bandwidth", "maximum_bandwidth", "exceed_bandwidth",
            "exceed_class_id",
        ):
            self._normalize_optional_int(attributes, key)
        overhead_val = attributes.pop("overhead", None)
        if overhead_val is not None:
            try:
                attributes["overhead"] = int(overhead_val)
            except (ValueError, TypeError):
                attributes.setdefault("extra_settings", {})["overhead"] = overhead_val
        attributes["extra_settings"] = {
            **attributes.get("extra_settings", {}),
            **_extract_extra_settings(
                attributes,
                set(FGTrafficShaper.model_fields),
            ),
        }
        self.config.traffic_shapers.append(
            FGTrafficShaper(**attributes)
        )
        return True

    if section_path == "firewall ippool":
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGIPPool.model_fields),
        )
        self.config.ip_pools.append(
            FGIPPool(**attributes)
        )
        return True

    if section_path in {"firewall vip", "firewall vip6"}:
        raw_realservers = attributes.pop("realservers", [])
        realservers = []
        for raw_server in raw_realservers:
            server = dict(raw_server)
            if server.get("name") == str(server.get("id")):
                server.pop("name", None)
            server["extra_settings"] = _extract_extra_settings(
                server,
                set(FGVIPRealServer.model_fields),
            )
            realservers.append(FGVIPRealServer(**server))
        attributes["realservers"] = realservers

        vip_model = FGVIP if section_path == "firewall vip" else FGVIP6
        attributes["extra_settings"] = (
            _extract_extra_settings(
                attributes,
                set(vip_model.model_fields),
            )
        )

        if section_path == "firewall vip":
            self.config.vips.append(FGVIP(**attributes))
        else:
            self.config.vips6.append(FGVIP6(**attributes))
        return True

    if section_path == "firewall vipgrp":
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGVIPGroup.model_fields),
        )
        self.config.vip_groups.append(
            FGVIPGroup(**attributes)
        )
        return True

    if section_path == "firewall vipgrp6":
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGVIPGroup6.model_fields),
        )
        self.config.vip_groups6.append(FGVIPGroup6(**attributes))
        return True

    return False
