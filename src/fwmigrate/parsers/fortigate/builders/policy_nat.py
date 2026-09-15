"""FortiGate policy and NAT builders."""

from fwmigrate.parsers.fortigate import parser as parser_module

globals().update({
    name: getattr(parser_module, name)
    for name in dir(parser_module)
    if not name.startswith("__")
})

def build_policy_nat(self: Any, section_path: str, attributes: Dict[str, Any]) -> bool:
    if section_path == "firewall policy":
        exec_ctx = self._execution_context()
        attributes["ngfw_mode"] = exec_ctx.ngfw_mode
        attributes["central_nat"] = exec_ctx.central_nat
        has_ipv4 = any(attributes.get(field) for field in ("srcaddr", "dstaddr", "internet_service", "internet_service_src"))
        has_ipv6 = any(attributes.get(field) for field in ("srcaddr6", "dstaddr6", "internet_service6", "internet_service6_src"))
        attributes["address_family"] = "ipv6" if has_ipv6 and not has_ipv4 else "dual-stack"
        compatibility_internet_service_settings = {
            key: list(attributes[key])
            for key in (
                "internet_service_custom", "internet_service_custom_group",
                "internet_service_src_custom", "internet_service_src_custom_group",
                "internet_service6_custom", "internet_service6_custom_group",
                "internet_service6_src_custom", "internet_service6_src_custom_group",
            )
            if attributes.get(key)
        }
        attributes["extra_settings"] = (
            _extract_extra_settings(
                attributes,
                set(FGPolicy.model_fields),
            )
        )
        attributes["extra_settings"].update(compatibility_internet_service_settings)

        self.config.policies.append(
            FGPolicy(**attributes)
        )
        return True

    if section_path in {"firewall multicast-policy", "firewall multicast-policy6"}:
        self._source_order += 1
        attributes["source_order"] = self._source_order
        extra_settings = {}
        if section_path.endswith("6"):
            for field in ("snat", "snat_ip", "dnat", "traffic_shaper"):
                if field in attributes:
                    extra_settings[field] = attributes.pop(field)
        extra_settings.update(_extract_extra_settings(
            attributes, set(FGMulticastPolicy.model_fields)
        ))
        attributes["extra_settings"] = extra_settings
        target = self.config.multicast_policies6 if section_path.endswith("6") else self.config.multicast_policies
        target.append(FGMulticastPolicy(**attributes))
        return True

    if section_path == "firewall central-snat-map":
        self._source_order += 1
        attributes["source_order"] = self._source_order
        if attributes.get("name") == str(attributes.get("id")):
            attributes.pop("name", None)
        attributes["extra_settings"] = _extract_extra_settings(
            attributes, set(FGCentralSNATRule.model_fields)
        )
        self.config.central_snat_rules.append(FGCentralSNATRule(**attributes))
        return True

    if section_path == "firewall ip-translation":
        self._source_order += 1
        attributes["source_order"] = self._source_order
        attributes["extra_settings"] = _extract_extra_settings(
            attributes, set(FGIPTranslation.model_fields)
        )
        self.config.ip_translations.append(FGIPTranslation(**attributes))
        return True

    if section_path == "firewall internet-service-name":
        validation_settings: Dict[str, Any] = {}
        raw_id = attributes.pop("internet_service_id", None)
        attributes["id"] = _parse_bounded_int(
            raw_id,
            minimum=0,
            maximum=4294967295,
            field_name="internet_service_id",
            extra_settings=validation_settings,
        )
        if raw_id is not None and attributes["id"] is None:
            validation_settings["unparsed_internet_service_id"] = raw_id
        for field in ("city_id", "country_id", "region_id"):
            attributes[field] = _parse_bounded_int(
                attributes.pop(field, None),
                minimum=0,
                maximum=4294967295,
                field_name=field,
                extra_settings=validation_settings,
            )
        attributes["service_type"] = _parse_enum(
            attributes.pop("type", None),
            field_name="type",
            allowed={"default", "location"},
            extra_settings=validation_settings,
        )
        attributes.update(validation_settings)
        attributes["extra_settings"] = _extract_extra_settings(
            attributes, set(FGInternetService.model_fields)
        )
        self.config.internet_services.append(FGInternetService(**attributes))
        return True

    if section_path == "firewall internet-service-custom":
        entries = [
            _typed_internet_item(
                entry,
                FGInternetServiceCustomEntry,
                int_ranges={"id": (0, 255), "protocol": (0, 255)},
                enums={"addr_mode": {"ipv4", "ipv6"}},
            )
            for entry in attributes.pop("entries", [])
        ]
        attributes["entries"] = [
            item.model_dump() if hasattr(item, "model_dump") else item for item in entries
        ]
        validation_settings: Dict[str, Any] = {}
        if "reputation" in attributes:
            attributes["reputation"] = _parse_bounded_int(
                attributes["reputation"],
                minimum=0,
                maximum=4294967295,
                field_name="reputation",
                extra_settings=validation_settings,
            )
        attributes.update(validation_settings)
        attributes["extra_settings"] = _extract_extra_settings(
            attributes, set(FGInternetServiceCustom.model_fields)
        )
        self.config.custom_internet_services.append(FGInternetServiceCustom(**attributes))
        return True

    if section_path == "firewall internet-service-custom-group":
        attributes["members"] = attributes.pop("member", [])
        attributes["extra_settings"] = _extract_extra_settings(
            attributes, set(FGInternetServiceCustomGroup.model_fields)
        )
        self.config.custom_internet_service_groups.append(FGInternetServiceCustomGroup(**attributes))
        return True

    if section_path == "firewall internet-service-addition":
        entries = []
        for entry in attributes.pop("entries", []):
            ranges = [
                _typed_internet_item(
                    port_range,
                    FGInternetServiceAdditionPortRange,
                    int_ranges={"id": (0, 4294967295), "start_port": (0, 65535), "end_port": (0, 65535)},
                )
                for port_range in entry.pop("port_ranges", [])
            ]
            entry["port_ranges"] = [item.model_dump() for item in ranges]
            entries.append(_typed_internet_item(
                entry,
                FGInternetServiceAdditionEntry,
                int_ranges={"id": (0, 255), "protocol": (0, 255)},
                enums={"addr_mode": {"ipv4", "ipv6"}},
            ))
        attributes["entries"] = [item.model_dump() for item in entries]
        validation_settings: Dict[str, Any] = {}
        attributes["id"] = _parse_bounded_int(
            attributes.get("id"), minimum=0, maximum=4294967295,
            field_name="id", extra_settings=validation_settings,
        )
        attributes.update(validation_settings)
        if attributes.get("name") == str(attributes.get("id")):
            attributes.pop("name", None)
        attributes["extra_settings"] = _extract_extra_settings(
            attributes, set(FGInternetServiceAddition.model_fields)
        )
        self.config.internet_service_additions.append(FGInternetServiceAddition(**attributes))
        return True

    if section_path == "firewall internet-service-append":
        self.config.internet_service_appends.append(_typed_internet_item(
            attributes,
            FGInternetServiceAppend,
            int_ranges={"append_port": (0, 65535), "match_port": (0, 65535)},
            enums={"addr_mode": {"ipv4", "ipv6", "both"}},
        ))
        return True

    if section_path == "firewall internet-service-extension":
        disable_entries = []
        for entry in attributes.pop("disable_entries", []):
            ipv4_ranges = [
                _typed_internet_item(
                    range_item,
                    FGInternetServiceExtensionIPv4Range,
                    int_ranges={"id": FG_IS_EXTENSION_IP_RANGE_ID_RANGE},
                )
                for range_item in entry.pop("ip_range", [])
            ]
            ipv6_ranges = [
                _typed_internet_item(
                    range_item,
                    FGInternetServiceExtensionIPv6Range,
                    int_ranges={"id": FG_IS_EXTENSION_IP6_RANGE_ID_RANGE},
                )
                for range_item in entry.pop("ip6_range", [])
            ]
            entry["ip_range"] = [item.model_dump() for item in ipv4_ranges]
            entry["ip6_range"] = [item.model_dump() for item in ipv6_ranges]
            ranges = [
                _typed_internet_item(
                    port_range,
                    FGInternetServiceExtensionPortRange,
                    int_ranges={"id": FG_IS_EXTENSION_PORT_RANGE_ID_RANGE, "start_port": (0, 65535), "end_port": (0, 65535)},
                )
                for port_range in entry.pop("port_ranges", [])
            ]
            entry["port_ranges"] = [item.model_dump() for item in ranges]
            disable_entries.append(_typed_internet_item(
                entry,
                FGInternetServiceExtensionDisableEntry,
                int_ranges={"id": FG_IS_EXTENSION_DISABLE_ENTRY_ID_RANGE, "protocol": FORTIOS_UINT8_RANGE},
                enums={"addr_mode": FG_IS_EXTENSION_ADDR_MODES},
            ))
        entries = []
        for entry in attributes.pop("entries", []):
            ranges = [
                _typed_internet_item(
                    port_range,
                    FGInternetServiceExtensionPortRange,
                    int_ranges={"id": FG_IS_EXTENSION_PORT_RANGE_ID_RANGE, "start_port": (0, 65535), "end_port": (0, 65535)},
                )
                for port_range in entry.pop("port_ranges", [])
            ]
            entry["port_ranges"] = [item.model_dump() for item in ranges]
            entries.append(_typed_internet_item(
                entry,
                FGInternetServiceExtensionEntry,
                int_ranges={"id": FG_IS_EXTENSION_ENTRY_ID_RANGE, "protocol": FORTIOS_UINT8_RANGE},
                enums={"addr_mode": FG_IS_EXTENSION_ADDR_MODES},
            ))
        attributes["disable_entries"] = [item.model_dump() for item in disable_entries]
        attributes["entries"] = [item.model_dump() for item in entries]
        validation_settings: Dict[str, Any] = {}
        attributes["id"] = _parse_bounded_int(
            attributes.get("id"), minimum=0, maximum=4294967295,
            field_name="id", extra_settings=validation_settings,
        )
        attributes.update(validation_settings)
        if attributes.get("name") == str(attributes.get("id")):
            attributes.pop("name", None)
        attributes["extra_settings"] = _extract_extra_settings(
            attributes, set(FGInternetServiceExtension.model_fields)
        )
        self.config.internet_service_extensions.append(FGInternetServiceExtension(**attributes))
        return True

    if section_path == "firewall internet-service-group":
        attributes["members"] = attributes.pop("member", [])
        validation_settings: Dict[str, Any] = {}
        raw_direction = attributes.get("direction", "both")
        parsed_direction = _parse_enum(
            raw_direction,
            field_name="direction",
            allowed={"source", "destination", "both"},
            extra_settings=validation_settings,
        )
        attributes["direction"] = parsed_direction if parsed_direction is not None else str(raw_direction).lower()
        attributes.update(validation_settings)
        attributes["extra_settings"] = _extract_extra_settings(
            attributes, set(FGInternetServiceGroup.model_fields)
        )
        self.config.internet_service_groups.append(FGInternetServiceGroup(**attributes))
        return True

    if section_path == "firewall internet-service-definition":
        attributes.pop("name", None)
        raw_entries = attributes.pop("entries", [])
        entries = []
        for entry_attributes in raw_entries:
            entry_attributes["seq_num"] = entry_attributes.pop("id", None)
            if entry_attributes.get("name") == str(entry_attributes["seq_num"]):
                entry_attributes.pop("name", None)
            raw_port_ranges = entry_attributes.pop("port_ranges", [])
            port_ranges = []
            for range_attributes in raw_port_ranges:
                range_attributes.pop("name", None)
                validation_settings: Dict[str, Any] = {}
                for field, minimum, maximum in (
                    ("id", 0, 4294967295),
                    ("start_port", 1, 65535),
                    ("end_port", 1, 65535),
                ):
                    if field in range_attributes:
                        range_attributes[field] = _parse_bounded_int(
                            range_attributes[field], minimum=minimum, maximum=maximum,
                            field_name=field, extra_settings=validation_settings,
                        )
                range_attributes.update(validation_settings)
                range_attributes["extra_settings"] = _extract_extra_settings(
                    range_attributes,
                    set(FGInternetServiceDefinitionPortRange.model_fields),
                )
                port_ranges.append(FGInternetServiceDefinitionPortRange(**range_attributes))
            entry_attributes["port_ranges"] = port_ranges
            validation_settings = {}
            entry_attributes["seq_num"] = _parse_bounded_int(
                entry_attributes.get("seq_num"), minimum=0, maximum=4294967295,
                field_name="seq_num", extra_settings=validation_settings,
            )
            for field, minimum, maximum in (("category_id", 0, 4294967295), ("protocol", 0, 255)):
                if field in entry_attributes:
                    entry_attributes[field] = _parse_bounded_int(
                        entry_attributes[field], minimum=minimum, maximum=maximum,
                        field_name=field, extra_settings=validation_settings,
                    )
            entry_attributes.update(validation_settings)
            entry_attributes["extra_settings"] = _extract_extra_settings(
                entry_attributes,
                set(FGInternetServiceDefinitionEntry.model_fields),
            )
            entries.append(FGInternetServiceDefinitionEntry(**entry_attributes))
        attributes["entries"] = entries
        validation_settings = {}
        attributes["id"] = _parse_bounded_int(
            attributes.get("id"), minimum=0, maximum=4294967295,
            field_name="id", extra_settings=validation_settings,
        )
        attributes.update(validation_settings)
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(FGInternetServiceDefinition.model_fields),
        )
        self.config.internet_service_definitions.append(
            FGInternetServiceDefinition(**attributes)
        )
        return True

    return False

