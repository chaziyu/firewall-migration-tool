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

    return False
