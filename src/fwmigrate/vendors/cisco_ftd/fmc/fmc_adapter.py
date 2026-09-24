"""Vendor-native adapter for offline FMC REST bundles."""

from __future__ import annotations

import json
from typing import Any

from fwmigrate.extraction.sanitize import sanitize_source_attributes

from ..model import (
    CiscoFTDAccessControlRule, CiscoFTDAccessControlPolicy, CiscoFTDConfig,
    CiscoFTDInterfaceGroup, CiscoFTDNetworkAddress, CiscoFTDNetworkGroup, CiscoFTDPortObjectGroup,
    CiscoFTDProtocolPortObject, CiscoFTDReference, CiscoFTDSecurityZone, CiscoFTDNativeResource,
    CiscoFTDManualNATRule, CiscoFTDAutoNATRule, CiscoFTDNATPolicy,
    CiscoFTDTimeRange, CiscoFTDRecurringTimeRangeEntry, CiscoFTDIntrusionPolicy, CiscoFTDIntrusionRuleGroup,
    CiscoFTDIntrusionRuleBehavior, CiscoFTDIntrusionRuleOverride,
    CiscoFTDFilePolicy, CiscoFTDFileRule, CiscoFTDDecryptionPolicy, CiscoFTDDecryptionRule,
    CiscoFTDDNSPolicy, CiscoFTDDNSRule, CiscoFTDInterfaceSource,
    CiscoFTDFMCUserRole, CiscoFTDFMCUser, CiscoFTDDHCPServer, CiscoFTDDHCPRelaySettings, CiscoFTDRealm,
    CiscoFTDNetworkAddressOverride, CiscoFTDAccessControlDefaultAction,
    CiscoFTDAccessPolicyInheritanceSettings, CiscoFTDPolicyAssignment,
    CiscoFTDRealmUserGroup, CiscoFTDRealmUser, CiscoFTDLocalRealmUser,
    CiscoFTDS2SVPNTopology, CiscoFTDS2SVPNEndpoint, CiscoFTDIKEPolicy,
    CiscoFTDIPsecProposal, CiscoFTDRAVPNPolicy, CiscoFTDRAVPNConnectionProfile,
    CiscoFTDRoute, CiscoFTDApplication, CiscoFTDSLAMonitor, CiscoFTDVariableSet, CiscoFTDURLCategory, CiscoFTDVLANObject,
    CiscoFTDIdentityPolicy,
    CiscoFTDCollectionMetadata, CiscoFTDCollectionPart,
    CiscoFTDVirtualRouter, CiscoFTDPolicyBasedRoute, CiscoFTDECMPZone,
    CiscoFTDCertificate, CiscoFTDCertificateMap, CiscoFTDCertificateEnrollment,
    CiscoFTDAddressPool, CiscoFTDGroupPolicy, CiscoFTDS2SIKESettings, CiscoFTDS2SIPsecSettings,
    CiscoFTDS2SAdvancedSettings, CiscoFTDRAVPNIPsecSettings, CiscoFTDLDAPAttributeMap,
    CiscoFTDRAVPNLoadBalanceSettings, CiscoFTDRAVPNAddressAssignmentSettings,
    CiscoFTDSecureClientSettings, CiscoFTDRAVPNIPsecCryptoMap, CiscoFTDPrefilterPolicy,
    CiscoFTDPrefilterRule, CiscoFTDPrefilterDefaultAction, CiscoFTDNetworkAnalysisPolicy,
    CiscoFTDInspectorConfig, CiscoFTDInspectorOverrideConfig,
)

FMC_BUNDLE_FORMAT = "cisco-fmc-rest-export-v1"


def _items(value: Any) -> list[dict]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict) and isinstance(value.get("items"), list):
        return [item for item in value["items"] if isinstance(item, dict)]
    return []


def is_fmc_bundle(content: str) -> bool:
    try:
        payload = json.loads(content)
    except (TypeError, ValueError):
        return False
    return isinstance(payload, dict) and (
        payload.get("format") == FMC_BUNDLE_FORMAT
        or (
            any(key in payload for key in ("access_policies", "nat_policies", "objects"))
            and payload.get("source") in {"fmc-rest-api", "cisco-fmc-rest-api"}
        )
    )


class CiscoFMCBundleParser:
    """Decode authoritative FMC API data into Cisco FTD source state."""

    def __init__(self, content: str):
        payload = json.loads(content)
        if not isinstance(payload, dict):
            raise ValueError("FMC bundle must be a JSON object")
        if payload.get("format") not in {None, FMC_BUNDLE_FORMAT}:
            raise ValueError(f"Unsupported FMC bundle format: {payload.get('format')!r}")
        self.payload = payload
        domain = payload.get("domain") if isinstance(payload.get("domain"), dict) else {}
        self.domain_id = domain.get("id") or payload.get("domainUUID")
        self.domain_name = domain.get("name") or "Global"
        self.context = f"fmc:{self.domain_name}"

    def _object_collections(self) -> dict[str, list[dict]]:
        objects = self.payload.get("objects") if isinstance(self.payload.get("objects"), dict) else {}
        names = (
            "networkaddresses", "hosts", "networks", "ranges", "fqdnobjects", "networkgroups", "protocolportobjects",
            "portobjectgroups", "securityzones", "interfacegroups",
            "applications", "timeranges", "users", "ips", "filepolicies", "decryptionpolicies", "dnspolicies", "intrusionpolicies",
            "realms", "realmusergroups", "realmusers", "localrealmusers", "s2svpns", "ravpns", "variablesets",
            "urlcategories", "vlanobjects", "ipv4addresspools", "ipv6addresspools", "grouppolicies", "certificatemaps",
            "dhcpipv6pools", "certenrollments", "internalcertificates", "ikev1policies", "ikev2policies", "ikev1ipsecproposals",
            "ikev2ipsecproposals", "customsiurllists", "customsiiplists", "siurllists", "siurlfeeds",
            "prefilterpolicies", "identitypolicies", "networkanalysispolicies", "slamonitors", "device_certificates",
        )
        collections = {name: _items(objects.get(name)) for name in names}
        collections.update({name: items for name, value in objects.items()
                            if name not in collections and (items := _items(value))})
        return collections

    def parse_source(self) -> CiscoFTDConfig:
        objects = self._object_collections()
        plane = "fmc-rest-bundle"
        collection = self.payload.get("collection")
        collection_provided = isinstance(collection, dict)
        collection = collection if collection_provided else {}
        collection_metadata = CiscoFTDCollectionMetadata(
            status=str(collection.get("status") or "UNKNOWN"), provided=collection_provided,
            parts=[CiscoFTDCollectionPart(
                name=str(part.get("name", "unknown")), status=str(part.get("status", "UNKNOWN")),
                complete=part.get("complete", False), count=part.get("count"),
            ) for part in _items(collection.get("parts"))],
        )

        def name(item: dict, index: int) -> str:
            return str(item.get("name") or item.get("id") or index)

        def reference(value: Any) -> CiscoFTDReference:
            if isinstance(value, dict):
                return CiscoFTDReference(source_id=str(value["id"]) if value.get("id") is not None else None,
                    name=str(value["name"]) if value.get("name") is not None else None,
                    source_type=value.get("type") or value.get("objectType"), value=value.get("value"),
                    source_attributes=sanitize_source_attributes({key: item for key, item in value.items()
                                                                  if key not in {"id", "name", "type", "objectType", "value"}}))
            return CiscoFTDReference(name=str(value))

        def refs(value: Any) -> list[CiscoFTDReference]:
            if isinstance(value, dict) and ("objects" in value or "literals" in value):
                value = [*_items(value.get("objects")), *_items(value.get("literals"))]
            if isinstance(value, dict):
                value = [value]
            return [reference(item) for item in (value or [])]

        def refs_field(item: dict, *keys: str) -> list[CiscoFTDReference] | None:
            key = next((key for key in keys if key in item), None)
            return refs(item[key]) if key is not None else None

        def ref_field(item: dict, *keys: str) -> CiscoFTDReference | None:
            key = next((key for key in keys if key in item), None)
            value = item.get(key) if key is not None else None
            return reference(value) if value is not None else None

        def acp_refs(item: dict, key: str) -> list[CiscoFTDReference] | None:
            if key not in item:
                return None
            value = item[key]
            if isinstance(value, dict) and ("objects" in value or "literals" in value):
                return refs([*_items(value.get("objects")), *_items(value.get("literals"))])
            if isinstance(value, dict) and not any(value.get(field) for field in ("id", "name", "value")):
                return []
            return refs(value)

        def record(item: dict, index: int, cls, **values):
            attributes = {"provenance": "FMC REST", "domain_id": self.domain_id}
            attributes.update(values.pop("source_attributes", {}))
            raw_extra = values.pop("raw_extra", sanitize_source_attributes(item))
            return cls(
                name=name(item, index), source_id=str(item.get("id") or "") or None,
                source_plane=plane, source_context=self.context, domain_id=self.domain_id,
                raw_extra=raw_extra,
                source_attributes=attributes,
                **values,
            )

        def ra_record(item: dict, index: int, cls, fields: dict[str, tuple[str, tuple[str, ...]]], **extra):
            """Promote only keys present in the FMC payload; keep other safe evidence."""
            values, explicit = {}, []
            for target, (kind, keys) in fields.items():
                key = next((key for key in keys if key in item), None)
                if key is None:
                    continue
                value = item[key]
                values[target] = (refs(value) if value is not None else None) if kind == "refs" else (
                                  reference(value) if kind == "ref" and value is not None else
                                  sanitize_source_attributes(value))
                explicit.append(target)
            return record(item, index, cls, **values, **extra, explicit_fields=explicit)

        def adapt_inspection_rule(item: dict, index: int, policy: dict, cls, fields: dict[str, tuple[str, ...]]):
            metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            position = item.get("position", item.get("order", metadata.get("ruleIndex")))
            values = {"parent_policy_id": str(policy["id"]) if policy.get("id") is not None else None,
                      "parent_policy_name": policy.get("name"),
                      "position": position, "collection_order": index}
            explicit = ["position"] if "position" in item or "order" in item or "ruleIndex" in metadata else []
            explicit.append("collection_order")
            for target, keys in fields.items():
                matched = [key for key in keys if key in item]
                if not matched:
                    continue
                raw_values = [item[key] for key in matched]
                values[target] = [ref for value in raw_values for ref in refs(value)] if target in {
                    "source_networks", "destination_networks", "source_ports", "destination_ports",
                    "certificates", "source_zones", "destination_zones", "vlan_tags", "lists_feeds", "networks",
                } else raw_values[0] if len(raw_values) == 1 else raw_values
                explicit.append(target)
            used = {key for keys in fields.values() for key in keys}
            used.update(("id", "name", "position", "order"))
            raw_extra = {key: value for key, value in item.items() if key not in used}
            if "ruleIndex" in metadata:
                raw_extra["metadata"] = {key: value for key, value in metadata.items() if key != "ruleIndex"}
                if not raw_extra["metadata"]:
                    raw_extra.pop("metadata")
            return record(item, index, cls, **values, explicit_fields=explicit,
                source_attributes={"parent_policy_id": values["parent_policy_id"],
                                   "parent_policy_name": values["parent_policy_name"]},
                raw_extra=sanitize_source_attributes(raw_extra))

        def adapt_inspection_policy(item: dict, index: int, cls, child_cls, child_keys: tuple[str, ...],
                                    fields: dict[str, tuple[str, ...]], policy_fields: dict[str, tuple[str, ...]]):
            values: dict[str, Any] = {}
            explicit: list[str] = []
            for target, keys in policy_fields.items():
                key = next((key for key in keys if key in item), None)
                if key is not None:
                    values[target] = ref_field(item, key) if target == "decryption_policy" else item[key]
                    explicit.append(target)
            rules_key = next((key for key in child_keys if key in item), None)
            if rules_key is not None and isinstance(item[rules_key], list):
                values["rules"] = [adapt_inspection_rule(child, child_index, item, child_cls, fields)
                                    for child_index, child in enumerate(item[rules_key], 1)
                                    if isinstance(child, dict)]
                explicit.append("rules")
            used = {key for keys in policy_fields.values() for key in keys}
            if rules_key is not None:
                used.add(rules_key)
            values["explicit_fields"] = explicit
            return record(item, index, cls, **values,
                raw_extra=sanitize_source_attributes({key: value for key, value in item.items() if key not in used}))

        def typed_child_records(family: str, keys: tuple[tuple[str, type], ...]):
            result = {key: [] for key, _ in keys}
            for parent in _items(objects.get(family)):
                ownership = {"parent_policy_id": parent.get("id"), "parent_policy_name": parent.get("name"),
                             "parent_policy_type": family}
                if family == "s2svpns":
                    ownership["parent_topology_id"] = parent.get("id")
                    ownership["parent_topology_name"] = parent.get("name")
                for key, cls in keys:
                    for index, item in enumerate(_items(parent.get(key)), 1):
                        values = {}
                        if cls is CiscoFTDS2SIKESettings:
                            v1, v2 = item.get("ikeV1Settings"), item.get("ikeV2Settings")
                            v1 = v1 if isinstance(v1, dict) else {}
                            v2 = v2 if isinstance(v2, dict) else {}
                            v1_policies = refs_field(v1, "policies")
                            v2_policies = refs_field(v2, "policies")
                            v1_cert = ref_field(v1, "certificateAuth")
                            v2_cert = ref_field(v2, "certificateAuth")
                            legacy_policies = refs_field(item, "ikePolicies", "ikePolicy")
                            legacy_certificates = refs_field(item, "certificates", "certificate")
                            key_fields = ("manualPreSharedKey", "preSharedKey", "preSharedKeyEncrypted", "psk")
                            psk_values = [block[field] for block in (v1, v2, item) for field in key_fields if field in block]
                            values.update(
                                ikev1_policies=v1_policies, ikev2_policies=v2_policies,
                                ike_policies=[*(v1_policies or []), *(v2_policies or [])]
                                    if v1_policies is not None or v2_policies is not None else legacy_policies,
                                ikev1_authentication_type=v1.get("authenticationType"),
                                ikev2_authentication_type=v2.get("authenticationType"),
                                ikev1_certificate=v1_cert, ikev2_certificate=v2_cert,
                                certificates=[ref for ref in (v1_cert, v2_cert) if ref] or legacy_certificates,
                                ikev1_automatic_psk_length=v1.get("automaticPreSharedKeyLength"),
                                ikev2_automatic_psk_length=v2.get("automaticPreSharedKeyLength"),
                                ikev2_hex_psk_only=v2.get("enforceHexBasedPreSharedKeyOnly"),
                                psk_present=True if any(bool(value) for value in psk_values) else None,
                                explicit_fields=[field for field in (
                                    "ikev1_authentication_type", "ikev2_authentication_type",
                                    "ikev1_automatic_psk_length", "ikev2_automatic_psk_length",
                                    "ikev2_hex_psk_only") if field in {
                                        "ikev1_authentication_type" if "authenticationType" in v1 else "",
                                        "ikev2_authentication_type" if "authenticationType" in v2 else "",
                                        "ikev1_automatic_psk_length" if "automaticPreSharedKeyLength" in v1 else "",
                                        "ikev2_automatic_psk_length" if "automaticPreSharedKeyLength" in v2 else "",
                                        "ikev2_hex_psk_only" if "enforceHexBasedPreSharedKeyOnly" in v2 else ""}],
                            )
                            values["explicit_fields"] = [field for field, value in values.items()
                                                          if field != "explicit_fields" and value is not None]
                        elif cls is CiscoFTDS2SIPsecSettings:
                            v1_refs = refs_field(item, "ikeV1IpsecProposal")
                            v2_refs = refs_field(item, "ikeV2IpsecProposal")
                            pfs = item.get("perfectForwardSecrecy")
                            pfs = pfs if isinstance(pfs, dict) else {}
                            values.update(
                                ikev1_ipsec_proposals=v1_refs, ikev2_ipsec_proposals=v2_refs,
                                ipsec_proposals=[*(v1_refs or []), *(v2_refs or [])]
                                    if v1_refs is not None or v2_refs is not None
                                    else refs_field(item, "ipsecProposals", "ipsecProposal", "proposals"),
                                pfs_enabled=pfs.get("enabled"), pfs_group=pfs.get("modulusGroup"),
                                lifetime_seconds=item.get("lifetimeSeconds"),
                                lifetime_kilobytes=item.get("lifetimeKilobytes"),
                                ikev2_mode=item.get("ikeV2Mode"), crypto_map_type=item.get("cryptoMapType"),
                                do_not_fragment_policy=item.get("doNotFragmentPolicy"),
                                enable_rri=item.get("enableRRI"),
                                enable_sa_strength_enforcement=item.get("enableSaStrengthEnforcement"),
                                tfc_packets=item.get("tfcPackets") if isinstance(item.get("tfcPackets"), dict) else None,
                                validate_incoming_icmp_error_message=item.get("validateIncomingIcmpErrorMessage"),
                            )
                            values["explicit_fields"] = [field for field, value in values.items()
                                                          if field != "explicit_fields" and value is not None]
                        elif cls is CiscoFTDS2SAdvancedSettings:
                            ike = item.get("advancedIkeSetting") if isinstance(item.get("advancedIkeSetting"), dict) else {}
                            tunnel = item.get("advancedTunnelSetting") if isinstance(item.get("advancedTunnelSetting"), dict) else {}
                            values.update(
                                ike_keepalive_settings=ike.get("ikeKeepaliveSettings"),
                                advanced_ike_settings=ike or None,
                                advanced_ipsec_settings=item.get("advancedIpsecSetting")
                                    if isinstance(item.get("advancedIpsecSetting"), dict) else None,
                                advanced_tunnel_settings=tunnel or None,
                            )
                            values["explicit_fields"] = [field for field, value in values.items()
                                                          if field != "explicit_fields" and value is not None]
                        elif cls is CiscoFTDRAVPNAddressAssignmentSettings:
                            for target, (kind, keys) in {
                                "address_pools": ("refs", ("addressPools", "ipv4AddressPools", "ipv6AddressPools")),
                                "assignment_method": ("raw", ("assignmentMethod",)),
                                "allow_reuse": ("raw", ("allowReuse",)),
                                "reuse_delay": ("raw", ("ipAddressReuseInterval", "reuseDelay", "addressReuseDelay")),
                                "external_assignment": ("ref", ("externalAssignment",)),
                                "use_authorization_server_for_ipv4": ("raw", ("useAuthorizationServerForIPv4",)),
                                "use_authorization_server_for_ipv6": ("raw", ("useAuthorizationServerForIPv6",)),
                                "use_dhcp": ("raw", ("useDHCP",)),
                                "use_internal_address_pool_for_ipv4": ("raw", ("useInternalAddressPoolForIPv4",)),
                                "use_internal_address_pool_for_ipv6": ("raw", ("useInternalAddressPoolForIPv6",)),
                            }.items():
                                source_key = next((candidate for candidate in keys if candidate in item), None)
                                if source_key is not None:
                                    values[target] = (refs(item[source_key]) if kind == "refs" else
                                        ref_field(item, source_key) if kind == "ref" else sanitize_source_attributes(item[source_key]))
                            values["explicit_fields"] = list(values)
                        elif cls is CiscoFTDRAVPNIPsecSettings:
                            for target, source_key in (("ikev2_settings", "ikev2settings"),
                                                       ("ipsec_settings", "ipsecsettings"),
                                                       ("nat_keepalive", "natKeepaliveMessageTraversal")):
                                if source_key in item:
                                    values[target] = sanitize_source_attributes(item[source_key])
                            values["explicit_fields"] = list(values)
                        elif cls is CiscoFTDSecureClientSettings:
                            for target, keys in (("packages", ("clientPackages", "secureClientPackages")),
                                                 ("profiles", ("clientProfiles", "secureClientProfiles"))):
                                source_key = next((candidate for candidate in keys if candidate in item), None)
                                if source_key is not None:
                                    values[target] = refs(item[source_key])
                            values["explicit_fields"] = list(values)
                        elif cls is CiscoFTDPrefilterRule:
                            values.update(position=item.get("position", item.get("order")), action=item.get("action"),
                                conditions=sanitize_source_attributes(item.get("conditions")) if "conditions" in item else None,
                                references=refs_field(item, "references", "interfaces", "networks"))
                        result[key].append(record(item, index, cls, **values,
                            source_attributes={**ownership, "resource_type": key}))
            return result

        def override_metadata(item: dict) -> dict | None:
            found = {key: value for key, value in item.items() if "override" in key.lower()}
            return sanitize_source_attributes(found) or None

        def network_address(item: dict, index: int):
            fields = {
                "address_type": ("type",), "value": ("value",), "description": ("description",),
                "fqdn_lookup_type": ("lookupType", "fqdnLookupType", "dnsResolutionType"),
                "address_family": ("addressFamily",),
            }
            values = {target: item[source] for target, spellings in fields.items()
                      if (source := next((key for key in spellings if key in item), None)) is not None}
            values["override_metadata"] = override_metadata(item)
            values["explicit_fields"] = [target for target, spellings in fields.items()
                                         if any(key in item for key in spellings)]
            if values["override_metadata"] is not None:
                values["explicit_fields"].append("override_metadata")
            return record(item, index, CiscoFTDNetworkAddress, **values)

        def network_group(item: dict, index: int):
            values = {
                "members": refs_field(item, "objects", "members"),
                "literal_members": refs_field(item, "literals"),
                "description": item.get("description"),
                "override_metadata": override_metadata(item),
                "explicit_fields": [field for field, keys in (
                    ("members", ("objects", "members")), ("literal_members", ("literals",)),
                    ("description", ("description",))) if any(key in item for key in keys)],
            }
            if values["override_metadata"] is not None:
                values["explicit_fields"].append("override_metadata")
            return record(item, index, CiscoFTDNetworkGroup, **values)

        def protocol_port_object(item: dict, index: int):
            fields = {
                "protocol": ("protocol",), "port": ("port", "destinationPort"),
                "end_port": ("endPort", "end_port"), "icmp_type": ("icmpType", "icmp_type"),
                "icmp_code": ("icmpCode", "icmp_code"), "description": ("description",),
            }
            values = {target: item[source] for target, spellings in fields.items()
                      if (source := next((key for key in spellings if key in item), None)) is not None}
            if "ports" in item:
                values["ports"] = item["ports"]
            values["override_metadata"] = override_metadata(item)
            values["explicit_fields"] = [target for target, spellings in fields.items()
                                         if any(key in item for key in spellings)]
            if "ports" in item:
                values["explicit_fields"].append("ports")
            if values["override_metadata"] is not None:
                values["explicit_fields"].append("override_metadata")
            return record(item, index, CiscoFTDProtocolPortObject, **values)

        def port_object_group(item: dict, index: int):
            values = {
                "members": refs_field(item, "objects", "members"),
                "description": item.get("description"), "override_metadata": override_metadata(item),
                "explicit_fields": [field for field, key in (("members", "objects"), ("description", "description"))
                                    if key in item or (field == "members" and "members" in item)],
            }
            if values["override_metadata"] is not None:
                values["explicit_fields"].append("override_metadata")
            return record(item, index, CiscoFTDPortObjectGroup, **values)

        # Newer FMC bundles use networkaddresses; older exports split hosts/networks/ranges.
        if objects.get("networkaddresses"):
            objects["hosts"] = objects["networks"] = objects["ranges"] = []
        network_groups = [
            network_group(item, index)
            for index, item in enumerate(objects.get("networkgroups", []), 1)
        ]
        network_address_items = objects.get("networkaddresses") or [
            *objects.get("hosts", []), *objects.get("networks", []), *objects.get("ranges", []), *objects.get("fqdnobjects", [])]
        network_addresses = [network_address(item, index)
            for index, item in enumerate(network_address_items, 1)]
        network_address_overrides = [record(item, index, CiscoFTDNetworkAddressOverride,
            parent=ref_field(item.get("overrides", {}), "parent"),
            target=ref_field(item.get("overrides", {}), "target"),
            address_type=item.get("type"), value=item.get("value"), overridable=item.get("overridable"),
            explicit_fields=[field for field, key in (("parent", "parent"), ("target", "target"))
                             if key in item.get("overrides", {})] +
                            [field for field, key in (("address_type", "type"), ("value", "value"), ("overridable", "overridable")) if key in item],
            source_attributes={"target_id": item.get("overrides", {}).get("target", {}).get("id"),
                               "target_name": item.get("overrides", {}).get("target", {}).get("name")})
            for index, item in enumerate(objects.get("network_address_overrides", []), 1)]
        protocol_ports = [
            protocol_port_object(item, index)
            for index, item in enumerate(objects.get("protocolportobjects", []), 1)
        ]
        port_groups = [
            port_object_group(item, index)
            for index, item in enumerate(objects.get("portobjectgroups", []), 1)
        ]
        zones = [
            record(item, index, CiscoFTDSecurityZone, interfaces=refs_field(item, "interfaces"))
            for index, item in enumerate(objects.get("securityzones", []), 1)
        ]
        interface_groups = [record(item, index, CiscoFTDInterfaceGroup, interfaces=refs_field(item, "interfaces", "members"))
            for index, item in enumerate(objects.get("interfacegroups", []), 1)]
        interfaces = [record(item, index, CiscoFTDDeviceInterface,
            interface_type=item.get("type"), address=item.get("address"),
            zone=reference(item["securityZone"]) if item.get("securityZone") else None)
            for index, item in enumerate(objects.get("interfaces", []), 1)]
        acp_policies = []
        acp_default_actions = []
        acp_inheritance_settings = []
        native = []
        policy_assignments = [record(item, index, CiscoFTDPolicyAssignment,
            policy=ref_field(item, "policy"), targets=refs_field(item, "targets"),
            explicit_fields=[field for field, key in (("policy", "policy"), ("targets", "targets")) if key in item])
            for index, item in enumerate(objects.get("policy_assignments", []), 1)]
        for policy_index, policy in enumerate(_items(self.payload.get("access_policies")), 1):
            policy_name = str(policy.get("name") or policy.get("id") or policy_index)
            acp_rules = []
            for rule_index, item in enumerate(_items(policy.get("rules")), 1):
                metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
                apps = item.get("applications") if isinstance(item.get("applications"), dict) else {}
                urls = item.get("urls") if isinstance(item.get("urls"), dict) else {}
                url_categories = urls.get("urlCategoriesWithReputation")
                if "urlCategoriesWithReputation" in urls:
                    url_categories = [entry.get("category", entry) if isinstance(entry, dict) else entry for entry in _items(url_categories)]
                acp_values = {
                    "policy_id": str(policy.get("id")) if policy.get("id") is not None else None,
                    "policy_name": policy_name,
                    "enabled": item.get("enabled"),
                    "position": item.get("position", metadata.get("ruleIndex")),
                    "collection_order": rule_index,
                    "section": metadata.get("section"),
                    "category": metadata.get("category"),
                    "action": item.get("action"),
                    "comments": item.get("comments"),
                    "source_zones": acp_refs(item, "sourceZones"),
                    "destination_zones": acp_refs(item, "destinationZones"),
                    "source_networks": acp_refs(item, "sourceNetworks"),
                    "destination_networks": acp_refs(item, "destinationNetworks"),
                    "source_ports": acp_refs(item, "sourcePorts"),
                    "destination_ports": acp_refs(item, "destinationPorts"),
                    "source_dynamic_objects": acp_refs(item, "sourceDynamicObjects"),
                    "destination_dynamic_objects": acp_refs(item, "destinationDynamicObjects"),
                    "vlan_tags": acp_refs(item, "vlanTags"),
                    "source_security_group_tags": acp_refs(item, "sourceSecurityGroupTags"),
                    "destination_security_group_tags": acp_refs(item, "destinationSecurityGroupTags"),
                    "realm": reference(item["realm"]) if "realm" in item and item["realm"] is not None else None,
                    "realm_users": acp_refs(item, "realmUsers"),
                    "users": acp_refs(item, "users"),
                    "user_groups": acp_refs(item, "realmUserGroups"),
                    "applications": acp_refs(apps, "applications"),
                    "application_filters": acp_refs(apps, "applicationFilters"),
                    "inline_application_filters": acp_refs(apps, "inlineApplicationFilters"),
                    "urls": sanitize_source_attributes(urls) if "urls" in item else None,
                    "url_categories": refs(url_categories) if url_categories is not None else None,
                    "time_range": reference(item["timeRange"]) if item.get("timeRange") is not None else None,
                    "intrusion_policy": reference(item["ipsPolicy"]) if item.get("ipsPolicy") is not None else None,
                    "variable_set": reference(item["variableSet"]) if item.get("variableSet") is not None else None,
                    "file_policy": reference(item["filePolicy"]) if item.get("filePolicy") is not None else None,
                    "log_begin": item.get("logBegin"),
                    "log_end": item.get("logEnd"),
                    "logging": sanitize_source_attributes({key: item[key] for key in ("logFiles", "sendEventsToFMC", "enableSyslog", "advancedLogging") if key in item}) or None,
                    "source_attributes": {"policy_id": policy.get("id"), "policy_name": policy_name},
                }
                acp_values["explicit_fields"] = [key for key, present in (
                    ("enabled", "enabled" in item), ("position", "position" in item or "ruleIndex" in metadata),
                    ("section", "section" in metadata), ("category", "category" in metadata),
                    ("action", "action" in item), ("comments", "comments" in item),
                    ("source_zones", "sourceZones" in item), ("destination_zones", "destinationZones" in item),
                    ("source_networks", "sourceNetworks" in item), ("destination_networks", "destinationNetworks" in item),
                    ("source_ports", "sourcePorts" in item), ("destination_ports", "destinationPorts" in item),
                    ("source_dynamic_objects", "sourceDynamicObjects" in item),
                    ("destination_dynamic_objects", "destinationDynamicObjects" in item),
                    ("vlan_tags", "vlanTags" in item),
                    ("source_security_group_tags", "sourceSecurityGroupTags" in item),
                    ("destination_security_group_tags", "destinationSecurityGroupTags" in item),
                    ("realm", "realm" in item), ("realm_users", "realmUsers" in item),
                    ("users", "users" in item), ("user_groups", "realmUserGroups" in item),
                    ("applications", "applications" in item), ("time_range", "timeRange" in item),
                    ("application_filters", "applicationFilters" in apps),
                    ("inline_application_filters", "inlineApplicationFilters" in apps),
                    ("urls", "urls" in item), ("url_categories", "urlCategoriesWithReputation" in urls),
                    ("intrusion_policy", "ipsPolicy" in item), ("variable_set", "variableSet" in item),
                    ("file_policy", "filePolicy" in item), ("log_begin", "logBegin" in item), ("log_end", "logEnd" in item),
                    ("logging", any(key in item for key in ("logFiles", "sendEventsToFMC", "enableSyslog", "advancedLogging"))),
                ) if present]
                acp_rules.append(record(
                    item, rule_index, CiscoFTDAccessControlRule, **acp_values,
                ))
            policy_metadata = policy.get("metadata") if isinstance(policy.get("metadata"), dict) else {}
            acp_policies.append(record(policy, policy_index, CiscoFTDAccessControlPolicy,
                rules=acp_rules if "rules" in policy else None,
                description=policy.get("description"),
                inherit=policy_metadata.get("inherit") if "inherit" in policy_metadata else None,
                base_policy=ref_field(policy_metadata, "parentPolicy") or ref_field(policy, "basePolicy"),
                default_action=ref_field(policy, "defaultAction"),
                prefilter_policy=ref_field(policy, "prefilterPolicy", "associatedPrefilterPolicy"),
                network_analysis_policy=ref_field(policy, "networkAnalysisPolicy", "networkanalysispolicy"),
                decryption_policy=ref_field(policy, "decryptionPolicy"), dns_policy=ref_field(policy, "dnsPolicy"),
                identity_policy=ref_field(policy, "identityPolicy"),
                logging_settings=sanitize_source_attributes(policy.get("logging_settings", policy.get("loggingSettings")))
                    if "logging_settings" in policy or "loggingSettings" in policy else None,
                explicit_fields=[field for field, present in (
                    ("description", "description" in policy), ("inherit", "inherit" in policy_metadata),
                    ("base_policy", "parentPolicy" in policy_metadata or "basePolicy" in policy),
                    ("default_action", "defaultAction" in policy),
                    ("prefilter_policy", ("prefilterPolicy", "associatedPrefilterPolicy")),
                    ("network_analysis_policy", ("networkAnalysisPolicy", "networkanalysispolicy")),
                    ("decryption_policy", ("decryptionPolicy",)), ("dns_policy", ("dnsPolicy",)),
                    ("identity_policy", ("identityPolicy",)),
                    ("logging_settings", "logging_settings" in policy or "loggingSettings" in policy))
                    if (present if isinstance(present, bool) else any(key in policy for key in present))]))
            acp_default_actions.extend(record(item, index, CiscoFTDAccessControlDefaultAction,
                policy_id=str(policy.get("id")) if policy.get("id") is not None else None,
                action=item.get("action"), explicit_fields=["action"] if "action" in item else [],
                source_attributes={"parent_policy_id": policy.get("id"), "parent_policy_name": policy_name})
                for index, item in enumerate(_items(policy.get("default_actions")), 1))
            acp_inheritance_settings.extend(record(item, index, CiscoFTDAccessPolicyInheritanceSettings,
                policy_id=str(policy.get("id")) if policy.get("id") is not None else None,
                base_policy=ref_field(item, "basePolicy"), description=item.get("description"),
                explicit_fields=[field for field, key in (("base_policy", "basePolicy"), ("description", "description")) if key in item],
                source_attributes={"parent_policy_id": policy.get("id"), "parent_policy_name": policy_name})
                for index, item in enumerate(_items(policy.get("inheritance_settings")), 1))

        nat_policies = []
        for policy_index, policy in enumerate(_items(self.payload.get("nat_policies")), 1):
            ownership = {"policy_id": policy.get("id"), "policy_name": policy.get("name")}

            def common_rule(item: dict, rule_index: int, rule_section: str | None = None):
                section = item.get("section") or rule_section
                return dict(
                    source_interface=reference(item["sourceInterface"]) if item.get("sourceInterface") else None,
                    destination_interface=reference(item["destinationInterface"]) if item.get("destinationInterface") else None,
                    nat_type=item.get("natType"), enabled=item.get("enabled"), section=section,
                    position=item.get("position", item.get("order")), observed_collection_order=rule_index,
                    source_attributes={**ownership, "observed_collection_order": rule_index},
                )

            def manual_rules(key: str, section: str | None = None):
                if key not in policy:
                    return None
                parsed = []
                for rule_index, item in enumerate(_items(policy.get(key)), 1):
                    values = common_rule(item, rule_index, section)
                    actual_section = values.pop("section")
                    # Collection membership establishes before/after; unknown generic manual sections stay unknown.
                    if section is None and not actual_section:
                        values["section"] = None
                    else:
                        values["section"] = actual_section
                    values.update(
                        original_source=item.get("originalSource", item.get("source")),
                        translated_source=item.get("translatedSource"),
                        original_destination=item.get("originalDestination", item.get("destination")),
                        translated_destination=item.get("translatedDestination"),
                        original_source_port=item.get("originalSourcePort"),
                        translated_source_port=item.get("translatedSourcePort"),
                        original_destination_port=item.get("originalDestinationPort"),
                        translated_destination_port=item.get("translatedDestinationPort"),
                        original_source_service=item.get("originalSourceService"),
                        translated_source_service=item.get("translatedSourceService"),
                        original_destination_service=item.get("originalDestinationService"),
                        translated_destination_service=item.get("translatedDestinationService"),
                        identity_nat=item.get("identityNat"), interface_pat=item.get("interfacePat"),
                        dns=item.get("dns"), route_lookup=item.get("routeLookup"), proxy_arp=item.get("noProxyArp") is False if "noProxyArp" in item else item.get("proxyArp"),
                    )
                    parsed.append(record(item, rule_index, CiscoFTDManualNATRule, **values))
                return parsed

            auto_rules = []
            for rule_index, item in enumerate(_items(policy.get("auto_rules")), 1):
                values = common_rule(item, rule_index)
                values.pop("section", None)
                original_network = item.get("originalNetwork")
                auto_rules.append(record(item, rule_index, CiscoFTDAutoNATRule,
                    **values, original_network=original_network,
                    translated_network=item.get("translatedNetwork"),
                    owning_network=item.get("originalNetwork"),
                    interface_pat=item.get("interfaceInTranslatedNetwork", item.get("interfacePat")),
                    identity_nat=item.get("identityNat"), dns=item.get("dns"),
                    route_lookup=item.get("routeLookup"), proxy_arp=item.get("proxyArp")))

            before = manual_rules("manual_rules_before_auto", "BEFORE_AUTO")
            unclassified = manual_rules("manual_rules")
            after = manual_rules("manual_rules_after_auto", "AFTER_AUTO")
            nat_policies.append(record(policy, policy_index, CiscoFTDNATPolicy,
                manual_rules_before_auto=before, auto_rules=auto_rules if "auto_rules" in policy else None,
                manual_rules_after_auto=after, unclassified_manual_rules=unclassified))

        def records(key, cls):
            return [record(item, i, cls) for i, item in enumerate(_items(self.payload.get(key)), 1)]

        def object_records(key, cls):
            return [record(item, i, cls) for i, item in enumerate(objects.get(key, []), 1)]

        def adapt_realm(item: dict, index: int):
            fields = {
                "realm_type": ("realmType",), "enabled": ("enabled",), "description": ("description",),
                "base_dn": ("baseDn",), "group_dn": ("groupDn",), "group_attribute": ("groupAttribute",),
                "ad_primary_domain": ("adPrimaryDomain",), "included_users": ("includedUsers",),
                "excluded_users": ("excludedUsers",), "included_groups": ("includedGroups",),
                "excluded_groups": ("excludedGroups",), "identity_provider": ("identityProvider",),
            }
            values = {field: item[key] for field, aliases in fields.items()
                      if (key := next((key for key in aliases if key in item), None)) is not None}
            explicit = list(values)
            if "directoryConfigurations" in item:
                values["directory_configurations"] = sanitize_source_attributes({"items": item["directoryConfigurations"]})["items"]
                explicit.append("directory_configurations")
            if "idpSettings" in item:
                values["idp_settings"] = sanitize_source_attributes({"settings": item["idpSettings"]})["settings"]
                explicit.append("idp_settings")
            sync_keys = ("updateHour", "updateInterval")
            sync = {key: item[key] for key in sync_keys if key in item}
            if "synchronizationSettings" in item and isinstance(item["synchronizationSettings"], dict):
                sync.update(item["synchronizationSettings"])
            if sync:
                values["synchronization_settings"] = sanitize_source_attributes(sync)
                explicit.append("synchronization_settings")
            values["explicit_fields"] = explicit
            return record(item, index, CiscoFTDRealm, **values)

        def adapt_realm_identity(item: dict, index: int, cls, *, user: bool = False):
            fields = {"username": ("username", "name"), "external_id": ("externalId",),
                      "distinguished_name": ("distinguishedName", "dn"),
                      "resolved": ("resolved",), "synchronized": ("synchronized",)}
            if not user:
                fields.pop("username")
            values = {field: item[key] for field, aliases in fields.items()
                      if (key := next((key for key in aliases if key in item), None)) is not None}
            explicit = list(values)
            if "metadata" in item and isinstance(item["metadata"], dict) and "resolved" in item["metadata"] and "resolved" not in values:
                values["resolved"] = item["metadata"]["resolved"]
                explicit.append("resolved")
            if "forPolicy" in item:
                values["for_policy"] = item["forPolicy"]
                explicit.append("for_policy")
            metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            if "lastSynced" in metadata:
                values["last_synced"] = metadata["lastSynced"]
                explicit.append("last_synced")
            if "realm" in item:
                values["realm"] = ref_field(item, "realm")
                explicit.append("realm")
            if user:
                for field, keys in (("groups", ("groups", "realmUserGroups")),):
                    key = next((key for key in keys if key in item), None)
                    if key is not None:
                        values[field] = refs_field(item, key)
                        explicit.append(field)
            values["explicit_fields"] = explicit
            return record(item, index, cls, **values)

        def adapt_local_realm_user(item: dict, index: int):
            keys = {"username": ("username", "name"), "enabled": ("enabled",),
                    "password_configured": ("passwordConfigured", "hasPassword")}
            values = {field: item[key] for field, aliases in keys.items()
                      if (key := next((key for key in aliases if key in item), None)) is not None}
            explicit = list(values)
            if ("password" in item or "passwordHash" in item or "password_hash" in item) and not any(
                    key in item for key in ("passwordConfigured", "hasPassword")):
                secret_value = item.get("password", item.get("passwordHash", item.get("password_hash")))
                values["password_configured"] = True if secret_value not in (None, "") else None
                if "password_configured" not in explicit:
                    explicit.append("password_configured")
            if "realm" in item:
                values["realm"] = ref_field(item, "realm")
                explicit.append("realm")
            for field, aliases in (("groups", ("groups", "realmUserGroups")),):
                key = next((key for key in aliases if key in item), None)
                if key is not None:
                    values[field] = refs_field(item, key)
                    explicit.append(field)
            values["explicit_fields"] = explicit
            return record(item, index, CiscoFTDLocalRealmUser, **values)

        def adapt_fmc_role(item: dict, index: int):
            fields = {
                "description": ("description",), "predefined": ("predefined", "isPredefined"),
                "custom": ("custom", "isCustom"), "menu_permissions": ("menuPermissions", "menuAccessPermissions"),
                "system_permissions": ("systemPermissions", "systemAccessPermissions"),
                "role_escalation": ("roleEscalation",), "other_permissions": ("permissions",),
            }
            values = {field: sanitize_source_attributes({key: item[key]})[key]
                      for field, aliases in fields.items()
                      if (key := next((key for key in aliases if key in item), None)) is not None}
            values["explicit_fields"] = list(values)
            return record(item, index, CiscoFTDFMCUserRole, **values)

        def adapt_fmc_user(item: dict, index: int):
            fields = {"username": ("username", "name"), "enabled": ("isUserEnabled", "enabled"),
                      "authentication_type": ("authenticationMethod", "authenticationType"),
                      "external_identity": ("externalIdentity",)}
            values = {field: sanitize_source_attributes({key: item[key]})[key]
                      for field, aliases in fields.items()
                      if (key := next((key for key in aliases if key in item), None)) is not None}
            explicit = list(values)
            for field, aliases in (("authentication_source", ("authenticationSource", "authSource")),):
                key = next((key for key in aliases if key in item), None)
                if key is not None:
                    values[field] = ref_field(item, key)
                    explicit.append(field)
            key = next((key for key in ("roles", "role") if key in item), None)
            if key is not None:
                values["roles"] = refs_field(item, key)
                explicit.append("roles")
            values["explicit_fields"] = explicit
            return record(item, index, CiscoFTDFMCUser, **values)

        def adapt_time_range(item: dict, index: int):
            recurrence_fields = {
                "recurrence_type": "recurrenceType", "days": "days",
                "daily_start_time": "dailyStartTime", "daily_end_time": "dailyEndTime",
                "range_start_day": "rangeStartDay", "range_start_time": "rangeStartTime",
                "range_end_day": "rangeEndDay", "range_end_time": "rangeEndTime",
            }

            def recurrence_entry(source: dict):
                def source_value(field: str, key: str):
                    value = source[key]
                    if field == "days":
                        return value if isinstance(value, list) and all(isinstance(day, str) for day in value) else None
                    return value if value is None or isinstance(value, str) else None

                return CiscoFTDRecurringTimeRangeEntry(
                    **{field: source_value(field, key) for field, key in recurrence_fields.items() if key in source},
                    explicit_fields=[field for field, key in recurrence_fields.items() if key in source],
                    raw_extra=sanitize_source_attributes(source),
                )

            fields = {
                "description": "description",
                "absolute_start_date_time": "effectiveStartDateTime",
                "absolute_end_date_time": "effectiveEndDateTime",
            }
            values = {field: item[key] if item[key] is None or isinstance(item[key], str) else None
                      for field, key in fields.items() if key in item}
            if "recurrenceList" in item:
                values["recurrence_entries"] = (
                    [recurrence_entry(entry) for entry in item["recurrenceList"] if isinstance(entry, dict)]
                    if isinstance(item["recurrenceList"], list) else None
                )
            values["explicit_fields"] = [field for field, key in fields.items() if key in item]
            if "recurrenceList" in item:
                values["explicit_fields"].append("recurrence_entries")
            return record(item, index, CiscoFTDTimeRange, **values)

        def adapt_intrusion_policy(item: dict, index: int):
            fields = {
                "description": ("description",), "variable_set": ("variableSet",),
                "base_policy": ("basePolicy", "baseIntrusionPolicy"),
                "snort_version": ("snortVersion",),
            }
            values = {target: reference(item[key]) if target in {"variable_set", "base_policy"} else item[key]
                      for target, keys in fields.items()
                      if (key := next((key for key in keys if key in item), None)) is not None}
            values["explicit_fields"] = [target for target, keys in fields.items()
                                         if any(key in item for key in keys)]
            return record(item, index, CiscoFTDIntrusionPolicy, **values)

        intrusion_policies = [adapt_intrusion_policy(item, index)
                              for index, item in enumerate(objects.get("intrusionpolicies", []), 1)]
        intrusion_rule_groups = []
        intrusion_rule_behaviors = []
        intrusion_rule_overrides = []
        for policy in objects.get("intrusionpolicies", []):
            policy_id = str(policy.get("id")) if policy.get("id") is not None else None
            policy_name = policy.get("name")
            groups = _items(policy.get("rule_groups"))
            memberships: dict[str, list[dict[str, Any]]] = {}
            membership_keys: set[tuple[str, str]] = set()
            for group_index, group in enumerate(groups, 1):
                group_id = str(group.get("id")) if group.get("id") is not None else None
                group_name = str(group.get("name") or group_id or group_index)
                intrusion_rule_groups.append(record(group, group_index, CiscoFTDIntrusionRuleGroup,
                    parent_policy_id=policy_id, parent_policy_name=policy_name,
                    description=group.get("description"),
                    explicit_fields=[field for field in ("description",) if field in group],
                    source_attributes={"parent_policy_id": policy_id, "parent_policy_name": policy_name}))
                for child in _items(group.get("rules")):
                    rule_key = str(child.get("ruleId") or child.get("id") or "")
                    if not rule_key:
                        continue
                    membership_key = (group_id or group_name, rule_key)
                    if membership_key in membership_keys:
                        continue
                    membership_keys.add(membership_key)
                    evidence = {"rule_group_id": group_id, "rule_group_name": group_name,
                                "rule_id": rule_key, "payload": sanitize_source_attributes(child)}
                    memberships.setdefault(rule_key, []).append(evidence)

            for rule_index, item in enumerate(_items(policy.get("rules")), 1):
                rule_key = str(item.get("ruleId") or item.get("id") or "")
                evidence = memberships.get(rule_key, [])
                conflicts = []
                for membership in evidence:
                    group_payload = membership["payload"]
                    differing = {key: {"behavior": item[key], "group": group_payload[key]}
                                 for key in ("state", "action", "enabled")
                                 if key in item and key in group_payload and item[key] != group_payload[key]}
                    if differing:
                        conflicts.append({**membership, "conflicting_fields": differing})
                attributes = {"parent_policy_id": policy_id, "parent_policy_name": policy_name}
                if evidence:
                    attributes["group_membership_evidence"] = evidence
                if conflicts:
                    attributes["conflicting_group_payload"] = conflicts
                values = {field: item[field] for field in ("state", "action", "enabled") if field in item}
                values.update(parent_policy_id=policy_id, parent_policy_name=policy_name,
                    rule_id=str(item["ruleId"]) if item.get("ruleId") is not None else None,
                    explicit_fields=[*values.keys(), *( ["rule_id"] if "ruleId" in item else [])],
                    source_attributes=attributes)
                intrusion_rule_behaviors.append(record(item, rule_index, CiscoFTDIntrusionRuleBehavior, **values))
            for override_index, item in enumerate(_items(policy.get("overrides")), 1):
                values = {field: item[key] for field, key in (("state", "state"), ("action", "action")) if key in item}
                if item.get("ruleId") is not None:
                    values["rule_id"] = str(item["ruleId"])
                rule_reference = ref_field(item, "ruleReference")
                if rule_reference is not None:
                    values["rule_reference"] = rule_reference
                values.update(parent_policy_id=policy_id, parent_policy_name=policy_name,
                    explicit_fields=list(values),
                    source_attributes={"parent_policy_id": policy_id, "parent_policy_name": policy_name})
                intrusion_rule_overrides.append(record(item, override_index, CiscoFTDIntrusionRuleOverride, **values))

        source_objects = self.payload.get("objects") if isinstance(self.payload.get("objects"), dict) else {}

        def vpn_records(families, legacy_key, cls):
            def adapt(item, index, version, resource_type):
                values = {"ike_version": version}
                if cls is CiscoFTDIKEPolicy:
                    fields = {
                        "priority": "priority", "lifetime_in_seconds": "lifetimeInSeconds",
                        "authentication_method": "authenticationMethod", "encryption": "encryption",
                        "hash": "hash", "diffie_hellman_group": "diffieHellmanGroup",
                        "encryption_algorithms": "encryptionAlgorithms",
                        "integrity_algorithms": "integrityAlgorithms",
                        "prf_integrity_algorithms": "prfIntegrityAlgorithms",
                        "diffie_hellman_groups": "diffieHellmanGroups",
                    }
                    values.update({field: item[key] for field, key in fields.items() if key in item})
                    explicit = [field for field, key in fields.items() if key in item]
                elif cls is CiscoFTDIPsecProposal:
                    fields = {
                        "esp_encryption": "espEncryption", "esp_hash": "espHash",
                        "encryption_algorithms": "encryptionAlgorithms",
                        "integrity_algorithms": "integrityAlgorithms",
                    }
                    values.update({field: item[key] for field, key in fields.items() if key in item})
                    explicit = [field for field, key in fields.items() if key in item]
                else:
                    explicit = []
                # Collection membership supplies the version; it is provenance, not an explicit payload field.
                return record(item, index, cls, **values, explicit_fields=explicit,
                    source_attributes={"resource_type": resource_type})

            if any(key in source_objects for key, _ in families):
                return [adapt(item, index, version, key)
                    for key, version in families for index, item in enumerate(objects.get(key, []), 1)]
            return [record(item, index, cls, ike_version=item.get("ike_version"),
                explicit_fields=["ike_version"] if "ike_version" in item else [],
                source_attributes={"resource_type": legacy_key})
                for index, item in enumerate(_items(self.payload.get(legacy_key)), 1)]

        routes, dhcp, dhcp_relay_settings, interfaces = [], [], [], []
        policy_based_routes, ecmp_zones, virtual_routers, sla_monitors = [], [], [], []
        def adapt_certificate(item: dict, index: int, family: str):
            validity = {key: item[key] for key in ("validityStartDate", "validityEndDate", "notBefore", "notAfter")
                        if key in item}
            metadata = {key: item[key] for key in ("fingerprint", "serialNumber", "algorithm", "keyLength", "isCA")
                        if key in item}
            presence_key = next((key for key in ("privateKeyPresent", "private_key_present") if key in item), None)
            secret_keys = ("privateKey", "private_key", "pkcs12")
            private_key_present = (item[presence_key] if presence_key else
                any(bool(item[key]) for key in secret_keys if key in item)
                if any(key in item for key in secret_keys) else None)
            explicit = [field for field in ("issuer", "subject") if field in item]
            if validity:
                explicit.append("validity")
            if metadata:
                explicit.append("certificate_metadata")
            if presence_key or any(key in item for key in secret_keys):
                explicit.append("private_key_present")
            if "type" in item and family not in {"internalcertificates", "device_certificates"}:
                explicit.append("certificate_type")
            return record(item, index, CiscoFTDCertificate,
                certificate_type=("internal" if family == "internalcertificates" else
                    "device" if family == "device_certificates" else item.get("type") or family), source_collection=family,
                device_id=str(item.get("deviceId") or item.get("device_id")) if item.get("deviceId") or item.get("device_id") else None,
                issuer=item.get("issuer"), subject=item.get("subject"), validity=validity or None,
                certificate_metadata=metadata or None, private_key_present=private_key_present,
                explicit_fields=explicit)

        certificates = [adapt_certificate(item, i, family)
            for family in ("internalcertificates", "device_certificates", "externalcertificates", "externalcacertificates")
            for i, item in enumerate(objects.get(family, []), 1)]
        address_pools = [ra_record(item, i, CiscoFTDAddressPool, {
            "source_representation": ("raw", ("addressPool", "addresses", "value")),
            "start_address": ("raw", ("startAddress", "start")),
            "end_address": ("raw", ("endAddress", "end")),
            "address_reuse_delay": ("raw", ("addressReuseDelay", "reuseDelay")),
        }, address_family=family, override_metadata=override_metadata(item))
            for collection, family in (("ipv4addresspools", "IPv4"), ("ipv6addresspools", "IPv6"))
            for i, item in enumerate(objects.get(collection, []), 1)]

        def adapt_group_policy(item: dict, index: int):
            fields = {
                "vpn_access": ("raw", ("vpnAccess",)), "protocols": ("raw", ("protocols", "vpnProtocols")),
                "connection_settings": ("raw", ("connectionSettings",)),
                "dns_servers": ("raw", ("dnsServers",)), "wins_servers": ("raw", ("winsServers",)),
                "domain_name": ("raw", ("domainName", "defaultDomain")),
                "realm": ("ref", ("realm", "realmId")),
                "aaa_server_group": ("ref", ("aaaServerGroup", "authenticationServerGroup")),
                "address_pools": ("refs", ("addressPools", "ipv4AddressPools", "ipv6AddressPools")),
                "split_tunnel_policy": ("raw", ("splitTunnelPolicy",)),
                "split_tunnel_networks": ("refs", ("splitTunnelNetworks",)),
                "split_dns": ("raw", ("splitDns", "splitDNS")),
                "secure_client": ("refs", ("secureClient", "secureClientPackages", "secureClientProfiles")),
                "session_settings": ("raw", ("sessionSettings",)),
                "simultaneous_logins": ("raw", ("simultaneousLogins",)),
            }
            result = ra_record(item, index, CiscoFTDGroupPolicy, fields)
            general = item.get("generalSettings") if isinstance(item.get("generalSettings"), dict) else {}
            assignment = general.get("addressAssignment") if isinstance(general.get("addressAssignment"), dict) else {}
            split_settings = general.get("splitTunnelSettings") if isinstance(general.get("splitTunnelSettings"), dict) else {}
            client = item.get("anyConnectSettings") if isinstance(item.get("anyConnectSettings"), dict) else {}
            advanced = item.get("advancedSettings") if isinstance(item.get("advancedSettings"), dict) else {}
            session = advanced.get("sessionSettings") if isinstance(advanced.get("sessionSettings"), dict) else {}

            def nested(field: str, value: Any):
                if field not in result.explicit_fields:
                    setattr(result, field, sanitize_source_attributes(value))
                    result.explicit_fields.append(field)

            if "protocol" in item:
                nested("protocols", item["protocol"])
            dns = [general[key] for key in ("primaryDNSServer", "secondaryDNSServer") if key in general]
            if dns:
                nested("dns_servers", dns)
            wins = [general[key] for key in ("primaryWINSServer", "secondaryWINSServer") if key in general]
            if wins:
                nested("wins_servers", wins)
            if "defaultDomainName" in assignment:
                nested("domain_name", assignment["defaultDomainName"])
            pools = [ref for key in ("ipv4LocalAddressPool", "ipv6LocalAddressPool")
                     if key in assignment for ref in refs(assignment[key])]
            if pools or any(key in assignment for key in ("ipv4LocalAddressPool", "ipv6LocalAddressPool")):
                if "address_pools" not in result.explicit_fields:
                    result.address_pools = pools
                    result.explicit_fields.append("address_pools")
            policies = {key: split_settings[key] for key in ("ipv4SplitTunnelPolicy", "ipv6SplitTunnelPolicy")
                        if key in split_settings}
            if policies:
                nested("split_tunnel_policy", policies)
            if "splitTunnelACL" in split_settings:
                result.split_tunnel_acl = ref_field(split_settings, "splitTunnelACL")
                result.explicit_fields.append("split_tunnel_acl")
            split_dns = {key: split_settings[key] for key in ("splitDNSDomainList", "splitDNSRequestPolicy")
                         if key in split_settings}
            if split_dns:
                nested("split_dns", split_dns)
            if "connectionSettings" in client:
                nested("connection_settings", client["connectionSettings"])
            if "vpnClientProfile" in client and "secure_client" not in result.explicit_fields:
                result.secure_client = refs(client["vpnClientProfile"])
                result.explicit_fields.append("secure_client")
            if "sessionSettings" in advanced:
                nested("session_settings", advanced["sessionSettings"])
            if "simultaneousLoginPerUser" in session:
                nested("simultaneous_logins", session["simultaneousLoginPerUser"])
            split = item.get("splitTunnel")
            if isinstance(split, dict):
                if "policy" in split and "split_tunnel_policy" not in result.explicit_fields:
                    result.split_tunnel_policy = sanitize_source_attributes(split["policy"])
                    result.explicit_fields.append("split_tunnel_policy")
                if "networks" in split and "split_tunnel_networks" not in result.explicit_fields:
                    result.split_tunnel_networks = refs(split["networks"])
                    result.explicit_fields.append("split_tunnel_networks")
            elif isinstance(split, list) and "split_tunnel_networks" not in result.explicit_fields:
                result.split_tunnel_networks = refs(split)
                result.explicit_fields.append("split_tunnel_networks")
            result.split_tunnel = result.split_tunnel_networks
            return result

        def adapt_ra_profile(item: dict, index: int, vpn: dict):
            profile = ra_record(item, index, CiscoFTDRAVPNConnectionProfile, {
                "alias": ("raw", ("groupAlias", "alias")),
                "group_url": ("raw", ("groupUrl", "groupURL")),
                "enabled": ("raw", ("enabled",)),
                "authentication_method": ("raw", ("authenticationMethod",)),
                "realm": ("ref", ("realm", "authenticationRealm")),
                "authentication_server": ("ref", ("primaryAuthenticationServer", "authenticationServerGroup", "authenticationServer")),
                "authorization": ("ref", ("authorizationServer", "authorization")),
                "accounting_server": ("ref", ("accountingServer",)),
                "address_assignment": ("raw", ("addressAssignment", "dhcpServersForAddressAssignment")),
                "address_pools": ("refs", ("addressPools", "ipv4AddressPools", "ipv6AddressPools", "ipv4AddressPool", "ipv6AddressPool")),
                "default_group_policy": ("ref", ("defaultGroupPolicy", "groupPolicy")),
                "certificates": ("refs", ("certificates", "certificate")),
                "certificate_maps": ("refs", ("certificateMaps", "certificateMap")),
                "connection_settings": ("raw", ("connectionSettings",)),
            }, parent_policy_id=str(vpn.get("id")) if vpn.get("id") is not None else None,
                parent_policy_name=vpn.get("name"),
                source_attributes={"parent_policy_id": vpn.get("id"), "parent_policy_name": vpn.get("name")})
            pools = [key for key in ("ipv4AddressPool", "ipv6AddressPool", "ipv4AddressPools", "ipv6AddressPools")
                     if key in item]
            if pools:
                profile.address_pools = ([ref for key in pools for ref in refs(item[key])]
                    if any(item[key] is not None for key in pools) else None)
                if "address_pools" not in profile.explicit_fields:
                    profile.explicit_fields.append("address_pools")
            return profile

        group_policies = [adapt_group_policy(item, i) for i, item in enumerate(objects.get("grouppolicies", []), 1)]
        certificate_maps = [ra_record(item, i, CiscoFTDCertificateMap, {
            "conditions": ("raw", ("conditions", "rules")),
            "connection_profile": ("ref", ("connectionProfile",)),
            "group_policy": ("ref", ("groupPolicy",)),
        }) for i, item in enumerate(objects.get("certificatemaps", []), 1)]
        certificate_enrollments = object_records("certenrollments", CiscoFTDCertificateEnrollment)
        prefilter_children = typed_child_records("prefilterpolicies", (("rules", CiscoFTDPrefilterRule),
            ("default_actions", CiscoFTDPrefilterDefaultAction)))
        network_analysis_children = typed_child_records("networkanalysispolicies", (
            ("inspectorconfigs", CiscoFTDInspectorConfig), ("inspectoroverrideconfigs", CiscoFTDInspectorOverrideConfig)))
        s2s_children = typed_child_records("s2svpns", (("ike_settings", CiscoFTDS2SIKESettings),
            ("ipsec_settings", CiscoFTDS2SIPsecSettings), ("advanced_settings", CiscoFTDS2SAdvancedSettings)))
        ra_children = typed_child_records("ravpns", (("ipsec_advanced_settings", CiscoFTDRAVPNIPsecSettings),
            ("ldap_attribute_maps", CiscoFTDLDAPAttributeMap), ("load_balance_settings", CiscoFTDRAVPNLoadBalanceSettings),
            ("address_assignment_settings", CiscoFTDRAVPNAddressAssignmentSettings),
            ("secure_client_customization_settings", CiscoFTDSecureClientSettings),
            ("ipsec_crypto_maps", CiscoFTDRAVPNIPsecCryptoMap)))
        typed_objects = {"networkaddresses", "network_address_overrides", "policy_assignments", "hosts", "networks", "ranges", "fqdnobjects", "networkgroups",
                         "protocolportobjects", "portobjectgroups", "securityzones", "interfacegroups", "applications",
                         "timeranges", "filepolicies", "decryptionpolicies", "dnspolicies", "intrusionpolicies",
                         "realms", "realmusergroups", "realmusers", "localrealmusers", "s2svpns", "ravpns", "identitypolicies", "variablesets",
                         "urlcategories", "vlanobjects", "slamonitors", "ikev1policies", "ikev2policies",
                         "ikev1ipsecproposals", "ikev2ipsecproposals", "ipv4addresspools", "ipv6addresspools",
                         "grouppolicies", "certificatemaps", "certenrollments", "internalcertificates",
                         "device_certificates", "externalcertificates", "externalcacertificates",
                         "prefilterpolicies", "networkanalysispolicies"}
        for collection_name, items in objects.items():
            if collection_name in typed_objects:
                continue
            native.extend(record(item, index, CiscoFTDNativeResource,
                source_attributes={"resource_type": collection_name, "ownership": "domain"},
                raw_extra=sanitize_source_attributes({key: value for key, value in item.items()
                    if not (collection_name in {"siurlfeeds", "siipfeeds"} and
                            key.casefold().replace("_", "") in {"entries", "members", "feeddata",
                                "downloadedentries", "content", "contents", "ipaddresses", "domains"})}))
                for index, item in enumerate(_items(items), 1))
        for device in _items(self.payload.get("devices")):
            device_id = str(device.get("id") or "")
            device_name = str(device.get("name") or device_id)
            resources = device.get("resources") if isinstance(device.get("resources"), dict) else {}
            interfaces.extend(record(item, index, CiscoFTDInterfaceSource,
                interface_type=item.get("interfaceType", item.get("type")), address=item.get("address"), device_id=device_id,
                source_attributes={"device_id": device_id, "device_name": device_name, "domain_id": self.domain_id})
                for index, item in enumerate(_items(resources.get("ftd_interfaces")), 1))
            interfaces.extend(record(item, index, CiscoFTDInterfaceSource,
                interface_type=item.get("interfaceType", item.get("type")), address=item.get("address"), device_id=device_id,
                source_attributes={"device_id": device_id, "device_name": device_name, "domain_id": self.domain_id,
                                   "interface_family": "virtual_tunnel_interface"})
                for index, item in enumerate(_items(resources.get("virtual_tunnel_interfaces")), 1))
            route_families = [("IPv4", item) for item in _items(resources.get("static_routes"))]
            route_families += [("IPv6", item) for item in _items(resources.get("ipv6_static_routes"))]
            for index, (family, item) in enumerate(route_families, 1):
                gateway = item.get("gateway")
                gateway_value = (gateway.get("object") or gateway.get("literal")
                                 if isinstance(gateway, dict) else gateway)
                selected = item.get("selectedNetworks")
                selected = selected if isinstance(selected, list) else []
                destination_value = selected[0] if selected else item.get("network") or item.get("destination")
                routes.append(record(item, index, CiscoFTDRoute, device_id=device_id,
                    interface=reference(item.get("interfaceName") or item.get("interface")) if item.get("interfaceName") or item.get("interface") else None,
                    destination=reference(destination_value) if destination_value else None,
                    selected_networks=refs(selected) if "selectedNetworks" in item else None,
                    gateway=reference(gateway_value) if gateway_value else None, address_family=item.get("addressFamily", family),
                    metric=item.get("metricValue", item.get("metric")), virtual_router=(str(item["virtualRouter"].get("name") or item["virtualRouter"].get("id") or "")
                        if isinstance(item.get("virtualRouter"), dict) else str(item["virtualRouter"]) if item.get("virtualRouter") else None),
                    virtual_router_ref=reference(item["virtualRouter"]) if item.get("virtualRouter") else None,
                    sla_monitor=reference(item.get("routeTracking", {}).get("slaMonitor") or item["slaMonitor"])
                        if item.get("routeTracking", {}).get("slaMonitor") or item.get("slaMonitor") else None,
                    route_tracking=sanitize_source_attributes(item.get("routeTracking")) if "routeTracking" in item else None,
                    tunneled=item.get("isTunneled") if "isTunneled" in item else None,
                    source_attributes={"device_id": device_id, "device_name": device_name, "domain_id": self.domain_id}))
            for vr in _items(resources.get("virtual_routers")):
                vr_id = str(vr.get("id") or "")
                vr_name = str(vr.get("name") or vr_id)
                vr_resources = vr.get("resources") if isinstance(vr.get("resources"), dict) else {}
                virtual_routers.append(record(vr, 1, CiscoFTDVirtualRouter,
                    interfaces=refs_field(vr, "interfaces", "interfaceNames"), device_id=device_id,
                    source_attributes={"device_id": device_id, "device_name": device_name,
                                       "virtual_router_id": vr_id, "virtual_router_name": vr_name}))
                for key in ("ipv4_static_routes", "ipv6_static_routes", "pbr_policies", "ecmp_zones"):
                    items = _items(vr_resources.get(key))
                    if key in {"ipv4_static_routes", "ipv6_static_routes"}:
                        family = "IPv6" if key == "ipv6_static_routes" else "IPv4"
                        gateway = item.get("gateway")
                        gateway_value = (gateway.get("object") or gateway.get("literal")
                                         if isinstance(gateway, dict) else gateway)
                        selected = item.get("selectedNetworks")
                        selected = selected if isinstance(selected, list) else []
                        destination_value = selected[0] if selected else item.get("network") or item.get("destination")
                        routes.extend(record(item, index, CiscoFTDRoute, device_id=device_id,
                            interface=reference(item.get("interfaceName") or item.get("interface")) if item.get("interfaceName") or item.get("interface") else None,
                            destination=reference(destination_value) if destination_value else None,
                            selected_networks=refs(selected) if "selectedNetworks" in item else None,
                            gateway=reference(gateway_value) if gateway_value else None,
                            address_family=item.get("addressFamily", family),
                            metric=item.get("metricValue", item.get("metric")), virtual_router=vr_name,
                            virtual_router_ref=reference({"id": vr_id, "name": vr_name}),
                            route_tracking=sanitize_source_attributes(item.get("routeTracking")) if "routeTracking" in item else None,
                            tunneled=item.get("isTunneled") if "isTunneled" in item else None,
                            source_attributes={"device_id": device_id, "virtual_router_id": vr_id, "virtual_router_name": vr_name})
                            for index, item in enumerate(items, 1))
                    elif key == "pbr_policies":
                        policy_based_routes.extend(record(item, index, CiscoFTDPolicyBasedRoute,
                            virtual_router=reference({"id": vr_id, "name": vr_name}),
                            ingress_interface=ref_field(item, "ingressInterface", "ingress_interface", "sourceInterface"),
                            egress_interface=ref_field(item, "egressInterface", "egress_interface"),
                            path_interface=ref_field(item, "pathInterface", "path_interface", "interface"),
                            networks=refs_field(item, "networks", "networkObjects", "sourceNetworks", "destinationNetworks"),
                            sla_monitor=ref_field(item, "slaMonitor", "sla_monitor"),
                            position=item.get("position", item.get("order")), device_id=device_id,
                            source_attributes={"device_id": device_id, "device_name": device_name,
                                "virtual_router_id": vr_id, "virtual_router_name": vr_name}) for index, item in enumerate(items, 1))
                    else:
                        ecmp_zones.extend(record(item, index, CiscoFTDECMPZone,
                            interfaces=refs_field(item, "interfaces", "members"), device_id=device_id,
                            source_attributes={"device_id": device_id, "device_name": device_name,
                                "virtual_router_id": vr_id, "virtual_router_name": vr_name}) for index, item in enumerate(items, 1))
            dhcp.extend(record(item, index, CiscoFTDDHCPServer,
                interface=reference(item["interfaceName"]) if item.get("interfaceName") is not None else None,
                explicit_fields=["interface"] if "interfaceName" in item else [],
                source_attributes={"device_id": device_id, "device_name": device_name, "domain_id": self.domain_id})
                for index, item in enumerate(_items(resources.get("dhcp_servers")), 1))
            dhcp_relay_settings.extend(record(item, index, CiscoFTDDHCPRelaySettings,
                relay_agents=sanitize_source_attributes(item.get("dhcpRelayAgent")) if "dhcpRelayAgent" in item else None,
                relay_servers=sanitize_source_attributes(item.get("dhcpRelayServers")) if "dhcpRelayServers" in item else None,
                ipv4_timeout_seconds=item.get("ipv4TimeoutInSec") if "ipv4TimeoutInSec" in item else None,
                ipv6_timeout_seconds=item.get("ipv6TimeoutInSec") if "ipv6TimeoutInSec" in item else None,
                trust_all_information=(item.get("trustAllInformation") if "trustAllInformation" in item
                    else item.get("isTrustAllInformation") if "isTrustAllInformation" in item else None),
                explicit_fields=[field for field, keys in (
                    ("relay_agents", ("dhcpRelayAgent",)), ("relay_servers", ("dhcpRelayServers",)),
                    ("ipv4_timeout_seconds", ("ipv4TimeoutInSec",)), ("ipv6_timeout_seconds", ("ipv6TimeoutInSec",)),
                    ("trust_all_information", ("trustAllInformation", "isTrustAllInformation"))) if any(key in item for key in keys)],
                source_attributes={"device_id": device_id, "device_name": device_name, "domain_id": self.domain_id})
                for index, item in enumerate(_items(resources.get("dhcp_relay_settings")), 1))
            for key, cls, target in (("pbr_policies", CiscoFTDPolicyBasedRoute, policy_based_routes),
                                     ("ecmp_zones", CiscoFTDECMPZone, ecmp_zones),
                                     ("sla_monitors", CiscoFTDSLAMonitor, sla_monitors)):
                for index, item in enumerate(_items(resources.get(key)), 1):
                    values = {"device_id": device_id,
                              "source_attributes": {"device_id": device_id, "device_name": device_name,
                                                    "domain_id": self.domain_id}}
                    if cls is CiscoFTDPolicyBasedRoute:
                        values.update(ingress_interface=ref_field(item, "ingressInterface", "ingress_interface", "sourceInterface"),
                            egress_interface=ref_field(item, "egressInterface", "egress_interface"),
                            path_interface=ref_field(item, "pathInterface", "path_interface", "interface"),
                            networks=refs_field(item, "networks", "networkObjects", "sourceNetworks", "destinationNetworks"),
                            sla_monitor=ref_field(item, "slaMonitor", "sla_monitor"), position=item.get("position", item.get("order")))
                    elif cls is CiscoFTDECMPZone:
                        values["interfaces"] = refs_field(item, "interfaces", "members")
                    target.append(record(item, index, cls, **values))

        file_rule_fields = {
            "enabled": ("enabled", "isEnabled"), "action": ("action",),
            "application_protocols": ("protocol", "applicationProtocols", "applicationProtocol"),
            "transfer_direction": ("direction", "transferDirection"),
            "file_types": ("fileTypes", "types"),
            "malware_inspection": ("analysis", "malwareInspection", "inspectMalware", "malware"),
            "file_store": ("storeFiles", "fileStore"),
        }
        decryption_rule_fields = {
            "enabled": ("enabled", "isEnabled"), "action": ("ruleAction", "action"),
            "source_networks": ("sourceNetworks", "sourceNetwork"),
            "destination_networks": ("destinationNetworks", "destinationNetwork"),
            "source_ports": ("sourcePorts", "sourcePort"),
            "destination_ports": ("destinationPorts", "destinationPort"),
            "certificates": ("decryptionCerts", "externalCertificates", "certificates", "certificate", "certificateAuthority"),
            "tls_conditions": ("tlsVersions", "tlsConditions", "tlsCondition"),
            "certificate_status_conditions": ("certStatuses", "certificateStatusConditions", "certificateStatus"),
        }
        dns_rule_fields = {
            "enabled": ("enabled", "isEnabled"), "action": ("ruleAction", "action"),
            "source_zones": ("sourceZones", "sourceZone"),
            "destination_zones": ("destinationZones", "destinationZone"),
            "source_networks": ("sourceNetworks", "sourceNetwork"),
            "destination_networks": ("destinationNetworks", "destinationNetwork"),
            "networks": ("networks",),
            "vlan_tags": ("vlanTags", "vlans"),
            "lists_feeds": ("dnsLists", "dnsFeeds", "securityIntelligenceLists", "lists", "feeds", "urlLists", "ipLists", "urlFeeds"),
        }
        file_policies = [adapt_inspection_policy(item, index, CiscoFTDFilePolicy, CiscoFTDFileRule,
            ("rules", "filerules", "filepolicyrules"), file_rule_fields,
            {"description": ("description",)}) for index, item in enumerate(objects.get("filepolicies", []), 1)]
        decryption_policies = [adapt_inspection_policy(item, index, CiscoFTDDecryptionPolicy, CiscoFTDDecryptionRule,
            ("rules", "decryptionpolicyrules"), decryption_rule_fields,
            {"description": ("description",), "default_action": ("defaultAction",),
             "undecryptable_action": ("undecryptableActions", "undecryptableAction", "undecryptableTrafficAction"),
             "advanced_settings": ("advancedOptions", "advancedSettings")})
            for index, item in enumerate(objects.get("decryptionpolicies", []), 1)]
        dns_policies = [adapt_inspection_policy(item, index, CiscoFTDDNSPolicy, CiscoFTDDNSRule,
            ("rules", "block_rules"), dns_rule_fields,
            {"description": ("description",), "default_action": ("defaultAction",),
             "umbrella_settings": ("umbrellaSettings", "umbrella")})
            for index, item in enumerate(objects.get("dnspolicies", []), 1)]

        return CiscoFTDConfig(
            input_source_type=plane, source_plane=plane,
            source_metadata={
                "domain_id": self.domain_id, "domain_name": self.domain_name,
                "source": self.payload.get("source", "fmc-rest-api"),
                "collection": collection or {},
                "coverage": self.payload.get("coverage", {}),
            },
            collection_metadata=collection_metadata,
            unsupported_evidence=[{"source_path": part.name, "reason": "FMC collection incomplete",
                                   "status": part.status, "complete": part.complete, "count": part.count}
                for part in collection_metadata.parts if not part.complete] + [
                    {"source_path": f"fmc/coverage/{area}", "reason": detail.get("reason", "Source area status"),
                     "status": detail.get("status"), "source": detail.get("source")}
                    for area, detail in (self.payload.get("coverage") or {}).items()
                    if isinstance(detail, dict) and detail.get("status") in {"UNAVAILABLE", "SOURCE_ONLY"}],
            network_addresses=network_addresses, network_groups=network_groups, protocol_port_objects=protocol_ports,
            port_object_groups=port_groups, security_zones=zones, interface_groups=interface_groups,
            device_interfaces=[], source_interfaces=interfaces,
            applications=object_records("applications", CiscoFTDApplication), variable_sets=object_records("variablesets", CiscoFTDVariableSet),
            sla_monitors=[*object_records("slamonitors", CiscoFTDSLAMonitor), *sla_monitors],
            virtual_routers=virtual_routers, policy_based_routes=policy_based_routes,
            ecmp_zones=ecmp_zones, certificates=certificates, certificate_maps=certificate_maps,
            certificate_enrollments=certificate_enrollments, address_pools=address_pools,
            group_policies=group_policies,
            s2s_ike_settings=s2s_children["ike_settings"], s2s_ipsec_settings=s2s_children["ipsec_settings"],
            s2s_advanced_settings=s2s_children["advanced_settings"],
            ra_vpn_ipsec_settings=ra_children["ipsec_advanced_settings"],
            ldap_attribute_maps=ra_children["ldap_attribute_maps"],
            ra_vpn_load_balance_settings=ra_children["load_balance_settings"],
            ra_vpn_address_assignment_settings=ra_children["address_assignment_settings"],
            secure_client_settings=ra_children["secure_client_customization_settings"],
            ra_vpn_ipsec_crypto_maps=ra_children["ipsec_crypto_maps"],
            prefilter_policies=object_records("prefilterpolicies", CiscoFTDPrefilterPolicy),
            prefilter_rules=prefilter_children["rules"], prefilter_default_actions=prefilter_children["default_actions"],
            network_analysis_policies=object_records("networkanalysispolicies", CiscoFTDNetworkAnalysisPolicy),
            inspector_configs=network_analysis_children["inspectorconfigs"],
            inspector_override_configs=network_analysis_children["inspectoroverrideconfigs"],
            url_categories=object_records("urlcategories", CiscoFTDURLCategory), vlan_objects=object_records("vlanobjects", CiscoFTDVLANObject),
            access_control_policies=acp_policies, nat_policies=nat_policies,
            identity_policies=object_records("identitypolicies", CiscoFTDIdentityPolicy),
            time_ranges=[adapt_time_range(item, i) for i, item in enumerate(objects.get("timeranges", []), 1)],
            intrusion_policies=intrusion_policies,
            intrusion_rule_groups=intrusion_rule_groups,
            intrusion_rule_behaviors=intrusion_rule_behaviors,
            intrusion_rule_overrides=intrusion_rule_overrides,
            file_policies=file_policies,
            decryption_policies=decryption_policies,
            dns_policies=dns_policies,
            fmc_user_roles=[adapt_fmc_role(item, i) for i, item in enumerate(_items(self.payload.get("fmc_roles")), 1)],
            fmc_users=[adapt_fmc_user(item, i) for i, item in enumerate(_items(self.payload.get("fmc_users")), 1)],
            dhcp_servers=dhcp, dhcp_relay_settings=dhcp_relay_settings, routes=routes,
            network_address_overrides=network_address_overrides,
            access_control_default_actions=acp_default_actions,
            access_policy_inheritance_settings=acp_inheritance_settings,
            policy_assignments=policy_assignments,
            realms=[adapt_realm(item, i) for i, item in enumerate(objects.get("realms", []), 1)],
            realm_user_groups=[adapt_realm_identity(item, i, CiscoFTDRealmUserGroup)
                               for i, item in enumerate(objects.get("realmusergroups", []), 1)],
            realm_users=[adapt_realm_identity(item, i, CiscoFTDRealmUser, user=True)
                         for i, item in enumerate(objects.get("realmusers", []), 1)],
            local_realm_users=[adapt_local_realm_user(item, i)
                               for i, item in enumerate(objects.get("localrealmusers", []), 1)],
            s2s_vpn_topologies=object_records("s2svpns", CiscoFTDS2SVPNTopology),
            s2s_vpn_endpoints=[record(item, i, CiscoFTDS2SVPNEndpoint,
                device=ref_field(item, "device", "managedDevice"), interface=ref_field(item, "interface"),
                vti=ref_field(item, "vti", "virtualTunnelInterface"),
                protected_networks=refs(item["protectedNetworks"].get("networks"))
                    if isinstance(item.get("protectedNetworks"), dict) and "networks" in item["protectedNetworks"]
                    else refs_field(item, "protectedNetworks", "networks"),
                peer_type=item.get("peerType"), connection_type=item.get("connectionType"),
                extranet=item.get("extranet"),
                extranet_info=item.get("extranetInfo") if isinstance(item.get("extranetInfo"), dict) else None,
                peer_ip_address=(item.get("extranetInfo", {}).get("ipAddress")
                                 if isinstance(item.get("extranetInfo"), dict) else None),
                local_identity_type=item.get("localIdentityType"), local_identity=item.get("localIdentityString"),
                local_identity_enabled=item.get("isLocalTunnelIdEnabled"),
                source_attributes={"parent_topology_id": vpn.get("id"), "parent_topology_name": vpn.get("name")})
                for vpn in objects.get("s2svpns", []) for i, item in enumerate(_items(vpn.get("endpoints")), 1)],
            ike_policies=vpn_records((
                ("ikev1policies", "IKEv1"), ("ikev2policies", "IKEv2")), "ike_policies", CiscoFTDIKEPolicy),
            ipsec_proposals=vpn_records((
                ("ikev1ipsecproposals", "IKEv1"), ("ikev2ipsecproposals", "IKEv2")), "ipsec_proposals", CiscoFTDIPsecProposal),
            ra_vpn_policies=[ra_record(item, i, CiscoFTDRAVPNPolicy, {
                "target_devices": ("refs", ("targetDevices", "devices")),
                "access_interfaces": ("refs", ("accessInterfaces", "interfaces")),
                "certificates": ("refs", ("certificates", "certificate")),
                "certificate_maps": ("refs", ("certificateMaps", "certificateMap")),
                "certificate_map_settings": ("raw", ("certificate_map_settings", "certificateMapSettings")),
                "connection_profiles": ("refs", ("connectionProfiles",)),
                "group_policies": ("refs", ("groupPolicies",)),
                "address_pools": ("refs", ("addressPools",)),
                "realms": ("refs", ("realms", "realm")),
                "ssl_tls_settings": ("raw", ("sslTlsSettings", "sslSettings")),
                "dtls_settings": ("raw", ("dtlsSettings",)),
                "session_settings": ("raw", ("sessionSettings",)),
            })
                for i, item in enumerate(objects.get("ravpns", []), 1)],
            ra_vpn_connection_profiles=[adapt_ra_profile(item, i, vpn)
                for vpn in objects.get("ravpns", []) for i, item in enumerate(_items(vpn.get("connection_profiles")), 1)],
            native_resources=native,
        )


__all__ = ["CiscoFMCBundleParser", "FMC_BUNDLE_FORMAT", "is_fmc_bundle"]
