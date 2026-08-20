# Intermediate Representation (IR) Data Structure (Updated)

The central data structure is `IRConfig`, which acts as the root schema for all firewall configurations. It contains lists of sub-models representing various firewall components.

## Root Model: `IRConfig`

| Field | Type | Description |
| :--- | :--- | :--- |
| `metadata` | `IRMetadata` | System information and migration metadata. |
| `zones` | `List[IRZone]` | Network topology zones. |
| `interfaces` | `List[IRInterface]` | Network interfaces (physical, subinterfaces, VLANs). |
| `addresses` | `List[IRAddress]` | Address objects (IP, CIDR, FQDN, MAC, Geo). |
| `address_groups` | `List[IRAddressGroup]` | Groups of address objects. |
| `services` | `List[IRService]` | Custom service definitions (TCP, UDP, ICMP, etc.). |
| `service_groups` | `List[IRServiceGroup]` | Groups of service objects. |
| `schedules` | `List[IRSchedule]` | Time-based enforcement schedules. |
| `security_profile_groups` | `List[IRSecurityProfileGroup]` | Unified threat inspection profiles (AV, IPS, etc.). |
| `policies` | `List[IRPolicy]` | Security and firewall rules. |
| `nat_rules` | `List[IRNATRule]` | Source and Destination NAT rules. |
| `vpn_tunnels` | `List[IRVPNTunnel]` | IPsec VPN gateway and tunnel configurations. |
| `routes` | `List[IRRoute]` | Static routing table entries. |
| `internet_services` | `List[IRInternetService]` | **[NEW]** Built-in SaaS objects (ISDB). |
| `audit_entries` | `List[IRAuditEntry]` | Migration audit trails and confidence scores. |

---

## Sub-Models

### `IRMetadata`
| Field | Type | Default / Note |
| :--- | :--- | :--- |
| `hostname` | `str` | Firewall hostname |
| `source_vendor` | `str` | Default: `"fortinet"` |
| `target_vendor` | `Optional[str]` | |
| `migration_timestamp` | `datetime` | Default: Current UTC time |

### `IRZone`
| Field | Type | Default / Note |
| :--- | :--- | :--- |
| `name` | `str` | |
| `interfaces` | `List[str]` | Default: `[]` |
| `description` | `Optional[str]` | |

### `IRInterface`
| Field | Type | Default / Note |
| :--- | :--- | :--- |
| `name` | `str` | |
| `zone` | `Optional[str]` | |
| `ip` | `Optional[str]` | CIDR format (e.g., `192.168.1.1/24`) |
| `description` | `Optional[str]` | |
| `management_profile` | `Optional[str]` | |
| `parent` | `Optional[str]` | For subinterfaces/VLANs |
| `tag` | `Optional[int]` | VLAN tag |
| `alias` | `Optional[str]` | **[NEW]** Interface alias / secondary name |
| `status` | `bool` | **[NEW]** Administrative state (Default: `True`) |
| `vlanid` | `Optional[int]` | **[NEW]** Explicit VLAN ID |
| `pppoe_mode` | `Optional[str]` | **[NEW]** PPPoE connection mode |
| `pppoe_username` | `Optional[str]` | **[NEW]** PPPoE authentication username |

### `IRAddress`
| Field | Type | Default / Note |
| :--- | :--- | :--- |
| `name` | `str` | |
| `type` | `AddressType` | Enum |
| `value` | `str` | CIDR, FQDN, range string, or MAC/Geo |
| `description` | `Optional[str]` | |
| `tags` | `List[str]` | Default: `[]` |
| `is_ipv6` | `bool` | **[NEW]** Indicates IPv6 address object (Default: `False`) |
| `is_multicast` | `bool` | **[NEW]** Indicates Multicast address object (Default: `False`) |

### `IRAddressGroup`
| Field | Type | Default / Note |
| :--- | :--- | :--- |
| `name` | `str` | |
| `members` | `List[str]` | Default: `[]` |
| `description` | `Optional[str]` | |
| `is_dynamic` | `bool` | Default: `False` |
| `dynamic_filter` | `Optional[str]` | |
| `tags` | `List[str]` | Default: `[]` |

### `IRServicePort`
| Field | Type | Default / Note |
| :--- | :--- | :--- |
| `protocol` | `ServiceProtocol` | Enum |
| `port` | `str` | e.g., `"443"`, `"80-90"` |
| `icmptype` | `Optional[int]` | **[NEW]** Specific ICMP type identifier |
| `icmpcode` | `Optional[int]` | **[NEW]** Specific ICMP code identifier |

### `IRService`
| Field | Type | Default / Note |
| :--- | :--- | :--- |
| `name` | `str` | |
| `ports` | `List[IRServicePort]` | Default: `[]` |
| `description` | `Optional[str]` | |

### `IRServiceGroup`
| Field | Type | Default / Note |
| :--- | :--- | :--- |
| `name` | `str` | |
| `members` | `List[str]` | Default: `[]` |
| `description` | `Optional[str]` | |

### `IRSchedule`
| Field | Type | Default / Note |
| :--- | :--- | :--- |
| `name` | `str` | |
| `start` | `Optional[str]` | |
| `end` | `Optional[str]` | |
| `days` | `List[str]` | Default: `[]` |

### `IRSecurityProfileGroup`
| Field | Type | Default / Note |
| :--- | :--- | :--- |
| `name` | `str` | |
| `antivirus` | `Optional[str]` | |
| `vulnerability` | `Optional[str]` | |
| `anti_spyware` | `Optional[str]` | |
| `url_filtering` | `Optional[str]` | |
| `file_blocking` | `Optional[str]` | |
| `wildfire` | `Optional[str]` | |
| `ssl_decryption` | `Optional[str]` | |
| `description` | `Optional[str]` | |

### `IRPolicy`
| Field | Type | Default / Note |
| :--- | :--- | :--- |
| `name` | `str` | |
| `from_zone` | `List[str]` | Default: `[]` |
| `to_zone` | `List[str]` | Default: `[]` |
| `source` | `List[str]` | Default: `[]` |
| `destination` | `List[str]` | Default: `[]` |
| `service` | `List[str]` | Default: `[]` |
| `action` | `PolicyAction` | Enum |
| `description` | `Optional[str]` | |
| `log_start` | `bool` | Default: `False` |
| `log_end` | `bool` | Default: `True` |
| `disabled` | `bool` | Default: `False` |
| `security_profile_group` | `Optional[str]` | |
| `antivirus` | `Optional[str]` | |
| `ips_sensor` | `Optional[str]` | |
| `webfilter` | `Optional[str]` | |
| `application_list` | `Optional[str]` | |
| `ssl_ssh_profile` | `Optional[str]` | |
| `applications` | `List[str]` | Default: `[]` |
| `internet_service` | `List[str]` | **[NEW]** SaaS / ISDB objects used as destinations |

### `IRInternetService` [NEW]
| Field | Type | Default / Note |
| :--- | :--- | :--- |
| `name` | `str` | e.g. `"Microsoft-Office365"` |
| `description` | `Optional[str]` | |

### `IRNATRule`
| Field | Type | Default / Note |
| :--- | :--- | :--- |
| `name` | `str` | |
| `type` | `NATType` | Enum |
| `from_zone` | `List[str]` | Default: `[]` |
| `to_zone` | `List[str]` | Default: `[]` |
| `source` | `List[str]` | Default: `[]` |
| `destination` | `List[str]` | Default: `[]` |
| `service` | `str` | Default: `"any"` |
| `translated_source` | `Optional[str]` | |
| `translated_destination`| `Optional[str]` | |
| `translated_port` | `Optional[str]` | |
| `description` | `Optional[str]` | |

### `IRVPNTunnel`
| Field | Type | Default / Note |
| :--- | :--- | :--- |
| `name` | `str` | |
| `peer_address` | `str` | |
| `local_interface` | `str` | |
| `ike_version` | `str` | Default: `"v1"` |
| `psk` | `Optional[str]` | |
| `ike_crypto_profile` | `str` | Default: `"default"` |
| `ipsec_crypto_profile`| `str` | Default: `"default"` |
| `description` | `Optional[str]` | |

### `IRRoute`
| Field | Type | Default / Note |
| :--- | :--- | :--- |
| `name` | `str` | |
| `destination` | `str` | |
| `interface` | `Optional[str]` | |
| `next_hop` | `Optional[str]` | |
| `metric` | `int` | Default: `10` |
| `description` | `Optional[str]` | |

### `IRAuditEntry`
| Field | Type | Default / Note |
| :--- | :--- | :--- |
| `id` | `str` | |
| `category` | `str` | |
| `message` | `str` | |
| `confidence` | `MigrationConfidence` | Enum |
| `original_config` | `Optional[str]` | |

---

## Enumerations (Enums)

### `AddressType`
- `NETWORK` (`"network"`)
- `HOST` (`"host"`)
- `RANGE` (`"range"`)
- `FQDN` (`"fqdn"`)
- `WILDCARD_FQDN` (`"wildcard"`)
- `GROUP` (`"group"`)
- `DYNAMIC` (`"dynamic"`)
- `GEO` (`"geo"`)
- `WILDCARD_MASK` (`"wildcard_mask"`)
- `MAC` (`"mac"`) **[NEW]**
- `EMS_TAG` (`"ems_tag"`) **[NEW]**

### `ServiceProtocol`
- `TCP` (`"tcp"`)
- `UDP` (`"udp"`)
- `ICMP` (`"icmp"`)
- `ICMPV6` (`"icmpv6"`)
- `IP` (`"ip"`)
- `ANY` (`"any"`)

### `PolicyAction`
- `ALLOW` (`"allow"`)
- `DENY` (`"deny"`)
- `DROP` (`"drop"`)

### `NATType`
- `SOURCE` (`"source"`)
- `DESTINATION` (`"destination"`)

### `MigrationConfidence`
- `FULL` (`"full"`)
- `PARTIAL` (`"partial"`)
- `MANUAL` (`"manual"`)
- `UNSUPPORTED` (`"unsupported"`)
