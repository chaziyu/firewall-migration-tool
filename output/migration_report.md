# 🛡️ Firewall Migration & Configuration Report

- **Hostname:** `FortiGate-500E`
- **Source Vendor:** Fortigate
- **Target Platform:** Palo Alto Networks (PAN-OS / Panorama)
- **Generated At:** 2026-08-20 02:16:49 UTC

## 1. Executive Summary & Migration Health

### Migration Health & Confidence

| Metric | Count | Status / Notes |
| :--- | :--- | :--- |
| **Total Processed Objects** | **19** | Combined network, object, security, and policy entities |
| 🟢 **Full Confidence** | 19 | Translated directly with high fidelity |
| 🟡 **Partial Confidence** | 0 | Semantic translation completed; review suggested |
| 🟠 **Manual Review Required** | 0 | Vendor-proprietary features requiring manual mapping |
| 🔴 **Unsupported** | 0 | Feature not supported in target architecture |

### Configuration Inventory Summary

| Inventory Category | Count | Description |
| :--- | :--- | :--- |
| **Security Zones** | 3 | Logical zone boundaries and interface mappings |
| **Network Interfaces** | 3 | Physical/VLAN interfaces and assigned IP subnets |
| **Address Objects** | 4 | Host, subnet, range, and FQDN definitions |
| **Address Groups** | 1 | Grouped address collections |
| **Service Objects** | 2 | Custom TCP/UDP/ICMP protocol definitions |
| **Service Groups** | 1 | Grouped port and service collections |
| **Threat Profile Groups** | 2 | Unified threat inspection bundles (AV, IPS, URL, etc.) |
| **Security Policies** | 3 | Firewall access control rules |
| **NAT Rules** | 2 | Source, destination, and static NAT translations |
| **IPsec VPN Tunnels** | 0 | Site-to-site IPsec tunnel endpoints |
| **Static Routes** | 1 | Routing table next-hop definitions |

## 2. ⚠️ Audit Trail & Action Items

> [!IMPORTANT]
> Review the following items before deploying the generated configuration to production.

| Category | Object ID | Confidence | Message / Remediation |
| :--- | :--- | :--- | :--- |
| Policy | `1` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_AV_default_IPS_default_WF_default'. |
| Policy | `2` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_AV_default_IPS_protect_server'. |

## 3. 🌐 Network Architecture & Zones

### Interfaces & Zone Assignments

| Interface | Assigned Zone | IP / Subnet | Description |
| :--- | :--- | :--- | :--- |
| `port1` | `trust` | `192.168.1.99/24` | - |
| `port2` | `untrust` | `203.0.113.2/24` | - |
| `port3` | `dmz` | `10.1.1.1/24` | - |

### Security Zones

| Zone Name | Bound Interfaces | Description |
| :--- | :--- | :--- |
| `trust` | `port1` | - |
| `untrust` | `port2` | - |
| `dmz` | `port3` | - |

### Static Routes

| Route Name | Destination | Next Hop | Outgoing Interface | Metric | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `route_1` | `0.0.0.0 0.0.0.0` | `203.0.113.1` | `port2` | 10 | Default Gateway |

## 4. 📦 Object Inventory

### Address Objects

| Address Name | Type | Value | Description |
| :--- | :--- | :--- | :--- |
| `HOST_10.1.1.100` | `network` | `10.1.1.100/32` | Web Server DMZ |
| `NET_192.168.1.0_24` | `network` | `192.168.1.0/24` | Corporate LAN |
| `RANGE_10.1.1.200-250` | `range` | `10.1.1.200-10.1.1.250` | Staging Servers |
| `FQDN_update.microsoft.com` | `fqdn` | `update.microsoft.com` | Windows Update |

### Address Groups

| Group Name | Members | Description |
| :--- | :--- | :--- |
| `GRP_Internal_Networks` | `HOST_10.1.1.100`, `NET_192.168.1.0_24` | All internal corporate subnets |

### Service Objects

| Service Name | Protocol | Port(s) | Description |
| :--- | :--- | :--- | :--- |
| `TCP_8080` | `TCP` | `8080` | Custom Web Proxy |
| `UDP_5000` | `UDP` | `5000` | Internal Streaming |

### Service Groups

| Group Name | Members | Description |
| :--- | :--- | :--- |
| `GRP_Web_Services` | `HTTP`, `HTTPS`, `TCP_8080` | Standard Web Group |

### Universal Threat Prevention & Profile Groups

| Profile Group Name | Antivirus | Vulnerability (IPS) | Anti-Spyware | URL Filtering | File Blocking | Sandbox | Decryption | Description |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `SPG_AV_default_IPS_default_WF_default` | `default` | `default` | `default` | `default` | `basic-file-blocking` | `default` | `certificate-inspection` | Auto-generated profile group for FortiGate UTM (AV_default, IPS_default, WF_default) |
| `SPG_AV_default_IPS_protect_server` | `default` | `protect_server` | `default` | `default` | `basic-file-blocking` | `default` | - | Auto-generated profile group for FortiGate UTM (AV_default, IPS_protect_server) |

## 5. 📋 Rulebase & Policies

### Security Policies

| # | Policy Name | From Zone | To Zone | Source | Destination | Service | Action | Status | Profiles | Description |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `Allow_Corporate_To_Internet` | `trust` | `untrust` | `NET_192.168.1.0_24` | `all` | `ALL` | 🟢 `ALLOW` | Active | `SPG_AV_default_IPS_default_WF_default` | LAN users internet outbound |
| 2 | `Allow_Inbound_Web_VIP` | `untrust` | `dmz` | `all` | `VIP_Web_Server` | `HTTPS` | 🟢 `ALLOW` | Active | `SPG_AV_default_IPS_protect_server` | Inbound traffic to web server |
| 3 | `Deny_Guest_To_DMZ` | `trust` | `dmz` | `all` | `HOST_10.1.1.100` | `ALL` | 🔴 `DENY` | Active | - | Block guest access to DMZ |

### NAT Rules

| Rule Name | Type | From Zone | To Zone | Source | Destination | Translated Source | Translated Dest | Service | Description |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `POOL_NAT_OUT` | `SOURCE` | `any` | `any` | `any` | `any` | `203.0.113.10-203.0.113.20` | - | `any` | Outbound SNAT Pool |
| `VIP_Web_Server` | `DESTINATION` | `untrust` | `any` | `any` | `203.0.113.5` | - | `10.1.1.100` | `any` | Inbound HTTPS to DMZ Web |

## 6. 📄 Raw Canonical Intermediate Representation (JSON)

This section provides the full, machine-readable Intermediate Representation (`IRConfig`) JSON export for pipeline automation and external audit validation.

<details><summary><b>View Full Normalized JSON Data</b> - Click to expand</summary>

```json
{
  "metadata": {
    "hostname": "FortiGate-500E",
    "source_vendor": "fortigate",
    "target_vendor": null,
    "migration_timestamp": "2026-08-20T02:16:49.434077Z"
  },
  "zones": [
    {
      "name": "trust",
      "interfaces": [
        "port1"
      ],
      "description": null
    },
    {
      "name": "untrust",
      "interfaces": [
        "port2"
      ],
      "description": null
    },
    {
      "name": "dmz",
      "interfaces": [
        "port3"
      ],
      "description": null
    }
  ],
  "interfaces": [
    {
      "name": "port1",
      "zone": "trust",
      "ip": "192.168.1.99/24",
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null
    },
    {
      "name": "port2",
      "zone": "untrust",
      "ip": "203.0.113.2/24",
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null
    },
    {
      "name": "port3",
      "zone": "dmz",
      "ip": "10.1.1.1/24",
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null
    }
  ],
  "addresses": [
    {
      "name": "HOST_10.1.1.100",
      "type": "network",
      "value": "10.1.1.100/32",
      "description": "Web Server DMZ"
    },
    {
      "name": "NET_192.168.1.0_24",
      "type": "network",
      "value": "192.168.1.0/24",
      "description": "Corporate LAN"
    },
    {
      "name": "RANGE_10.1.1.200-250",
      "type": "range",
      "value": "10.1.1.200-10.1.1.250",
      "description": "Staging Servers"
    },
    {
      "name": "FQDN_update.microsoft.com",
      "type": "fqdn",
      "value": "update.microsoft.com",
      "description": "Windows Update"
    }
  ],
  "address_groups": [
    {
      "name": "GRP_Internal_Networks",
      "members": [
        "HOST_10.1.1.100",
        "NET_192.168.1.0_24"
      ],
      "description": "All internal corporate subnets"
    }
  ],
  "services": [
    {
      "name": "TCP_8080",
      "ports": [
        {
          "protocol": "tcp",
          "port": "8080"
        }
      ],
      "description": "Custom Web Proxy"
    },
    {
      "name": "UDP_5000",
      "ports": [
        {
          "protocol": "udp",
          "port": "5000"
        }
      ],
      "description": "Internal Streaming"
    }
  ],
  "service_groups": [
    {
      "name": "GRP_Web_Services",
      "members": [
        "HTTP",
        "HTTPS",
        "TCP_8080"
      ],
      "description": "Standard Web Group"
    }
  ],
  "schedules": [],
  "security_profile_groups": [
    {
      "name": "SPG_AV_default_IPS_default_WF_default",
      "antivirus": "default",
      "vulnerability": "default",
      "anti_spyware": "default",
      "url_filtering": "default",
      "file_blocking": "basic-file-blocking",
      "wildfire": "default",
      "ssl_decryption": "certificate-inspection",
      "description": "Auto-generated profile group for FortiGate UTM (AV_default, IPS_default, WF_default)"
    },
    {
      "name": "SPG_AV_default_IPS_protect_server",
      "antivirus": "default",
      "vulnerability": "protect_server",
      "anti_spyware": "default",
      "url_filtering": "default",
      "file_blocking": "basic-file-blocking",
      "wildfire": "default",
      "ssl_decryption": null,
      "description": "Auto-generated profile group for FortiGate UTM (AV_default, IPS_protect_server)"
    }
  ],
  "policies": [
    {
      "name": "Allow_Corporate_To_Internet",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "NET_192.168.1.0_24"
      ],
      "destination": [
        "all"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "LAN users internet outbound",
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_AV_default_IPS_default_WF_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": []
    },
    {
      "name": "Allow_Inbound_Web_VIP",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "all"
      ],
      "destination": [
        "VIP_Web_Server"
      ],
      "service": [
        "HTTPS"
      ],
      "action": "allow",
      "description": "Inbound traffic to web server",
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_AV_default_IPS_protect_server",
      "antivirus": "default",
      "ips_sensor": "protect_server",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": []
    },
    {
      "name": "Deny_Guest_To_DMZ",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "all"
      ],
      "destination": [
        "HOST_10.1.1.100"
      ],
      "service": [
        "ALL"
      ],
      "action": "deny",
      "description": "Block guest access to DMZ",
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": []
    }
  ],
  "nat_rules": [
    {
      "name": "POOL_NAT_OUT",
      "type": "source",
      "from_zone": [],
      "to_zone": [],
      "source": [],
      "destination": [],
      "service": "any",
      "translated_source": "203.0.113.10-203.0.113.20",
      "translated_destination": null,
      "description": "Outbound SNAT Pool"
    },
    {
      "name": "VIP_Web_Server",
      "type": "destination",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [],
      "source": [],
      "destination": [
        "203.0.113.5"
      ],
      "service": "any",
      "translated_source": null,
      "translated_destination": "10.1.1.100",
      "description": "Inbound HTTPS to DMZ Web"
    }
  ],
  "vpn_tunnels": [],
  "routes": [
    {
      "name": "route_1",
      "destination": "0.0.0.0 0.0.0.0",
      "interface": "port2",
      "next_hop": "203.0.113.1",
      "metric": 10,
      "description": "Default Gateway"
    }
  ],
  "audit_entries": [
    {
      "id": "1",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_AV_default_IPS_default_WF_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "2",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_AV_default_IPS_protect_server'.",
      "confidence": "full",
      "original_config": null
    }
  ]
}
```

</details>
