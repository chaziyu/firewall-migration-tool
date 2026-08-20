# 🛡️ Firewall Migration & Configuration Report

- **Hostname:** `deleumHQ`
- **Source Vendor:** Fortigate
- **Target Platform:** Palo Alto Networks (PAN-OS / Panorama)
- **Generated At:** 2026-08-20 13:02:16 UTC

## 1. Executive Summary & Migration Health

### Migration Health & Confidence

| Metric | Count | Status / Notes |
| :--- | :--- | :--- |
| **Total Processed Objects** | **2426** | Combined network, object, security, and policy entities |
| 🟢 **Full Confidence** | 2397 | Translated directly with high fidelity |
| 🟡 **Partial Confidence** | 29 | Semantic translation completed; review suggested |
| 🟠 **Manual Review Required** | 0 | Vendor-proprietary features requiring manual mapping |
| 🔴 **Unsupported** | 0 | Feature not supported in target architecture |

### Configuration Inventory Summary

| Inventory Category | Count | Description |
| :--- | :--- | :--- |
| **Security Zones** | 4 | Logical zone boundaries and interface mappings |
| **Network Interfaces** | 63 | Physical/VLAN interfaces and assigned IP subnets |
| **Address Objects** | 148 | Host, subnet, range, and FQDN definitions |
| **Address Groups** | 45 | Grouped address collections |
| **Service Objects** | 89 | Custom TCP/UDP/ICMP protocol definitions |
| **Service Groups** | 4 | Grouped port and service collections |
| **Internet Services (ISDB)** | 1774 | Built-in SaaS objects |
| **Threat Profile Groups** | 11 | Unified threat inspection bundles (AV, IPS, URL, etc.) |
| **Security Policies** | 224 | Firewall access control rules |
| **NAT Rules** | 6 | Source, destination, and static NAT translations |
| **IPsec VPN Tunnels** | 23 | Site-to-site IPsec tunnel endpoints |
| **Static Routes** | 39 | Routing table next-hop definitions |

### Out of Scope / Manually Required
The following features are intentionally out of scope for automated conversion and require manual design:
- SSL VPN and Portals
- FortiClient EMS Dynamic Endpoint Tagging
- Automation Stitches and Event Handlers
- FortiAnalyzer and Syslog integrations
- Admin Users and Profiles
- Certificates and Private Keys
- SAML / User Group mappings

## 2. ⚠️ Audit Trail & Action Items

> [!IMPORTANT]
> Review the following items before deploying the generated configuration to production.

| Category | Object ID | Confidence | Message / Remediation |
| :--- | :--- | :--- | :--- |
| Address | `EMS_ALL_UNKNOWN_CLIENTS` | 🟢 `FULL` | Dynamic/EMS Tag 'EMS_ALL_UNKNOWN_CLIENTS' automatically converted to Target Dynamic Address Group (DAG) with filter 'EMS_ALL_UNKNOWN_CLIENTS'. |
| Address | `EMS_ALL_UNMANAGEABLE_CLIENTS` | 🟢 `FULL` | Dynamic/EMS Tag 'EMS_ALL_UNMANAGEABLE_CLIENTS' automatically converted to Target Dynamic Address Group (DAG) with filter 'EMS_ALL_UNMANAGEABLE_CLIENTS'. |
| Address | `FCTEMS_ALL_FORTICLOUD_SERVERS` | 🟢 `FULL` | Dynamic/EMS Tag 'FCTEMS_ALL_FORTICLOUD_SERVERS' automatically converted to Target Dynamic Address Group (DAG) with filter 'FCTEMS_ALL_FORTICLOUD_SERVERS'. |
| Address | `EMS1_ZTNA_all_registered_clients` | 🟢 `FULL` | Dynamic/EMS Tag 'EMS1_ZTNA_all_registered_clients' automatically converted to Target Dynamic Address Group (DAG) with filter 'EMS1_ZTNA_all_registered_clients'. |
| Address | `MAC_EMS1_ZTNA_all_registered_clients` | 🟢 `FULL` | Dynamic/EMS Tag 'MAC_EMS1_ZTNA_all_registered_clients' automatically converted to Target Dynamic Address Group (DAG) with filter 'MAC_EMS1_ZTNA_all_registered_clients'. |
| Address | `EMS1_ZTNA_Deleum_ADUser` | 🟢 `FULL` | Dynamic/EMS Tag 'EMS1_ZTNA_Deleum_ADUser' automatically converted to Target Dynamic Address Group (DAG) with filter 'EMS1_ZTNA_Deleum_ADUser'. |
| Address | `MAC_EMS1_ZTNA_Deleum_ADUser` | 🟢 `FULL` | Dynamic/EMS Tag 'MAC_EMS1_ZTNA_Deleum_ADUser' automatically converted to Target Dynamic Address Group (DAG) with filter 'MAC_EMS1_ZTNA_Deleum_ADUser'. |
| Address | `EMS1_ZTNA_Deleum_AV` | 🟢 `FULL` | Dynamic/EMS Tag 'EMS1_ZTNA_Deleum_AV' automatically converted to Target Dynamic Address Group (DAG) with filter 'EMS1_ZTNA_Deleum_AV'. |
| Address | `MAC_EMS1_ZTNA_Deleum_AV` | 🟢 `FULL` | Dynamic/EMS Tag 'MAC_EMS1_ZTNA_Deleum_AV' automatically converted to Target Dynamic Address Group (DAG) with filter 'MAC_EMS1_ZTNA_Deleum_AV'. |
| Address | `EMS1_ZTNA_Deleum_CriticalVul` | 🟢 `FULL` | Dynamic/EMS Tag 'EMS1_ZTNA_Deleum_CriticalVul' automatically converted to Target Dynamic Address Group (DAG) with filter 'EMS1_ZTNA_Deleum_CriticalVul'. |
| Address | `MAC_EMS1_ZTNA_Deleum_CriticalVul` | 🟢 `FULL` | Dynamic/EMS Tag 'MAC_EMS1_ZTNA_Deleum_CriticalVul' automatically converted to Target Dynamic Address Group (DAG) with filter 'MAC_EMS1_ZTNA_Deleum_CriticalVul'. |
| Address | `EMS1_ZTNA_Not_Log_Domain_Name` | 🟢 `FULL` | Dynamic/EMS Tag 'EMS1_ZTNA_Not_Log_Domain_Name' automatically converted to Target Dynamic Address Group (DAG) with filter 'EMS1_ZTNA_Not_Log_Domain_Name'. |
| Address | `EMS1_ZTNA_Outdated_Windows` | 🟢 `FULL` | Dynamic/EMS Tag 'EMS1_ZTNA_Outdated_Windows' automatically converted to Target Dynamic Address Group (DAG) with filter 'EMS1_ZTNA_Outdated_Windows'. |
| Address | `MAC_EMS1_ZTNA_Outdated_Windows` | 🟢 `FULL` | Dynamic/EMS Tag 'MAC_EMS1_ZTNA_Outdated_Windows' automatically converted to Target Dynamic Address Group (DAG) with filter 'MAC_EMS1_ZTNA_Outdated_Windows'. |
| Address | `EMS1_ZTNA_Deleum_OSVersion` | 🟢 `FULL` | Dynamic/EMS Tag 'EMS1_ZTNA_Deleum_OSVersion' automatically converted to Target Dynamic Address Group (DAG) with filter 'EMS1_ZTNA_Deleum_OSVersion'. |
| Address | `MAC_EMS1_ZTNA_Deleum_OSVersion` | 🟢 `FULL` | Dynamic/EMS Tag 'MAC_EMS1_ZTNA_Deleum_OSVersion' automatically converted to Target Dynamic Address Group (DAG) with filter 'MAC_EMS1_ZTNA_Deleum_OSVersion'. |
| Address | `EMS1_ZTNA_Not_Deleum` | 🟢 `FULL` | Dynamic/EMS Tag 'EMS1_ZTNA_Not_Deleum' automatically converted to Target Dynamic Address Group (DAG) with filter 'EMS1_ZTNA_Not_Deleum'. |
| Address | `MAC_EMS1_ZTNA_Not_Deleum` | 🟢 `FULL` | Dynamic/EMS Tag 'MAC_EMS1_ZTNA_Not_Deleum' automatically converted to Target Dynamic Address Group (DAG) with filter 'MAC_EMS1_ZTNA_Not_Deleum'. |
| Address | `EMS1_ZTNA_Crit_Vul` | 🟢 `FULL` | Dynamic/EMS Tag 'EMS1_ZTNA_Crit_Vul' automatically converted to Target Dynamic Address Group (DAG) with filter 'EMS1_ZTNA_Crit_Vul'. |
| Address | `MAC_EMS1_ZTNA_Crit_Vul` | 🟢 `FULL` | Dynamic/EMS Tag 'MAC_EMS1_ZTNA_Crit_Vul' automatically converted to Target Dynamic Address Group (DAG) with filter 'MAC_EMS1_ZTNA_Crit_Vul'. |
| Address | `google-play` | 🟡 `PARTIAL` | Wildcard FQDN '*play.google.com' normalized to PAN-OS format '*.play.google.com'. Note: Apex domain matching behavior may differ. Review for semantics. |
| Address | `update.microsoft.com` | 🟡 `PARTIAL` | Wildcard FQDN '*update.microsoft.com' normalized to PAN-OS format '*.update.microsoft.com'. Note: Apex domain matching behavior may differ. Review for semantics. |
| Address | `swscan.apple.com` | 🟡 `PARTIAL` | Wildcard FQDN '*swscan.apple.com' normalized to PAN-OS format '*.swscan.apple.com'. Note: Apex domain matching behavior may differ. Review for semantics. |
| Address | `autoupdate.opera.com` | 🟡 `PARTIAL` | Wildcard FQDN '*autoupdate.opera.com' normalized to PAN-OS format '*.autoupdate.opera.com'. Note: Apex domain matching behavior may differ. Review for semantics. |
| Address | `google-drive` | 🟡 `PARTIAL` | Wildcard FQDN '*drive.google.com' normalized to PAN-OS format '*.drive.google.com'. Note: Apex domain matching behavior may differ. Review for semantics. |
| Address | `itunes` | 🟡 `PARTIAL` | Wildcard FQDN '*itunes.apple.com' normalized to PAN-OS format '*.itunes.apple.com'. Note: Apex domain matching behavior may differ. Review for semantics. |
| Policy | `3` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `252` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `253` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `258` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `263` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `255` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `259` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `264` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `257` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `260` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `256` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `254` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `261` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `9` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'Migrated_Profiles'. |
| Policy | `285` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `298` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `288` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `302` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `286` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `295` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `292` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `303` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `269` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `282` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `297` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `291` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `305` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `281` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `284` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `299` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `289` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `301` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `287` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `296` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `293` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `304` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `274` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `280` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `128` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `23` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio'. |
| Policy | `127` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `186` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_WF_deleum_webfilter_APP_deleum_application_control'. |
| Policy | `137` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_APP_deleum_application_control'. |
| Policy | `72` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_WF_deleum_webfilter_APP_deleum_application_control'. |
| Policy | `33` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio'. |
| Policy | `249` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_WF_wifi__deleum_webfilter_APP_deleum_application_control_fo'. |
| Policy | `39` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_WF_wifi__deleum_webfilter_APP_deleum_application_control'. |
| Policy | `147` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio'. |
| Policy | `148` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `152` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `150` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `154` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `160` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `174` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `155` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `157` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `156` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_WF_deleum_webfilter_APP_deleum_application_control'. |
| Policy | `172` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `161` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `180` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `162` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `188` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `272` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `276` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `190` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `178` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `164` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `171` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `216` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `224` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `226` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `225` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `227` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `205` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio'. |
| Policy | `230` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `231` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `176` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `242` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `203` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `245` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `131` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `241` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `240` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `195` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `196` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `246` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `167` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `236` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `169` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `133` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `165` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `184` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `182` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default_WF_deleum_webfilter_APP_deleum_application_cont'. |
| Policy | `82` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `211` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `168` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `210` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `134` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `112` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `238` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `212` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `232` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `244` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `239` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `233` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `135` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `25` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_AV_default_IPS_high_security_WF_deleum_webfilter_APP_deleum'. |
| Policy | `136` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `26` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `21` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_AV_default_IPS_high_security_WF_deleum_webfilter_APP_deleum'. |
| Policy | `22` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `138` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `119` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `34` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio'. |
| Policy | `18` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `124` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `149` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security_APP_deleum_application_control'. |
| Policy | `181` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `36` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security_APP_deleum_application_control'. |
| Policy | `61` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `283` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `294` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `290` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'Migrated_Profiles'. |
| Policy | `300` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'Migrated_Profiles'. |
| Policy | `62` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `78` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `123` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `76` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `79` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio'. |
| Policy | `198` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `197` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `106` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `146` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `243` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `143` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `217` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `132` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `116` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `237` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `218` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'. |
| Policy | `219` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_IPS_default'. |
| Policy | `266` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_AV_default_IPS_high_security_WF_deleum_webfilter_APP_deleum'. |
| Policy | `312` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_WF_deleum_webfilter_APP_deleum_application_control'. |
| Policy | `311` | 🟢 `FULL` | UTM profiles mapped to Security Profile Group 'SPG_AV_default_IPS_high_security_WF_deleum_webfilter_APP_deleum'. |
| VPN | `toMiriWH` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |
| VPN | `to_CKJ_unifi` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |
| VPN | `to_DOSSB_Miri` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |
| VPN | `toDOSSB_KSB` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |
| VPN | `toIT_fromHQ` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |
| VPN | `toCKJ_secondary` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |
| VPN | `to_TKY` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |
| VPN | `toTKY_secondary` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |
| VPN | `toKSB_secondary` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |
| VPN | `MiriWHsecondary` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |
| VPN | `Miri_secondary` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |
| VPN | `toKK_secondary` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |
| VPN | `to_KK` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |
| VPN | `toLabuan` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |
| VPN | `toLabuan_second` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |
| VPN | `toIT_secondary` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |
| VPN | `toMiri_DTS` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |
| VPN | `MiriDTS_second` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |
| VPN | `toBintulu1` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |
| VPN | `toBintulu2` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |
| VPN | `Bintulu1_second` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |
| VPN | `Bintulu2_second` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |
| VPN | `FortiClient` | 🟡 `PARTIAL` | IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway. |

## 3. 🌐 Network Architecture & Zones

### Interfaces & Zone Assignments

| Interface | Alias | Status | Type / VLAN Tag | Assigned Zone | IP / Subnet | Details / Description |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `ha` | - | 🟢 Up | Physical | `untrust` | - | - |
| `mgmt` | - | 🟢 Up | Physical | `trust` | `192.168.100.99/24` | - |
| `port1` | - | 🟢 Up | Physical | `untrust` | - | - |
| `port2` | `untrust 300MB` | 🟢 Up | Physical | `virtual-wan-link` | `172.16.1.100/24` | - |
| `port3` | - | 🟢 Up | Physical | `untrust` | - | - |
| `port4` | `Metro-E_Internet 20MB` | 🔴 Down | Physical | `virtual-wan-link` | `103.27.106.130/29` | - |
| `port5` | `FAZ200F_192.168.30.0/24` | 🟢 Up | Physical | `trust` | `192.168.30.1/24` | - |
| `port6` | `wifi_user_10.10.10.0/23` | 🟢 Up | Physical | `trust` | `10.10.10.1/23` | - |
| `port7` | - | 🟢 Up | Physical | `untrust` | - | - |
| `port8` | `Biometric_192.168.10.0/24` | 🟢 Up | Physical | `trust` | `192.168.10.254/24` | - |
| `port9` | `trust_192.168.0.0/23` | 🟢 Up | Physical | `trust` | `192.168.0.100/23` | - |
| `port10` | `server_192.168.42.0/24` | 🟢 Up | Physical | `dmz` | `192.168.42.30/24` | - |
| `port11` | `Pulse2_172.16.0.0/24` | 🟢 Up | Physical | `trust` | `172.16.0.1/24` | - |
| `port12` | - | 🟢 Up | Physical | `untrust` | - | - |
| `port13` | - | 🟢 Up | Physical | `untrust` | - | - |
| `port14` | - | 🟢 Up | Physical | `untrust` | - | - |
| `port15` | - | 🟢 Up | Physical | `untrust` | - | - |
| `port16` | - | 🟢 Up | Physical | `untrust` | - | - |
| `x1` | - | 🟢 Up | Physical | `untrust` | - | - |
| `x2` | - | 🟢 Up | Physical | `untrust` | - | - |
| `x3` | - | 🟢 Up | Physical | `untrust` | - | - |
| `x4` | - | 🟢 Up | Physical | `untrust` | - | - |
| `x5` | - | 🟢 Up | Physical | `untrust` | - | - |
| `x6` | - | 🟢 Up | Physical | `untrust` | - | - |
| `x7` | - | 🟢 Up | Physical | `untrust` | - | - |
| `x8` | - | 🟢 Up | Physical | `untrust` | - | - |
| `port17` | - | 🟢 Up | Physical | `untrust` | - | - |
| `port18` | - | 🟢 Up | Physical | `untrust` | - | - |
| `port19` | - | 🟢 Up | Physical | `untrust` | - | - |
| `port20` | - | 🟢 Up | Physical | `untrust` | - | - |
| `modem` | - | 🔴 Down | Physical | `untrust` | - | **PPPoE:** `None` |
| `naf.root` | - | 🟢 Up | Physical | `untrust` | - | - |
| `l2t.root` | - | 🟢 Up | Physical | `untrust` | - | - |
| `ssl.root` | `SSL VPN interface` | 🟢 Up | Physical | `untrust` | - | - |
| `unifi_port1` | - | 🟢 Up | VLAN 500 (Parent: `port1`) | `virtual-wan-link` | - | **PPPoE:** `deleum05@unifibiz` |
| `HQ_Vlan20` | `Labuan-10.10.2.1/24` | 🟢 Up | VLAN 20 (Parent: `port3`) | `trust` | `10.10.2.1/24` | - |
| `HQ_Vlan70` | `DPSB_TK_10.10.7.1/24` | 🟢 Up | VLAN 70 (Parent: `port3`) | `trust` | `10.10.7.1/24` | - |
| `toMiriWH` | - | 🟢 Up | Sub-interface (Parent: `unifi_port1`) | `untrust` | - | - |
| `to_CKJ_unifi` | - | 🟢 Up | Sub-interface (Parent: `unifi_port1`) | `untrust` | - | - |
| `to_DOSSB_Miri` | - | 🟢 Up | Sub-interface (Parent: `unifi_port1`) | `untrust` | - | - |
| `unifi2_Vlan` | - | 🟢 Up | VLAN 500 (Parent: `port12`) | `virtual-wan-link` | - | **PPPoE:** `delcom.oilfieldsb1@unifibiz` |
| `toDOSSB_KSB` | - | 🟢 Up | Sub-interface (Parent: `unifi_port1`) | `untrust` | - | - |
| `toIT_fromHQ` | - | 🔴 Down | Sub-interface (Parent: `unifi_port1`) | `untrust` | - | - |
| `toCKJ_secondary` | - | 🟢 Up | Sub-interface (Parent: `unifi2_Vlan`) | `untrust` | - | - |
| `unifi3` | - | 🟢 Up | VLAN 500 (Parent: `port7`) | `virtual-wan-link` | - | **PPPoE:** `delcom@unifibiz` |
| `to_TKY` | - | 🟢 Up | Sub-interface (Parent: `unifi_port1`) | `untrust` | - | - |
| `toTKY_secondary` | - | 🟢 Up | Sub-interface (Parent: `unifi2_Vlan`) | `untrust` | - | - |
| `toKSB_secondary` | - | 🟢 Up | Sub-interface (Parent: `unifi2_Vlan`) | `untrust` | - | - |
| `MiriWHsecondary` | - | 🟢 Up | Sub-interface (Parent: `unifi2_Vlan`) | `untrust` | - | - |
| `Miri_secondary` | - | 🟢 Up | Sub-interface (Parent: `unifi2_Vlan`) | `untrust` | - | - |
| `toKK_secondary` | - | 🟢 Up | Sub-interface (Parent: `unifi2_Vlan`) | `untrust` | - | - |
| `to_KK` | - | 🟢 Up | Sub-interface (Parent: `unifi_port1`) | `untrust` | - | - |
| `toLabuan` | - | 🟢 Up | Sub-interface (Parent: `unifi_port1`) | `untrust` | - | - |
| `toLabuan_second` | - | 🟢 Up | Sub-interface (Parent: `unifi2_Vlan`) | `untrust` | - | - |
| `toIT_secondary` | - | 🔴 Down | Sub-interface (Parent: `unifi2_Vlan`) | `untrust` | - | - |
| `maxis` | - | 🟢 Up | VLAN 500 (Parent: `port13`) | `untrust` | - | **PPPoE:** `95187@sme.maxis.com.my` |
| `toMiri_DTS` | - | 🟢 Up | Sub-interface (Parent: `unifi_port1`) | `untrust` | - | - |
| `MiriDTS_second` | - | 🟢 Up | Sub-interface (Parent: `unifi2_Vlan`) | `untrust` | - | - |
| `toBintulu1` | - | 🟢 Up | Sub-interface (Parent: `unifi_port1`) | `untrust` | - | - |
| `toBintulu2` | - | 🟢 Up | Sub-interface (Parent: `unifi_port1`) | `untrust` | - | - |
| `Bintulu1_second` | - | 🟢 Up | Sub-interface (Parent: `unifi2_Vlan`) | `untrust` | - | - |
| `Bintulu2_second` | - | 🟢 Up | Sub-interface (Parent: `unifi2_Vlan`) | `untrust` | - | - |
| `FortiClient` | - | 🟢 Up | Sub-interface (Parent: `unifi2_Vlan`) | `untrust` | - | - |

### Security Zones

| Zone Name | Bound Interfaces | Description |
| :--- | :--- | :--- |
| `untrust` | `ha`, `port1`, `port3`, `port7`, `port12`, `port13`, `port14`, `port15`, `port16`, `x1`, `x2`, `x3`, `x4`, `x5`, `x6`, `x7`, `x8`, `port17`, `port18`, `port19`, `port20`, `modem`, `naf.root`, `l2t.root`, `ssl.root`, `toMiriWH`, `to_CKJ_unifi`, `to_DOSSB_Miri`, `toDOSSB_KSB`, `toIT_fromHQ`, `toCKJ_secondary`, `to_TKY`, `toTKY_secondary`, `toKSB_secondary`, `MiriWHsecondary`, `Miri_secondary`, `toKK_secondary`, `to_KK`, `toLabuan`, `toLabuan_second`, `toIT_secondary`, `maxis`, `toMiri_DTS`, `MiriDTS_second`, `toBintulu1`, `toBintulu2`, `Bintulu1_second`, `Bintulu2_second`, `FortiClient` | - |
| `trust` | `mgmt`, `port5`, `port6`, `port8`, `port9`, `port11`, `HQ_Vlan20`, `HQ_Vlan70` | - |
| `virtual-wan-link` | `port2`, `port4`, `unifi_port1`, `unifi2_Vlan`, `unifi3` | - |
| `dmz` | `port10` | - |

### Static Routes

| Route Name | Destination | Next Hop | Outgoing Interface | Metric | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `route_2` | `192.168.2.0/24` | `10.10.2.254` | `HQ_Vlan20` | 5 | - |
| `route_4` | `0.0.0.0/0` | - | - | 1 | - |
| `route_6` | `192.168.7.0/24` | `10.10.7.254` | `HQ_Vlan70` | 7 | - |
| `route_9` | `10.10.77.0/24` | `10.10.7.254` | `HQ_Vlan70` | 7 | - |
| `route_23` | `192.168.8.0/24` | - | `toMiriWH` | 5 | - |
| `route_26` | `192.168.43.0/24` | - | `toIT_fromHQ` | 4 | - |
| `route_29` | `192.168.14.0/24` | - | `to_CKJ_unifi` | 6 | VPN: to_CKJ_unifi (Created by VPN wizard) |
| `route_30` | `0.0.0.0/0` | - | - | 254 | VPN: to_CKJ_unifi (Created by VPN wizard) |
| `route_31` | `10.10.22.0/24` | `10.10.2.254` | `HQ_Vlan20` | 5 | - |
| `route_32` | `192.168.5.0/24` | - | `to_DOSSB_Miri` | 6 | VPN: to_DOSSB_Miri (Created by VPN wizard) |
| `route_33` | `0.0.0.0/0` | - | - | 254 | VPN: to_DOSSB_Miri (Created by VPN wizard) |
| `route_22` | `0.0.0.0/0` | `103.27.106.129` | `port4` | 10 | - |
| `route_27` | `0.0.0.0/0` | - | `toDOSSB_KSB` | 6 | VPN: toDOSSB_KSB (Created by VPN wizard) |
| `route_34` | `0.0.0.0/0` | - | - | 254 | VPN: toDOSSB_KSB (Created by VPN wizard) |
| `route_35` | `192.168.4.0/24` | - | `toDOSSB_KSB` | 6 | - |
| `route_36` | `192.168.111.0/24` | - | `toIT_fromHQ` | 4 | - |
| `route_37` | `192.168.14.0/24` | - | `toCKJ_secondary` | 4 | - |
| `route_38` | `172.16.0.0/16` | `172.16.1.1` | `port2` | 6 | - |
| `route_40` | `192.168.13.0/24` | - | `to_KK` | 6 | - |
| `route_41` | `192.168.111.0/24` | `172.16.1.1` | `port2` | 5 | - |
| `route_25` | `192.168.7.0/24` | - | `to_TKY` | 6 | - |
| `route_28` | `192.168.7.0/24` | - | `toTKY_secondary` | 4 | - |
| `route_24` | `192.168.4.0/24` | - | `toKSB_secondary` | 4 | - |
| `route_39` | `192.168.8.0/24` | - | `MiriWHsecondary` | 4 | - |
| `route_42` | `192.168.5.0/24` | - | `Miri_secondary` | 4 | - |
| `route_43` | `192.168.13.0/24` | - | `toKK_secondary` | 4 | - |
| `route_44` | `192.168.2.0/24` | - | `toLabuan` | 6 | - |
| `route_45` | `192.168.2.0/24` | - | `toLabuan_second` | 4 | - |
| `route_46` | `10.10.22.0/24` | - | `toLabuan` | 6 | - |
| `route_47` | `10.10.22.0/24` | - | `toLabuan_second` | 4 | - |
| `route_48` | `192.168.111.0/24` | - | `toIT_secondary` | 6 | - |
| `route_49` | `0.0.0.0/0` | - | `unifi2_Vlan` | 10 | - |
| `route_50` | `0.0.0.0/0` | - | `unifi3` | 10 | - |
| `route_51` | `192.168.6.0/24` | - | `toMiri_DTS` | 6 | - |
| `route_52` | `192.168.6.0/24` | - | `MiriDTS_second` | 4 | - |
| `route_53` | `192.168.11.0/24` | - | `toBintulu1` | 6 | - |
| `route_54` | `192.168.3.0/24` | - | `toBintulu2` | 6 | - |
| `route_55` | `192.168.11.0/24` | - | `Bintulu1_second` | 4 | - |
| `route_56` | `192.168.3.0/24` | - | `Bintulu2_second` | 4 | - |

### IPsec VPN Tunnels

| Tunnel Name | Peer Gateway | Local Interface | IKE Version | PSK Configured | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `toMiriWH` | `219.93.103.225` | `unifi_port1` | V1 | ✅ Configured | - |
| `to_CKJ_unifi` | `175.138.111.73` | `unifi_port1` | V1 | ✅ Configured | VPN: to_CKJ_unifi (Created by VPN wizard) |
| `to_DOSSB_Miri` | `219.93.103.173` | `unifi_port1` | V1 | ✅ Configured | VPN: to_DOSSB_Miri (Created by VPN wizard) |
| `toDOSSB_KSB` | `210.186.145.17` | `unifi_port1` | V1 | ✅ Configured | - |
| `toIT_fromHQ` | `175.143.98.49` | `unifi_port1` | V1 | ✅ Configured | - |
| `toCKJ_secondary` | `175.138.111.73` | `unifi2_Vlan` | V1 | ✅ Configured | - |
| `to_TKY` | `175.144.112.161` | `unifi_port1` | V1 | ✅ Configured | - |
| `toTKY_secondary` | `175.144.112.161` | `unifi2_Vlan` | V1 | ✅ Configured | - |
| `toKSB_secondary` | `210.186.145.17` | `unifi2_Vlan` | V1 | ✅ Configured | - |
| `MiriWHsecondary` | `219.93.103.225` | `unifi2_Vlan` | V1 | ✅ Configured | - |
| `Miri_secondary` | `219.93.103.173` | `unifi2_Vlan` | V1 | ✅ Configured | - |
| `toKK_secondary` | `60.51.57.249` | `unifi2_Vlan` | V1 | ✅ Configured | - |
| `to_KK` | `60.51.57.249` | `unifi_port1` | V1 | ✅ Configured | - |
| `toLabuan` | `175.139.233.117` | `unifi_port1` | V1 | ✅ Configured | - |
| `toLabuan_second` | `175.139.233.117` | `unifi2_Vlan` | V1 | ✅ Configured | - |
| `toIT_secondary` | `175.143.98.49` | `unifi2_Vlan` | V1 | ✅ Configured | - |
| `toMiri_DTS` | `180.74.182.45` | `unifi_port1` | V1 | ✅ Configured | - |
| `MiriDTS_second` | `180.74.182.45` | `unifi2_Vlan` | V1 | ✅ Configured | - |
| `toBintulu1` | `210.187.179.169` | `unifi_port1` | V1 | ✅ Configured | - |
| `toBintulu2` | `180.74.181.209` | `unifi_port1` | V1 | ✅ Configured | - |
| `Bintulu1_second` | `210.187.179.169` | `unifi2_Vlan` | V1 | ✅ Configured | - |
| `Bintulu2_second` | `180.74.181.209` | `unifi2_Vlan` | V1 | ✅ Configured | - |
| `FortiClient` | `dynamic` | `unifi2_Vlan` | V2 | ✅ Configured | - |

## 4. 📦 Object Inventory

### Address Objects

| Address Name | Type | Flags | Value | Description |
| :--- | :--- | :--- | :--- | :--- |
| `SSLVPN_TUNNEL_ADDR1` | `range` | - | `10.212.134.200-10.212.134.230` | - |
| `Biometric-192.168.10.0/24` | `network` | - | `192.168.10.0/24` | - |
| `DPSB_CKJ_192.168.14.0/24` | `network` | - | `192.168.14.0/24` | - |
| `Miri_DTS_192.168.6.0/24` | `network` | - | `192.168.6.0/24` | - |
| `DPSB_Miri-192.168.9.0/24` | `network` | - | `192.168.9.0/24` | - |
| `DPSB_Miri_Leased_Line-10.10.9.0/24` | `network` | - | `10.10.9.0/24` | - |
| `DPSB_TK_new_192.168.7.0/24` | `network` | - | `192.168.7.0/24` | - |
| `DPSB_TK_wifi_10.10.77.0/24` | `network` | - | `10.10.77.0/24` | - |
| `DPSB_Teluk_Kalong_Leased_Line-10.10.7.0/24` | `network` | - | `10.10.7.0/24` | - |
| `DPSB_bintulu-192.168.11.0/24` | `network` | - | `192.168.11.0/24` | - |
| `DR-192.168.43.0/24` | `network` | - | `192.168.43.0/24` | - |
| `DRSSB_Bintulu-192.168.12.0/24` | `network` | - | `192.168.12.0/24` | - |
| `Bintulu2-192.168.3.0/24` | `network` | - | `192.168.3.0/24` | - |
| `DRSSB_Kajang_Leased_Line-10.10.3.0/24` | `network` | - | `10.10.3.0/24` | - |
| `HQ_Wifi_User-10.10.10.0/23` | `network` | - | `10.10.10.0/23` | - |
| `ICT_HQ_192.168.111.0/24` | `network` | - | `192.168.111.0/24` | - |
| `DOSSB_KSB-192.168.4.0/24` | `network` | - | `192.168.4.0/24` | - |
| `DOSSB_KK-192.168.13.0/24` | `network` | - | `192.168.13.0/24` | - |
| `DOSSB_Labuan-192.168.2.0/24` | `network` | - | `192.168.2.0/24` | - |
| `DOSSB_Labuan_Leased_Line-10.10.2.0/24` | `network` | - | `10.10.2.0/24` | - |
| `DOSSB_Miri-192.168.5.0/24` | `network` | - | `192.168.5.0/24` | - |
| `DOSSB_Miri_Leased_Line-10.10.5.0/24` | `network` | - | `10.10.5.0/24` | - |
| `Miri_WS-192.168.8.0/24` | `network` | - | `192.168.8.0/24` | - |
| `Peplink_175.138.64.170` | `network` | - | `175.138.64.170/32` | - |
| `Metro-E_Internet` | `network` | - | `103.27.106.128/29` | - |
| `SSL_VPN_HQ` | `network` | - | `10.10.100.0/24` | - |
| `Server-192.168.42.0/24` | `network` | - | `192.168.42.0/24` | - |
| `Trust-192.168.0.0/23` | `network` | - | `192.168.0.0/23` | - |
| `unifi` | `network` | - | `60.53.219.65/32` | - |
| `pulse secure_local-172.16.1.0/24` | `network` | - | `172.16.1.0/24` | - |
| `peplink WAN IP range` | `network` | - | `172.16.0.0/16` | - |
| `ariba` | `fqdn` | - | `ariba.com` | - |
| `SSL_VPN_HQ_new` | `network` | - | `10.10.100.0/24` | - |
| `FAZ200F_192.168.30.2` | `network` | - | `192.168.30.2/32` | - |
| `ps.compliance.protection.outlook.com` | `fqdn` | - | `ps.compliance.protection.outlook.com` | - |
| `microsoft1` | `network` | - | `40.92.0.0/15` | - |
| `microsoft2` | `network` | - | `40.107.0.0/16` | - |
| `microsoft3` | `network` | - | `52.100.0.0/14` | - |
| `microsoft4` | `network` | - | `52.238.78.88/32` | - |
| `microsoft5` | `network` | - | `104.47.0.0/17` | - |
| `jobsmalaysia.gov.my` | `fqdn` | - | `jobsmalaysia.gov.my` | - |
| `192.168.1.5/32` | `network` | - | `192.168.1.5/32` | - |
| `to_CKJ_unifi_local_subnet_1` | `network` | - | `192.168.42.0/24` | - |
| `to_CKJ_unifi_remote_subnet_1` | `network` | - | `192.168.14.0/24` | - |
| `DOSSB_Labuan_wifi_10.10.22.0/24` | `network` | - | `10.10.22.0/24` | - |
| `Labuan_172.16.2.0/24_temp` | `network` | - | `172.16.2.0/24` | - |
| `DPSB_TK 172.16.7.0/24_temp` | `network` | - | `172.16.7.0/24` | - |
| `trust_fixed_IP` | `range` | - | `192.168.0.1-192.168.0.100` | - |
| `trust_dhcp_reserved` | `range` | - | `192.168.1.249-192.168.1.250` | - |
| `ceac.state.gov` | `fqdn` | - | `ceac.state.gov` | - |
| `DBATT_192.168.10.7` | `network` | - | `192.168.10.7/32` | - |
| `India IP` | `geo` | - | `unknown` | - |
| `IPS_malaysia IP` | `geo` | - | `unknown` | - |
| `pulse_new_172.16.0.0/24` | `network` | - | `172.16.0.0/24` | - |
| `trust_dhcp` | `range` | - | `192.168.0.101-192.168.1.250` | - |
| `vpn.deleum.com` | `fqdn` | - | `vpn.deleum.com` | - |
| `secure.deleum.com` | `fqdn` | - | `secure.deleum.com` | - |
| `secure.deleum.com_publicIP` | `network` | - | `175.143.1.50/32` | - |
| `vpn.deleum.com_publicIP` | `network` | - | `60.53.219.70/32` | - |
| `vpnPulse_175.138.64.172` | `network` | - | `175.138.64.172/32` | - |
| `Malaysia IP` | `geo` | - | `unknown` | - |
| `deleum.com_public_IP` | `network` | - | `60.53.219.66/32` | - |
| `VC_pc_192.168.0.133` | `network` | - | `192.168.0.133/32` | - |
| `Owl_VC` | `network` | - | `10.10.10.58/32` | - |
| `AGM2022_1` | `fqdn` | - | `apc01.safelinks.protection.outlook.com` | - |
| `AGM2022_2` | `fqdn` | - | `us02web.zoom.us` | - |
| `AGM2022_3` | `fqdn` | - | `app-uat.tiih.com.my` | - |
| `PSA_172.16.0.100` | `network` | - | `172.16.0.100/32` | - |
| `login.microsoftonline.com` | `fqdn` | - | `login.microsoftonline.com` | - |
| `login.microsoft.com` | `fqdn` | - | `login.microsoft.com` | - |
| `login.windows.net` | `fqdn` | - | `login.windows.net` | - |
| `gmail.com` | `fqdn` | - | `gmail.com` | - |
| `wildcard.google.com` | `fqdn` | - | `*.google.com` | - |
| `wildcard.dropbox.com` | `fqdn` | - | `*.dropbox.com` | - |
| `metroE_test_192.168.0.80` | `network` | - | `192.168.0.80/32` | - |
| `ipad 1` | `mac` | - | `00:00:00:00:00:00` | Created for DHCP Reservation |
| `ipad 2` | `mac` | - | `00:00:00:00:00:00` | Created for DHCP Reservation |
| `TimeAtt-192.168.10.7` | `host` | - | `192.168.10.7/32` | - |
| `caterpillar` | `fqdn` | - | `securemail.cat.com` | - |
| `securemail.cat.com` | `fqdn` | - | `securemail.cat.com` | - |
| `test192.168.0.216` | `network` | - | `192.168.0.216/32` | - |
| `test192.168.0.140` | `network` | - | `192.168.0.140/32` | - |
| `test_192.168.0.147` | `network` | - | `192.168.0.147/32` | - |
| `s2b.standardchartered.com` | `fqdn` | - | `s2b.standardchartered.com` | - |
| `mrates.maybank.com.my` | `fqdn` | - | `mrates.maybank.com.my` | - |
| `hsbcnet.com` | `fqdn` | - | `hsbcnet.com` | - |
| `qtn.mac_00:00:00:00:00:00` | `mac` | - | `00:00:00:00:00:00` | Quarantine dummy MAC to keep the addrgrp |
| `efiling.rd.go.th` | `fqdn` | - | `efiling.rd.go.th` | - |
| `server_192.168.42.17` | `network` | - | `192.168.42.17/32` | - |
| `server_192.168.42.18` | `network` | - | `192.168.42.18/32` | - |
| `server_192.168.42.19` | `network` | - | `192.168.42.19/32` | - |
| `server_192.168.42.6` | `network` | - | `192.168.42.6/32` | - |
| `croudstrike1` | `fqdn` | - | `ts01-gyr-maverick.cloudsink.net` | - |
| `croudstrike2` | `fqdn` | - | `lfodown01-gyr-maverick.cloudsink.net` | - |
| `server_192.168.42.12` | `network` | - | `192.168.42.12/32` | - |
| `server_192.168.42.9` | `network` | - | `192.168.42.17/32` | - |
| `Bintulu1_192.168.11.0/24` | `network` | - | `192.168.11.0/24` | - |
| `KaiZenHR` | `fqdn` | - | `ess.deleum.com` | - |
| `DBFS_192.168.42.25` | `network` | - | `192.168.42.25/32` | - |
| `Deleum_AD` | `network` | - | `192.168.42.43/32` | - |
| `Test_IPSEC2_range` | `range` | - | `10.10.100.120-10.10.100.130` | VPN: Test_IPSEC2 (Created by VPN wizard) |
| `Test_IPSEC_2_range` | `range` | - | `10.10.100.120-10.10.100.130` | VPN: Test_IPSEC_2 (Created by VPN wizard) |
| `miniOrange_52.55.147.107` | `network` | - | `52.55.147.107/32` | - |
| `miniOrange_52.86.38.163` | `network` | - | `52.86.38.163/32` | - |
| `miniOrange_54.165.245.227` | `network` | - | `54.165.245.227/32` | - |
| `LDAPgateway` | `network` | - | `192.168.42.28/32` | - |
| `CCTVnvr_192.168.10.8` | `network` | - | `192.168.10.8/32` | - |
| `192.168.0.70` | `network` | - | `192.168.0.70/32` | - |
| `SangforCP_192.24.64.0/24` | `network` | - | `192.24.64.0/24` | - |
| `server_192.168.42.60` | `network` | - | `192.168.42.60/32` | - |
| `all_hosts` | `host` | Multicast | `224.0.0.1/32` | - |
| `all_routers` | `host` | Multicast | `224.0.0.2/32` | - |
| `Bonjour` | `host` | Multicast | `224.0.0.251/32` | - |
| `cdn-apple` | `wildcard` | - | `*.cdn-apple.com` | - |
| `mzstatic-apple` | `wildcard` | - | `*.mzstatic.com` | - |
| `google-play` | `wildcard` | - | `*.play.google.com` | - |
| `update.microsoft.com` | `wildcard` | - | `*.update.microsoft.com` | - |
| `swscan.apple.com` | `wildcard` | - | `*.swscan.apple.com` | - |
| `autoupdate.opera.com` | `wildcard` | - | `*.autoupdate.opera.com` | - |
| `adobe` | `wildcard` | - | `*.adobe.com` | - |
| `Adobe Login` | `wildcard` | - | `*.adobelogin.com` | - |
| `android` | `wildcard` | - | `*.android.com` | - |
| `apple` | `wildcard` | - | `*.apple.com` | - |
| `appstore` | `wildcard` | - | `*.appstore.com` | - |
| `auth.gfx.ms` | `wildcard` | - | `*.auth.gfx.ms` | - |
| `citrix` | `wildcard` | - | `*.citrixonline.com` | - |
| `dropbox.com` | `wildcard` | - | `*.dropbox.com` | - |
| `eease` | `wildcard` | - | `*.eease.com` | - |
| `firefox update server` | `wildcard` | - | `aus*.mozilla.org` | - |
| `fortinet` | `wildcard` | - | `*.fortinet.com` | - |
| `googleapis.com` | `wildcard` | - | `*.googleapis.com` | - |
| `google-drive` | `wildcard` | - | `*.drive.google.com` | - |
| `google-play2` | `wildcard` | - | `*.ggpht.com` | - |
| `google-play3` | `wildcard` | - | `*.books.google.com` | - |
| `Gotomeeting` | `wildcard` | - | `*.gotomeeting.com` | - |
| `icloud` | `wildcard` | - | `*.icloud.com` | - |
| `itunes` | `wildcard` | - | `*.itunes.apple.com` | - |
| `microsoft` | `wildcard` | - | `*.microsoft.com` | - |
| `skype` | `wildcard` | - | `*.messenger.live.com` | - |
| `softwareupdate.vmware.com` | `wildcard` | - | `*.softwareupdate.vmware.com` | - |
| `verisign` | `wildcard` | - | `*.verisign.com` | - |
| `Windows update 2` | `wildcard` | - | `*.windowsupdate.com` | - |
| `live.com` | `wildcard` | - | `*.live.com` | - |
| `deleumeform.com_60.53.219.68` | `host` | - | `60.53.219.68/32` | Auto-generated Address for VIP deleumeform.com_60.53.219.68 |
| `deleumintranet.com_60.53.219.67` | `host` | - | `60.53.219.67/32` | Auto-generated Address for VIP deleumintranet.com_60.53.219.67 |
| `eformproxy_60.53.219.66` | `host` | - | `60.53.219.66/32` | Auto-generated Address for VIP eformproxy_60.53.219.66 |
| `ess.deleum.com_60.53.219.69` | `host` | - | `60.53.219.69/32` | Auto-generated Address for VIP ess.deleum.com_60.53.219.69 |
| `secure.deleum.com_175.143.1.50` | `host` | - | `175.143.1.50/32` | Auto-generated Address for VIP secure.deleum.com_175.143.1.50 |

### Address Groups

| Group Name | Members | Description |
| :--- | :--- | :--- |
| `EMS_ALL_UNKNOWN_CLIENTS` | *(Dynamic DAG: `'EMS_ALL_UNKNOWN_CLIENTS'`)* | Migrated FortiClient EMS Dynamic Tag: EMS_ALL_UNKNOWN_CLIENTS |
| `EMS_ALL_UNMANAGEABLE_CLIENTS` | *(Dynamic DAG: `'EMS_ALL_UNMANAGEABLE_CLIENTS'`)* | Migrated FortiClient EMS Dynamic Tag: EMS_ALL_UNMANAGEABLE_CLIENTS |
| `FCTEMS_ALL_FORTICLOUD_SERVERS` | *(Dynamic DAG: `'FCTEMS_ALL_FORTICLOUD_SERVERS'`)* | Migrated FortiClient EMS Dynamic Tag: FCTEMS_ALL_FORTICLOUD_SERVERS |
| `EMS1_ZTNA_all_registered_clients` | *(Dynamic DAG: `'EMS1_ZTNA_all_registered_clients'`)* | Migrated FortiClient EMS Dynamic Tag: EMS1_ZTNA_all_registered_clients |
| `MAC_EMS1_ZTNA_all_registered_clients` | *(Dynamic DAG: `'MAC_EMS1_ZTNA_all_registered_clients'`)* | Migrated FortiClient EMS Dynamic Tag: MAC_EMS1_ZTNA_all_registered_clients |
| `EMS1_ZTNA_Deleum_ADUser` | *(Dynamic DAG: `'EMS1_ZTNA_Deleum_ADUser'`)* | Active Directory User |
| `MAC_EMS1_ZTNA_Deleum_ADUser` | *(Dynamic DAG: `'MAC_EMS1_ZTNA_Deleum_ADUser'`)* | Active Directory User |
| `EMS1_ZTNA_Deleum_AV` | *(Dynamic DAG: `'EMS1_ZTNA_Deleum_AV'`)* | Antivirus Installed |
| `MAC_EMS1_ZTNA_Deleum_AV` | *(Dynamic DAG: `'MAC_EMS1_ZTNA_Deleum_AV'`)* | Antivirus Installed |
| `EMS1_ZTNA_Deleum_CriticalVul` | *(Dynamic DAG: `'EMS1_ZTNA_Deleum_CriticalVul'`)* | Critical Vulnerability |
| `MAC_EMS1_ZTNA_Deleum_CriticalVul` | *(Dynamic DAG: `'MAC_EMS1_ZTNA_Deleum_CriticalVul'`)* | Critical Vulnerability |
| `EMS1_ZTNA_Not_Log_Domain_Name` | *(Dynamic DAG: `'EMS1_ZTNA_Not_Log_Domain_Name'`)* | Domain_Name |
| `EMS1_ZTNA_Outdated_Windows` | *(Dynamic DAG: `'EMS1_ZTNA_Outdated_Windows'`)* | Outdated Windows |
| `MAC_EMS1_ZTNA_Outdated_Windows` | *(Dynamic DAG: `'MAC_EMS1_ZTNA_Outdated_Windows'`)* | Outdated Windows |
| `EMS1_ZTNA_Deleum_OSVersion` | *(Dynamic DAG: `'EMS1_ZTNA_Deleum_OSVersion'`)* | Allowed OS |
| `MAC_EMS1_ZTNA_Deleum_OSVersion` | *(Dynamic DAG: `'MAC_EMS1_ZTNA_Deleum_OSVersion'`)* | Allowed OS |
| `EMS1_ZTNA_Not_Deleum` | *(Dynamic DAG: `'EMS1_ZTNA_Not_Deleum'`)* | Not Deleum Domain |
| `MAC_EMS1_ZTNA_Not_Deleum` | *(Dynamic DAG: `'MAC_EMS1_ZTNA_Not_Deleum'`)* | Not Deleum Domain |
| `EMS1_ZTNA_Crit_Vul` | *(Dynamic DAG: `'EMS1_ZTNA_Crit_Vul'`)* | Critical Vulnerability Presence |
| `MAC_EMS1_ZTNA_Crit_Vul` | *(Dynamic DAG: `'MAC_EMS1_ZTNA_Crit_Vul'`)* | Critical Vulnerability Presence |
| `Branches_LAN` | `DOSSB_KK-192.168.13.0/24`, `DOSSB_Labuan-192.168.2.0/24`, `DOSSB_Miri-192.168.5.0/24`, `DPSB_Miri-192.168.9.0/24`, `DPSB_TK_new_192.168.7.0/24`, `Miri_WS-192.168.8.0/24` | - |
| `branches_leased_line` | `DOSSB_Labuan_Leased_Line-10.10.2.0/24`, `DPSB_Teluk_Kalong_Leased_Line-10.10.7.0/24` | - |
| `protection.outlook.com` | `microsoft1`, `microsoft2`, `microsoft3`, `microsoft4`, `microsoft5` | - |
| `FAZ to_branch untrust group` | `DPSB_Miri-192.168.9.0/24` | - |
| `to_CKJ_unifi_local` | `to_CKJ_unifi_local_subnet_1` | VPN: to_CKJ_unifi (Created by VPN wizard) |
| `to_CKJ_unifi_remote` | `to_CKJ_unifi_remote_subnet_1` | VPN: to_CKJ_unifi (Created by VPN wizard) |
| `to_DOSSB_Miri_local` | `to_DOSSB_Miri_local_subnet_1` | VPN: to_DOSSB_Miri (Created by VPN wizard) |
| `to_DOSSB_Miri_remote` | `to_DOSSB_Miri_remote_subnet_1` | VPN: to_DOSSB_Miri (Created by VPN wizard) |
| `single_session` | `ariba`, `ceac.state.gov`, `jobsmalaysia.gov.my` | - |
| `toDOSSB_KSB_local` | `toDOSSB_KSB_local_subnet_1` | VPN: toDOSSB_KSB (Created by VPN wizard) |
| `toDOSSB_KSB_remote` | `toDOSSB_KSB_remote_subnet_1` | VPN: toDOSSB_KSB (Created by VPN wizard) |
| `Microsoft Office 365` | `login.microsoftonline.com`, `login.microsoft.com`, `login.windows.net` | - |
| `G Suite` | `gmail.com`, `wildcard.google.com` | - |
| `exclude QUIC` | `ipad 1`, `ipad 2` | - |
| `banking` | `s2b.standardchartered.com`, `hsbcnet.com`, `mrates.maybank.com.my` | - |
| `QuarantinedDevices` | `qtn.mac_00:00:00:00:00:00` | - |
| `Unifi2_route` | `securemail.cat.com`, `efiling.rd.go.th` | - |
| `server_no_internet` | `server_192.168.42.17`, `server_192.168.42.19`, `server_192.168.42.18`, `server_192.168.42.9`, `server_192.168.42.12` | - |
| `Deleum_VPN` | `EMS1_ZTNA_all_registered_clients`, `MAC_EMS1_ZTNA_all_registered_clients` | - |
| `Deleum_ICT` | `EMS1_ZTNA_Deleum_ADUser`, `EMS1_ZTNA_Deleum_AV`, `EMS1_ZTNA_Deleum_CriticalVul`, `MAC_EMS1_ZTNA_all_registered_clients`, `MAC_EMS1_ZTNA_Deleum_ADUser`, `MAC_EMS1_ZTNA_Deleum_AV`, `MAC_EMS1_ZTNA_Deleum_CriticalVul`, `EMS1_ZTNA_all_registered_clients` | - |
| `Deleum_IPSEC_split` | `all` | VPN: Deleum_IPSEC (Created by VPN wizard) |
| `Test_IPSEC2_split` | `all` | VPN: Test_IPSEC2 (Created by VPN wizard) |
| `FortiClient_split` | `all` | VPN: FortiClient (Created by VPN wizard) |
| `miniOrange_Cloud` | `miniOrange_52.55.147.107`, `miniOrange_52.86.38.163`, `miniOrange_54.165.245.227` | - |
| `SangforCP_split` | `Server-192.168.42.0/24` | VPN: SangforCP (Created by VPN wizard) |

### Service Objects

| Service Name | Protocol | Port(s) / ICMP | Description |
| :--- | :--- | :--- | :--- |
| `ALL` | `TCP` | `any` | - |
| `FTP` | `TCP` | `21` | - |
| `FTP_GET` | `TCP` | `21` | - |
| `FTP_PUT` | `TCP` | `21` | - |
| `DNS` | `TCP, UDP` | `53, 53` | - |
| `HTTP` | `TCP` | `80` | - |
| `HTTPS` | `TCP` | `443` | - |
| `IMAP` | `TCP` | `143` | - |
| `IMAPS` | `TCP` | `993` | - |
| `LDAP` | `TCP` | `389` | - |
| `DCE-RPC` | `TCP, UDP` | `135, 135` | - |
| `POP3` | `TCP` | `110` | - |
| `POP3S` | `TCP` | `995` | - |
| `SAMBA` | `TCP` | `139` | - |
| `SMTP` | `TCP` | `25` | - |
| `SMTPS` | `TCP` | `465` | - |
| `KERBEROS` | `TCP, TCP, UDP, UDP` | `88, 464, 88, 464` | - |
| `LDAP_UDP` | `UDP` | `389` | - |
| `SMB` | `TCP` | `445` | - |
| `ALL_TCP` | `TCP` | `1-65535` | - |
| `ALL_UDP` | `UDP` | `1-65535` | - |
| `ALL_ICMP` | `ICMP` | `any` | - |
| `ALL_ICMP6` | `ICMP` | `any` | - |
| `GRE` | `IP` | `47` | - |
| `AH` | `IP` | `51` | - |
| `ESP` | `IP` | `50` | - |
| `AOL` | `TCP` | `5190-5194` | - |
| `BGP` | `TCP` | `179` | - |
| `DHCP` | `UDP` | `67-68` | - |
| `FINGER` | `TCP` | `79` | - |
| `GOPHER` | `TCP` | `70` | - |
| `H323` | `TCP, TCP, UDP` | `1720, 1503, 1719` | - |
| `IKE` | `UDP, UDP` | `500, 4500` | - |
| `Internet-Locator-Service` | `TCP` | `389` | - |
| `IRC` | `TCP` | `6660-6669` | - |
| `L2TP` | `TCP, UDP` | `1701, 1701` | - |
| `NetMeeting` | `TCP` | `1720` | - |
| `NFS` | `TCP, TCP, UDP, UDP` | `111, 2049, 111, 2049` | - |
| `NNTP` | `TCP` | `119` | - |
| `NTP` | `TCP, UDP` | `123, 123` | - |
| `OSPF` | `IP` | `89` | - |
| `PC-Anywhere` | `TCP, UDP` | `5631, 5632` | - |
| `PING` | `ICMP` | `Type:8` | - |
| `TIMESTAMP` | `ICMP` | `Type:13` | - |
| `INFO_REQUEST` | `ICMP` | `Type:15` | - |
| `INFO_ADDRESS` | `ICMP` | `Type:17` | - |
| `ONC-RPC` | `TCP, UDP` | `111, 111` | - |
| `PPTP` | `TCP` | `1723` | - |
| `QUAKE` | `UDP, UDP, UDP, UDP` | `26000, 27000, 27910, 27960` | - |
| `RAUDIO` | `UDP` | `7070` | - |
| `REXEC` | `TCP` | `512` | - |
| `RIP` | `UDP` | `520` | - |
| `RLOGIN` | `TCP` | `513` | - |
| `RSH` | `TCP` | `514` | - |
| `SCCP` | `TCP` | `2000` | - |
| `SIP` | `TCP, UDP` | `5060, 5060` | - |
| `SIP-MSNmessenger` | `TCP` | `1863` | - |
| `SNMP` | `TCP, UDP` | `161-162, 161-162` | - |
| `SSH` | `TCP` | `22` | - |
| `SYSLOG` | `UDP` | `514` | - |
| `TALK` | `UDP` | `517-518` | - |
| `TELNET` | `TCP` | `23` | - |
| `TFTP` | `UDP` | `69` | - |
| `MGCP` | `UDP, UDP` | `2427, 2727` | - |
| `UUCP` | `TCP` | `540` | - |
| `VDOLIVE` | `TCP` | `7000-7010` | - |
| `WAIS` | `TCP` | `210` | - |
| `WINFRAME` | `TCP, TCP` | `1494, 2598` | - |
| `X-WINDOWS` | `TCP` | `6000-6063` | - |
| `PING6` | `ICMP` | `Type:128` | - |
| `MS-SQL` | `TCP, TCP` | `1433, 1434` | - |
| `MYSQL` | `TCP` | `3306` | - |
| `RDP` | `TCP` | `3389` | - |
| `VNC` | `TCP` | `5900` | - |
| `DHCP6` | `UDP, UDP` | `546, 547` | - |
| `SQUID` | `TCP` | `3128` | - |
| `SOCKS` | `TCP, UDP` | `1080, 1080` | - |
| `WINS` | `TCP, UDP` | `1512, 1512` | - |
| `RADIUS` | `UDP, UDP` | `1812, 1813` | - |
| `RADIUS-OLD` | `UDP, UDP` | `1645, 1646` | - |
| `CVSPSERVER` | `TCP, UDP` | `2401, 2401` | - |
| `AFS3` | `TCP, UDP` | `7000-7009, 7000-7009` | - |
| `TRACEROUTE` | `UDP` | `33434-33535` | - |
| `RTSP` | `TCP, TCP, TCP, UDP` | `554, 7070, 8554, 554` | - |
| `MMS` | `TCP, UDP` | `1755, 1024-5000` | - |
| `NONE` | `TCP` | `1-65535` | - |
| `webproxy` | `TCP` | `1-65535` | - |
| `port_8081` | `TCP` | `8081` | - |
| `LDAPS` | `TCP` | `636` | - |

### Service Groups

| Group Name | Members | Description |
| :--- | :--- | :--- |
| `Email Access` | `DNS`, `IMAP`, `IMAPS`, `POP3`, `POP3S`, `SMTP`, `SMTPS` | - |
| `Web Access` | `DNS`, `HTTP`, `HTTPS` | - |
| `Windows AD` | `DCE-RPC`, `DNS`, `KERBEROS`, `LDAP`, `LDAP_UDP`, `SAMBA`, `SMB` | - |
| `Exchange Server` | `DCE-RPC`, `DNS`, `HTTPS` | - |

### Internet Services (ISDB)

| Service Name | Description |
| :--- | :--- |
| `Google-Other` | - |
| `Google-Web` | - |
| `Google-ICMP` | - |
| `Google-DNS` | - |
| `Google-Outbound_Email` | - |
| `Google-SSH` | - |
| `Google-FTP` | - |
| `Google-NTP` | - |
| `Google-Inbound_Email` | - |
| `Google-LDAP` | - |
| `Google-NetBIOS.Session.Service` | - |
| `Google-RTMP` | - |
| `Google-NetBIOS.Name.Service` | - |
| `Google-Google.Cloud` | - |
| `Google-Google.Bot` | - |
| `Google-Gmail` | - |
| `Meta-Other` | - |
| `Meta-Web` | - |
| `Meta-ICMP` | - |
| `Meta-DNS` | - |
| `Meta-Outbound_Email` | - |
| `Meta-SSH` | - |
| `Meta-FTP` | - |
| `Meta-NTP` | - |
| `Meta-Inbound_Email` | - |
| `Meta-LDAP` | - |
| `Meta-NetBIOS.Session.Service` | - |
| `Meta-RTMP` | - |
| `Meta-NetBIOS.Name.Service` | - |
| `Meta-Whatsapp` | - |
| `Meta-Instagram` | - |
| `Apple-Other` | - |
| `Apple-Web` | - |
| `Apple-ICMP` | - |
| `Apple-DNS` | - |
| `Apple-Outbound_Email` | - |
| `Apple-SSH` | - |
| `Apple-FTP` | - |
| `Apple-NTP` | - |
| `Apple-Inbound_Email` | - |
| `Apple-LDAP` | - |
| `Apple-NetBIOS.Session.Service` | - |
| `Apple-RTMP` | - |
| `Apple-NetBIOS.Name.Service` | - |
| `Apple-App.Store` | - |
| `Apple-APNs` | - |
| `Yahoo-Other` | - |
| `Yahoo-Web` | - |
| `Yahoo-ICMP` | - |
| `Yahoo-DNS` | - |
| `Yahoo-Outbound_Email` | - |
| `Yahoo-SSH` | - |
| `Yahoo-FTP` | - |
| `Yahoo-NTP` | - |
| `Yahoo-Inbound_Email` | - |
| `Yahoo-LDAP` | - |
| `Yahoo-NetBIOS.Session.Service` | - |
| `Yahoo-RTMP` | - |
| `Yahoo-NetBIOS.Name.Service` | - |
| `Microsoft-Other` | - |
| `Microsoft-Web` | - |
| `Microsoft-ICMP` | - |
| `Microsoft-DNS` | - |
| `Microsoft-Outbound_Email` | - |
| `Microsoft-SSH` | - |
| `Microsoft-FTP` | - |
| `Microsoft-NTP` | - |
| `Microsoft-Inbound_Email` | - |
| `Microsoft-LDAP` | - |
| `Microsoft-NetBIOS.Session.Service` | - |
| `Microsoft-RTMP` | - |
| `Microsoft-NetBIOS.Name.Service` | - |
| `Microsoft-Skype_Teams` | - |
| `Microsoft-Office365` | - |
| `Microsoft-Azure` | - |
| `Microsoft-Bing.Bot` | - |
| `Microsoft-Outlook` | - |
| `Microsoft-Microsoft.Update` | - |
| `Microsoft-Dynamics` | - |
| `Microsoft-WNS` | - |
| `Microsoft-Office365.Published` | - |
| `Amazon-Other` | - |
| `Amazon-Web` | - |
| `Amazon-ICMP` | - |
| `Amazon-DNS` | - |
| `Amazon-Outbound_Email` | - |
| `Amazon-SSH` | - |
| `Amazon-FTP` | - |
| `Amazon-NTP` | - |
| `Amazon-Inbound_Email` | - |
| `Amazon-LDAP` | - |
| `Amazon-NetBIOS.Session.Service` | - |
| `Amazon-RTMP` | - |
| `Amazon-NetBIOS.Name.Service` | - |
| `Amazon-AWS` | - |
| `Amazon-AWS.WorkSpaces.Gateway` | - |
| `eBay-Other` | - |
| `eBay-Web` | - |
| `eBay-ICMP` | - |
| `eBay-DNS` | - |
| `eBay-Outbound_Email` | - |
| `eBay-SSH` | - |
| `eBay-FTP` | - |
| `eBay-NTP` | - |
| `eBay-Inbound_Email` | - |
| `eBay-LDAP` | - |
| `eBay-NetBIOS.Session.Service` | - |
| `eBay-RTMP` | - |
| `eBay-NetBIOS.Name.Service` | - |
| `PayPal-Other` | - |
| `PayPal-Web` | - |
| `PayPal-ICMP` | - |
| `PayPal-DNS` | - |
| `PayPal-Outbound_Email` | - |
| `PayPal-SSH` | - |
| `PayPal-FTP` | - |
| `PayPal-NTP` | - |
| `PayPal-Inbound_Email` | - |
| `PayPal-LDAP` | - |
| `PayPal-NetBIOS.Session.Service` | - |
| `PayPal-RTMP` | - |
| `PayPal-NetBIOS.Name.Service` | - |
| `Box-Other` | - |
| `Box-Web` | - |
| `Box-ICMP` | - |
| `Box-DNS` | - |
| `Box-Outbound_Email` | - |
| `Box-SSH` | - |
| `Box-FTP` | - |
| `Box-NTP` | - |
| `Box-Inbound_Email` | - |
| `Box-LDAP` | - |
| `Box-NetBIOS.Session.Service` | - |
| `Box-RTMP` | - |
| `Box-NetBIOS.Name.Service` | - |
| `Salesforce-Other` | - |
| `Salesforce-Web` | - |
| `Salesforce-ICMP` | - |
| `Salesforce-DNS` | - |
| `Salesforce-Outbound_Email` | - |
| `Salesforce-SSH` | - |
| `Salesforce-FTP` | - |
| `Salesforce-NTP` | - |
| `Salesforce-Inbound_Email` | - |
| `Salesforce-LDAP` | - |
| `Salesforce-NetBIOS.Session.Service` | - |
| `Salesforce-RTMP` | - |
| `Salesforce-NetBIOS.Name.Service` | - |
| `Salesforce-Email.Relay` | - |
| `Dropbox-Other` | - |
| `Dropbox-Web` | - |
| `Dropbox-ICMP` | - |
| `Dropbox-DNS` | - |
| `Dropbox-Outbound_Email` | - |
| `Dropbox-SSH` | - |
| `Dropbox-FTP` | - |
| `Dropbox-NTP` | - |
| `Dropbox-Inbound_Email` | - |
| `Dropbox-LDAP` | - |
| `Dropbox-NetBIOS.Session.Service` | - |
| `Dropbox-RTMP` | - |
| `Dropbox-NetBIOS.Name.Service` | - |
| `Netflix-Other` | - |
| `Netflix-Web` | - |
| `Netflix-ICMP` | - |
| `Netflix-DNS` | - |
| `Netflix-Outbound_Email` | - |
| `Netflix-SSH` | - |
| `Netflix-FTP` | - |
| `Netflix-NTP` | - |
| `Netflix-Inbound_Email` | - |
| `Netflix-LDAP` | - |
| `Netflix-NetBIOS.Session.Service` | - |
| `Netflix-RTMP` | - |
| `Netflix-NetBIOS.Name.Service` | - |
| `LinkedIn-Other` | - |
| `LinkedIn-Web` | - |
| `LinkedIn-ICMP` | - |
| `LinkedIn-DNS` | - |
| `LinkedIn-Outbound_Email` | - |
| `LinkedIn-SSH` | - |
| `LinkedIn-FTP` | - |
| `LinkedIn-NTP` | - |
| `LinkedIn-Inbound_Email` | - |
| `LinkedIn-LDAP` | - |
| `LinkedIn-NetBIOS.Session.Service` | - |
| `LinkedIn-RTMP` | - |
| `LinkedIn-NetBIOS.Name.Service` | - |
| `Adobe-Other` | - |
| `Adobe-Web` | - |
| `Adobe-ICMP` | - |
| `Adobe-DNS` | - |
| `Adobe-Outbound_Email` | - |
| `Adobe-SSH` | - |
| `Adobe-FTP` | - |
| `Adobe-NTP` | - |
| `Adobe-Inbound_Email` | - |
| `Adobe-LDAP` | - |
| `Adobe-NetBIOS.Session.Service` | - |
| `Adobe-RTMP` | - |
| `Adobe-NetBIOS.Name.Service` | - |
| `Adobe-Adobe.Experience.Cloud` | - |
| `Oracle-Other` | - |
| `Oracle-Web` | - |
| `Oracle-ICMP` | - |
| `Oracle-DNS` | - |
| `Oracle-Outbound_Email` | - |
| `Oracle-SSH` | - |
| `Oracle-FTP` | - |
| `Oracle-NTP` | - |
| `Oracle-Inbound_Email` | - |
| `Oracle-LDAP` | - |
| `Oracle-NetBIOS.Session.Service` | - |
| `Oracle-RTMP` | - |
| `Oracle-NetBIOS.Name.Service` | - |
| `Oracle-Oracle.Cloud` | - |
| `Hulu-Other` | - |
| `Hulu-Web` | - |
| `Hulu-ICMP` | - |
| `Hulu-DNS` | - |
| `Hulu-Outbound_Email` | - |
| `Hulu-SSH` | - |
| `Hulu-FTP` | - |
| `Hulu-NTP` | - |
| `Hulu-Inbound_Email` | - |
| `Hulu-LDAP` | - |
| `Hulu-NetBIOS.Session.Service` | - |
| `Hulu-RTMP` | - |
| `Hulu-NetBIOS.Name.Service` | - |
| `Pinterest-Other` | - |
| `Pinterest-Web` | - |
| `Pinterest-ICMP` | - |
| `Pinterest-DNS` | - |
| `Pinterest-Outbound_Email` | - |
| `Pinterest-SSH` | - |
| `Pinterest-FTP` | - |
| `Pinterest-NTP` | - |
| `Pinterest-Inbound_Email` | - |
| `Pinterest-LDAP` | - |
| `Pinterest-NetBIOS.Session.Service` | - |
| `Pinterest-RTMP` | - |
| `Pinterest-NetBIOS.Name.Service` | - |
| `LogMeIn-Other` | - |
| `LogMeIn-Web` | - |
| `LogMeIn-ICMP` | - |
| `LogMeIn-DNS` | - |
| `LogMeIn-Outbound_Email` | - |
| `LogMeIn-SSH` | - |
| `LogMeIn-FTP` | - |
| `LogMeIn-NTP` | - |
| `LogMeIn-Inbound_Email` | - |
| `LogMeIn-LDAP` | - |
| `LogMeIn-NetBIOS.Session.Service` | - |
| `LogMeIn-RTMP` | - |
| `LogMeIn-NetBIOS.Name.Service` | - |
| `LogMeIn-GoTo.Suite` | - |
| `Fortinet-Other` | - |
| `Fortinet-Web` | - |
| `Fortinet-ICMP` | - |
| `Fortinet-DNS` | - |
| `Fortinet-Outbound_Email` | - |
| `Fortinet-SSH` | - |
| `Fortinet-FTP` | - |
| `Fortinet-NTP` | - |
| `Fortinet-Inbound_Email` | - |
| `Fortinet-LDAP` | - |
| `Fortinet-NetBIOS.Session.Service` | - |
| `Fortinet-RTMP` | - |
| `Fortinet-NetBIOS.Name.Service` | - |
| `Fortinet-FortiGuard` | - |
| `Fortinet-FortiMail.Cloud` | - |
| `Fortinet-FortiCloud` | - |
| `Kaspersky-Other` | - |
| `Kaspersky-Web` | - |
| `Kaspersky-ICMP` | - |
| `Kaspersky-DNS` | - |
| `Kaspersky-Outbound_Email` | - |
| `Kaspersky-SSH` | - |
| `Kaspersky-FTP` | - |
| `Kaspersky-NTP` | - |
| `Kaspersky-Inbound_Email` | - |
| `Kaspersky-LDAP` | - |
| `Kaspersky-NetBIOS.Session.Service` | - |
| `Kaspersky-RTMP` | - |
| `Kaspersky-NetBIOS.Name.Service` | - |
| `McAfee-Other` | - |
| `McAfee-Web` | - |
| `McAfee-ICMP` | - |
| `McAfee-DNS` | - |
| `McAfee-Outbound_Email` | - |
| `McAfee-SSH` | - |
| `McAfee-FTP` | - |
| `McAfee-NTP` | - |
| `McAfee-Inbound_Email` | - |
| `McAfee-LDAP` | - |
| `McAfee-NetBIOS.Session.Service` | - |
| `McAfee-RTMP` | - |
| `McAfee-NetBIOS.Name.Service` | - |
| `Symantec-Other` | - |
| `Symantec-Web` | - |
| `Symantec-ICMP` | - |
| `Symantec-DNS` | - |
| `Symantec-Outbound_Email` | - |
| `Symantec-SSH` | - |
| `Symantec-FTP` | - |
| `Symantec-NTP` | - |
| `Symantec-Inbound_Email` | - |
| `Symantec-LDAP` | - |
| `Symantec-NetBIOS.Session.Service` | - |
| `Symantec-RTMP` | - |
| `Symantec-NetBIOS.Name.Service` | - |
| `Symantec-Symantec.Cloud` | - |
| `VMware-Other` | - |
| `VMware-Web` | - |
| `VMware-ICMP` | - |
| `VMware-DNS` | - |
| `VMware-Outbound_Email` | - |
| `VMware-SSH` | - |
| `VMware-FTP` | - |
| `VMware-NTP` | - |
| `VMware-Inbound_Email` | - |
| `VMware-LDAP` | - |
| `VMware-NetBIOS.Session.Service` | - |
| `VMware-RTMP` | - |
| `VMware-NetBIOS.Name.Service` | - |
| `VMware-Workspace.ONE` | - |
| `AOL-Other` | - |
| `AOL-Web` | - |
| `AOL-ICMP` | - |
| `AOL-DNS` | - |
| `AOL-Outbound_Email` | - |
| `AOL-SSH` | - |
| `AOL-FTP` | - |
| `AOL-NTP` | - |
| `AOL-Inbound_Email` | - |
| `AOL-LDAP` | - |
| `AOL-NetBIOS.Session.Service` | - |
| `AOL-RTMP` | - |
| `AOL-NetBIOS.Name.Service` | - |
| `RealNetworks-Other` | - |
| `RealNetworks-Web` | - |
| `RealNetworks-ICMP` | - |
| `RealNetworks-DNS` | - |
| `RealNetworks-Outbound_Email` | - |
| `RealNetworks-SSH` | - |
| `RealNetworks-FTP` | - |
| `RealNetworks-NTP` | - |
| `RealNetworks-Inbound_Email` | - |
| `RealNetworks-LDAP` | - |
| `RealNetworks-NetBIOS.Session.Service` | - |
| `RealNetworks-RTMP` | - |
| `RealNetworks-NetBIOS.Name.Service` | - |
| `Zoho-Other` | - |
| `Zoho-Web` | - |
| `Zoho-ICMP` | - |
| `Zoho-DNS` | - |
| `Zoho-Outbound_Email` | - |
| `Zoho-SSH` | - |
| `Zoho-FTP` | - |
| `Zoho-NTP` | - |
| `Zoho-Inbound_Email` | - |
| `Zoho-LDAP` | - |
| `Zoho-NetBIOS.Session.Service` | - |
| `Zoho-RTMP` | - |
| `Zoho-NetBIOS.Name.Service` | - |
| `Mozilla-Other` | - |
| `Mozilla-Web` | - |
| `Mozilla-ICMP` | - |
| `Mozilla-DNS` | - |
| `Mozilla-Outbound_Email` | - |
| `Mozilla-SSH` | - |
| `Mozilla-FTP` | - |
| `Mozilla-NTP` | - |
| `Mozilla-Inbound_Email` | - |
| `Mozilla-LDAP` | - |
| `Mozilla-NetBIOS.Session.Service` | - |
| `Mozilla-RTMP` | - |
| `Mozilla-NetBIOS.Name.Service` | - |
| `TeamViewer-Other` | - |
| `TeamViewer-Web` | - |
| `TeamViewer-ICMP` | - |
| `TeamViewer-DNS` | - |
| `TeamViewer-Outbound_Email` | - |
| `TeamViewer-SSH` | - |
| `TeamViewer-FTP` | - |
| `TeamViewer-NTP` | - |
| `TeamViewer-Inbound_Email` | - |
| `TeamViewer-LDAP` | - |
| `TeamViewer-NetBIOS.Session.Service` | - |
| `TeamViewer-RTMP` | - |
| `TeamViewer-NetBIOS.Name.Service` | - |
| `TeamViewer-TeamViewer` | - |
| `HP-Other` | - |
| `HP-Web` | - |
| `HP-ICMP` | - |
| `HP-DNS` | - |
| `HP-Outbound_Email` | - |
| `HP-SSH` | - |
| `HP-FTP` | - |
| `HP-NTP` | - |
| `HP-Inbound_Email` | - |
| `HP-LDAP` | - |
| `HP-NetBIOS.Session.Service` | - |
| `HP-RTMP` | - |
| `HP-NetBIOS.Name.Service` | - |
| `HP-Aruba` | - |
| `Cisco-Other` | - |
| `Cisco-Web` | - |
| `Cisco-ICMP` | - |
| `Cisco-DNS` | - |
| `Cisco-Outbound_Email` | - |
| `Cisco-SSH` | - |
| `Cisco-FTP` | - |
| `Cisco-NTP` | - |
| `Cisco-Inbound_Email` | - |
| `Cisco-LDAP` | - |
| `Cisco-NetBIOS.Session.Service` | - |
| `Cisco-RTMP` | - |
| `Cisco-NetBIOS.Name.Service` | - |
| `Cisco-Webex` | - |
| `Cisco-Meraki.Cloud` | - |
| `Cisco-Duo.Security` | - |
| `Cisco-AppDynamic` | - |
| `IBM-Other` | - |
| `IBM-Web` | - |
| `IBM-ICMP` | - |
| `IBM-DNS` | - |
| `IBM-Outbound_Email` | - |
| `IBM-SSH` | - |
| `IBM-FTP` | - |
| `IBM-NTP` | - |
| `IBM-Inbound_Email` | - |
| `IBM-LDAP` | - |
| `IBM-NetBIOS.Session.Service` | - |
| `IBM-RTMP` | - |
| `IBM-NetBIOS.Name.Service` | - |
| `IBM-IBM.Cloud` | - |
| `Citrix-Other` | - |
| `Citrix-Web` | - |
| `Citrix-ICMP` | - |
| `Citrix-DNS` | - |
| `Citrix-Outbound_Email` | - |
| `Citrix-SSH` | - |
| `Citrix-FTP` | - |
| `Citrix-NTP` | - |
| `Citrix-Inbound_Email` | - |
| `Citrix-LDAP` | - |
| `Citrix-NetBIOS.Session.Service` | - |
| `Citrix-RTMP` | - |
| `Citrix-NetBIOS.Name.Service` | - |
| `Twitter-Other` | - |
| `Twitter-Web` | - |
| `Twitter-ICMP` | - |
| `Twitter-DNS` | - |
| `Twitter-Outbound_Email` | - |
| `Twitter-SSH` | - |
| `Twitter-FTP` | - |
| `Twitter-NTP` | - |
| `Twitter-Inbound_Email` | - |
| `Twitter-LDAP` | - |
| `Twitter-NetBIOS.Session.Service` | - |
| `Twitter-RTMP` | - |
| `Twitter-NetBIOS.Name.Service` | - |
| `Dell-Other` | - |
| `Dell-Web` | - |
| `Dell-ICMP` | - |
| `Dell-DNS` | - |
| `Dell-Outbound_Email` | - |
| `Dell-SSH` | - |
| `Dell-FTP` | - |
| `Dell-NTP` | - |
| `Dell-Inbound_Email` | - |
| `Dell-LDAP` | - |
| `Dell-NetBIOS.Session.Service` | - |
| `Dell-RTMP` | - |
| `Dell-NetBIOS.Name.Service` | - |
| `Vimeo-Other` | - |
| `Vimeo-Web` | - |
| `Vimeo-ICMP` | - |
| `Vimeo-DNS` | - |
| `Vimeo-Outbound_Email` | - |
| `Vimeo-SSH` | - |
| `Vimeo-FTP` | - |
| `Vimeo-NTP` | - |
| `Vimeo-Inbound_Email` | - |
| `Vimeo-LDAP` | - |
| `Vimeo-NetBIOS.Session.Service` | - |
| `Vimeo-RTMP` | - |
| `Vimeo-NetBIOS.Name.Service` | - |
| `Redhat-Other` | - |
| `Redhat-Web` | - |
| `Redhat-ICMP` | - |
| `Redhat-DNS` | - |
| `Redhat-Outbound_Email` | - |
| `Redhat-SSH` | - |
| `Redhat-FTP` | - |
| `Redhat-NTP` | - |
| `Redhat-Inbound_Email` | - |
| `Redhat-LDAP` | - |
| `Redhat-NetBIOS.Session.Service` | - |
| `Redhat-RTMP` | - |
| `Redhat-NetBIOS.Name.Service` | - |
| `VK-Other` | - |
| `VK-Web` | - |
| `VK-ICMP` | - |
| `VK-DNS` | - |
| `VK-Outbound_Email` | - |
| `VK-SSH` | - |
| `VK-FTP` | - |
| `VK-NTP` | - |
| `VK-Inbound_Email` | - |
| `VK-LDAP` | - |
| `VK-NetBIOS.Session.Service` | - |
| `VK-RTMP` | - |
| `VK-NetBIOS.Name.Service` | - |
| `TrendMicro-Other` | - |
| `TrendMicro-Web` | - |
| `TrendMicro-ICMP` | - |
| `TrendMicro-DNS` | - |
| `TrendMicro-Outbound_Email` | - |
| `TrendMicro-SSH` | - |
| `TrendMicro-FTP` | - |
| `TrendMicro-NTP` | - |
| `TrendMicro-Inbound_Email` | - |
| `TrendMicro-LDAP` | - |
| `TrendMicro-NetBIOS.Session.Service` | - |
| `TrendMicro-RTMP` | - |
| `TrendMicro-NetBIOS.Name.Service` | - |
| `Tencent-Other` | - |
| `Tencent-Web` | - |
| `Tencent-ICMP` | - |
| `Tencent-DNS` | - |
| `Tencent-Outbound_Email` | - |
| `Tencent-SSH` | - |
| `Tencent-FTP` | - |
| `Tencent-NTP` | - |
| `Tencent-Inbound_Email` | - |
| `Tencent-LDAP` | - |
| `Tencent-NetBIOS.Session.Service` | - |
| `Tencent-RTMP` | - |
| `Tencent-NetBIOS.Name.Service` | - |
| `Ask-Other` | - |
| `Ask-Web` | - |
| `Ask-ICMP` | - |
| `Ask-DNS` | - |
| `Ask-Outbound_Email` | - |
| `Ask-SSH` | - |
| `Ask-FTP` | - |
| `Ask-NTP` | - |
| `Ask-Inbound_Email` | - |
| `Ask-LDAP` | - |
| `Ask-NetBIOS.Session.Service` | - |
| `Ask-RTMP` | - |
| `Ask-NetBIOS.Name.Service` | - |
| `CNN-Other` | - |
| `CNN-Web` | - |
| `CNN-ICMP` | - |
| `CNN-DNS` | - |
| `CNN-Outbound_Email` | - |
| `CNN-SSH` | - |
| `CNN-FTP` | - |
| `CNN-NTP` | - |
| `CNN-Inbound_Email` | - |
| `CNN-LDAP` | - |
| `CNN-NetBIOS.Session.Service` | - |
| `CNN-RTMP` | - |
| `CNN-NetBIOS.Name.Service` | - |
| `Myspace-Other` | - |
| `Myspace-Web` | - |
| `Myspace-ICMP` | - |
| `Myspace-DNS` | - |
| `Myspace-Outbound_Email` | - |
| `Myspace-SSH` | - |
| `Myspace-FTP` | - |
| `Myspace-NTP` | - |
| `Myspace-Inbound_Email` | - |
| `Myspace-LDAP` | - |
| `Myspace-NetBIOS.Session.Service` | - |
| `Myspace-RTMP` | - |
| `Myspace-NetBIOS.Name.Service` | - |
| `Tor-Relay.Node` | - |
| `Tor-Exit.Node` | - |
| `Baidu-Other` | - |
| `Baidu-Web` | - |
| `Baidu-ICMP` | - |
| `Baidu-DNS` | - |
| `Baidu-Outbound_Email` | - |
| `Baidu-SSH` | - |
| `Baidu-FTP` | - |
| `Baidu-NTP` | - |
| `Baidu-Inbound_Email` | - |
| `Baidu-LDAP` | - |
| `Baidu-NetBIOS.Session.Service` | - |
| `Baidu-RTMP` | - |
| `Baidu-NetBIOS.Name.Service` | - |
| `ntp.org-Other` | - |
| `ntp.org-Web` | - |
| `ntp.org-ICMP` | - |
| `ntp.org-DNS` | - |
| `ntp.org-Outbound_Email` | - |
| `ntp.org-SSH` | - |
| `ntp.org-FTP` | - |
| `ntp.org-NTP` | - |
| `ntp.org-Inbound_Email` | - |
| `ntp.org-LDAP` | - |
| `ntp.org-NetBIOS.Session.Service` | - |
| `ntp.org-RTMP` | - |
| `ntp.org-NetBIOS.Name.Service` | - |
| `Proxy-Proxy.Server` | - |
| `Botnet-C&C.Server` | - |
| `Spam-Spamming.Server` | - |
| `Phishing-Phishing.Server` | - |
| `Zendesk-Zendesk.Suite` | - |
| `DocuSign-Other` | - |
| `DocuSign-Web` | - |
| `DocuSign-ICMP` | - |
| `DocuSign-DNS` | - |
| `DocuSign-Outbound_Email` | - |
| `DocuSign-SSH` | - |
| `DocuSign-FTP` | - |
| `DocuSign-NTP` | - |
| `DocuSign-Inbound_Email` | - |
| `DocuSign-LDAP` | - |
| `DocuSign-NetBIOS.Session.Service` | - |
| `DocuSign-RTMP` | - |
| `DocuSign-NetBIOS.Name.Service` | - |
| `ServiceNow-Other` | - |
| `ServiceNow-Web` | - |
| `ServiceNow-ICMP` | - |
| `ServiceNow-DNS` | - |
| `ServiceNow-Outbound_Email` | - |
| `ServiceNow-SSH` | - |
| `ServiceNow-FTP` | - |
| `ServiceNow-NTP` | - |
| `ServiceNow-Inbound_Email` | - |
| `ServiceNow-LDAP` | - |
| `ServiceNow-NetBIOS.Session.Service` | - |
| `ServiceNow-RTMP` | - |
| `ServiceNow-NetBIOS.Name.Service` | - |
| `GitHub-GitHub` | - |
| `Workday-Other` | - |
| `Workday-Web` | - |
| `Workday-ICMP` | - |
| `Workday-DNS` | - |
| `Workday-Outbound_Email` | - |
| `Workday-SSH` | - |
| `Workday-FTP` | - |
| `Workday-NTP` | - |
| `Workday-Inbound_Email` | - |
| `Workday-LDAP` | - |
| `Workday-NetBIOS.Session.Service` | - |
| `Workday-RTMP` | - |
| `Workday-NetBIOS.Name.Service` | - |
| `HubSpot-Other` | - |
| `HubSpot-Web` | - |
| `HubSpot-ICMP` | - |
| `HubSpot-DNS` | - |
| `HubSpot-Outbound_Email` | - |
| `HubSpot-SSH` | - |
| `HubSpot-FTP` | - |
| `HubSpot-NTP` | - |
| `HubSpot-Inbound_Email` | - |
| `HubSpot-LDAP` | - |
| `HubSpot-NetBIOS.Session.Service` | - |
| `HubSpot-RTMP` | - |
| `HubSpot-NetBIOS.Name.Service` | - |
| `Twilio-Other` | - |
| `Twilio-Web` | - |
| `Twilio-ICMP` | - |
| `Twilio-DNS` | - |
| `Twilio-Outbound_Email` | - |
| `Twilio-SSH` | - |
| `Twilio-FTP` | - |
| `Twilio-NTP` | - |
| `Twilio-Inbound_Email` | - |
| `Twilio-LDAP` | - |
| `Twilio-NetBIOS.Session.Service` | - |
| `Twilio-RTMP` | - |
| `Twilio-NetBIOS.Name.Service` | - |
| `Twilio-Elastic.SIP.Trunking` | - |
| `Coupa-Other` | - |
| `Coupa-Web` | - |
| `Coupa-ICMP` | - |
| `Coupa-DNS` | - |
| `Coupa-Outbound_Email` | - |
| `Coupa-SSH` | - |
| `Coupa-FTP` | - |
| `Coupa-NTP` | - |
| `Coupa-Inbound_Email` | - |
| `Coupa-LDAP` | - |
| `Coupa-NetBIOS.Session.Service` | - |
| `Coupa-RTMP` | - |
| `Coupa-NetBIOS.Name.Service` | - |
| `Atlassian-Other` | - |
| `Atlassian-Web` | - |
| `Atlassian-ICMP` | - |
| `Atlassian-DNS` | - |
| `Atlassian-Outbound_Email` | - |
| `Atlassian-SSH` | - |
| `Atlassian-FTP` | - |
| `Atlassian-NTP` | - |
| `Atlassian-Inbound_Email` | - |
| `Atlassian-LDAP` | - |
| `Atlassian-NetBIOS.Session.Service` | - |
| `Atlassian-RTMP` | - |
| `Atlassian-NetBIOS.Name.Service` | - |
| `Xero-Other` | - |
| `Xero-Web` | - |
| `Xero-ICMP` | - |
| `Xero-DNS` | - |
| `Xero-Outbound_Email` | - |
| `Xero-SSH` | - |
| `Xero-FTP` | - |
| `Xero-NTP` | - |
| `Xero-Inbound_Email` | - |
| `Xero-LDAP` | - |
| `Xero-NetBIOS.Session.Service` | - |
| `Xero-RTMP` | - |
| `Xero-NetBIOS.Name.Service` | - |
| `Zuora-Other` | - |
| `Zuora-Web` | - |
| `Zuora-ICMP` | - |
| `Zuora-DNS` | - |
| `Zuora-Outbound_Email` | - |
| `Zuora-SSH` | - |
| `Zuora-FTP` | - |
| `Zuora-NTP` | - |
| `Zuora-Inbound_Email` | - |
| `Zuora-LDAP` | - |
| `Zuora-NetBIOS.Session.Service` | - |
| `Zuora-RTMP` | - |
| `Zuora-NetBIOS.Name.Service` | - |
| `AdRoll-Other` | - |
| `AdRoll-Web` | - |
| `AdRoll-ICMP` | - |
| `AdRoll-DNS` | - |
| `AdRoll-Outbound_Email` | - |
| `AdRoll-SSH` | - |
| `AdRoll-FTP` | - |
| `AdRoll-NTP` | - |
| `AdRoll-Inbound_Email` | - |
| `AdRoll-LDAP` | - |
| `AdRoll-NetBIOS.Session.Service` | - |
| `AdRoll-RTMP` | - |
| `AdRoll-NetBIOS.Name.Service` | - |
| `Xactly-Other` | - |
| `Xactly-Web` | - |
| `Xactly-ICMP` | - |
| `Xactly-DNS` | - |
| `Xactly-Outbound_Email` | - |
| `Xactly-SSH` | - |
| `Xactly-FTP` | - |
| `Xactly-NTP` | - |
| `Xactly-Inbound_Email` | - |
| `Xactly-LDAP` | - |
| `Xactly-NetBIOS.Session.Service` | - |
| `Xactly-RTMP` | - |
| `Xactly-NetBIOS.Name.Service` | - |
| `Intuit-Other` | - |
| `Intuit-Web` | - |
| `Intuit-ICMP` | - |
| `Intuit-DNS` | - |
| `Intuit-Outbound_Email` | - |
| `Intuit-SSH` | - |
| `Intuit-FTP` | - |
| `Intuit-NTP` | - |
| `Intuit-Inbound_Email` | - |
| `Intuit-LDAP` | - |
| `Intuit-NetBIOS.Session.Service` | - |
| `Intuit-RTMP` | - |
| `Intuit-NetBIOS.Name.Service` | - |
| `Marketo-Other` | - |
| `Marketo-Web` | - |
| `Marketo-ICMP` | - |
| `Marketo-DNS` | - |
| `Marketo-Outbound_Email` | - |
| `Marketo-SSH` | - |
| `Marketo-FTP` | - |
| `Marketo-NTP` | - |
| `Marketo-Inbound_Email` | - |
| `Marketo-LDAP` | - |
| `Marketo-NetBIOS.Session.Service` | - |
| `Marketo-RTMP` | - |
| `Marketo-NetBIOS.Name.Service` | - |
| `Bill-Other` | - |
| `Bill-Web` | - |
| `Bill-ICMP` | - |
| `Bill-DNS` | - |
| `Bill-Outbound_Email` | - |
| `Bill-SSH` | - |
| `Bill-FTP` | - |
| `Bill-NTP` | - |
| `Bill-Inbound_Email` | - |
| `Bill-LDAP` | - |
| `Bill-NetBIOS.Session.Service` | - |
| `Bill-RTMP` | - |
| `Bill-NetBIOS.Name.Service` | - |
| `Shopify-Other` | - |
| `Shopify-Web` | - |
| `Shopify-ICMP` | - |
| `Shopify-DNS` | - |
| `Shopify-Outbound_Email` | - |
| `Shopify-SSH` | - |
| `Shopify-FTP` | - |
| `Shopify-NTP` | - |
| `Shopify-Inbound_Email` | - |
| `Shopify-LDAP` | - |
| `Shopify-NetBIOS.Session.Service` | - |
| `Shopify-RTMP` | - |
| `Shopify-NetBIOS.Name.Service` | - |
| `Shopify-Shopify` | - |
| `MuleSoft-Other` | - |
| `MuleSoft-Web` | - |
| `MuleSoft-ICMP` | - |
| `MuleSoft-DNS` | - |
| `MuleSoft-Outbound_Email` | - |
| `MuleSoft-SSH` | - |
| `MuleSoft-FTP` | - |
| `MuleSoft-NTP` | - |
| `MuleSoft-Inbound_Email` | - |
| `MuleSoft-LDAP` | - |
| `MuleSoft-NetBIOS.Session.Service` | - |
| `MuleSoft-RTMP` | - |
| `MuleSoft-NetBIOS.Name.Service` | - |
| `Cornerstone-Other` | - |
| `Cornerstone-Web` | - |
| `Cornerstone-ICMP` | - |
| `Cornerstone-DNS` | - |
| `Cornerstone-Outbound_Email` | - |
| `Cornerstone-SSH` | - |
| `Cornerstone-FTP` | - |
| `Cornerstone-NTP` | - |
| `Cornerstone-Inbound_Email` | - |
| `Cornerstone-LDAP` | - |
| `Cornerstone-NetBIOS.Session.Service` | - |
| `Cornerstone-RTMP` | - |
| `Cornerstone-NetBIOS.Name.Service` | - |
| `Eventbrite-Other` | - |
| `Eventbrite-Web` | - |
| `Eventbrite-ICMP` | - |
| `Eventbrite-DNS` | - |
| `Eventbrite-Outbound_Email` | - |
| `Eventbrite-SSH` | - |
| `Eventbrite-FTP` | - |
| `Eventbrite-NTP` | - |
| `Eventbrite-Inbound_Email` | - |
| `Eventbrite-LDAP` | - |
| `Eventbrite-NetBIOS.Session.Service` | - |
| `Eventbrite-RTMP` | - |
| `Eventbrite-NetBIOS.Name.Service` | - |
| `Paychex-Other` | - |
| `Paychex-Web` | - |
| `Paychex-ICMP` | - |
| `Paychex-DNS` | - |
| `Paychex-Outbound_Email` | - |
| `Paychex-SSH` | - |
| `Paychex-FTP` | - |
| `Paychex-NTP` | - |
| `Paychex-Inbound_Email` | - |
| `Paychex-LDAP` | - |
| `Paychex-NetBIOS.Session.Service` | - |
| `Paychex-RTMP` | - |
| `Paychex-NetBIOS.Name.Service` | - |
| `NewRelic-Other` | - |
| `NewRelic-Web` | - |
| `NewRelic-ICMP` | - |
| `NewRelic-DNS` | - |
| `NewRelic-Outbound_Email` | - |
| `NewRelic-SSH` | - |
| `NewRelic-FTP` | - |
| `NewRelic-NTP` | - |
| `NewRelic-Inbound_Email` | - |
| `NewRelic-LDAP` | - |
| `NewRelic-NetBIOS.Session.Service` | - |
| `NewRelic-RTMP` | - |
| `NewRelic-NetBIOS.Name.Service` | - |
| `Splunk-Other` | - |
| `Splunk-Web` | - |
| `Splunk-ICMP` | - |
| `Splunk-DNS` | - |
| `Splunk-Outbound_Email` | - |
| `Splunk-SSH` | - |
| `Splunk-FTP` | - |
| `Splunk-NTP` | - |
| `Splunk-Inbound_Email` | - |
| `Splunk-LDAP` | - |
| `Splunk-NetBIOS.Session.Service` | - |
| `Splunk-RTMP` | - |
| `Splunk-NetBIOS.Name.Service` | - |
| `Domo-Other` | - |
| `Domo-Web` | - |
| `Domo-ICMP` | - |
| `Domo-DNS` | - |
| `Domo-Outbound_Email` | - |
| `Domo-SSH` | - |
| `Domo-FTP` | - |
| `Domo-NTP` | - |
| `Domo-Inbound_Email` | - |
| `Domo-LDAP` | - |
| `Domo-NetBIOS.Session.Service` | - |
| `Domo-RTMP` | - |
| `Domo-NetBIOS.Name.Service` | - |
| `FreshBooks-Other` | - |
| `FreshBooks-Web` | - |
| `FreshBooks-ICMP` | - |
| `FreshBooks-DNS` | - |
| `FreshBooks-Outbound_Email` | - |
| `FreshBooks-SSH` | - |
| `FreshBooks-FTP` | - |
| `FreshBooks-NTP` | - |
| `FreshBooks-Inbound_Email` | - |
| `FreshBooks-LDAP` | - |
| `FreshBooks-NetBIOS.Session.Service` | - |
| `FreshBooks-RTMP` | - |
| `FreshBooks-NetBIOS.Name.Service` | - |
| `Tableau-Other` | - |
| `Tableau-Web` | - |
| `Tableau-ICMP` | - |
| `Tableau-DNS` | - |
| `Tableau-Outbound_Email` | - |
| `Tableau-SSH` | - |
| `Tableau-FTP` | - |
| `Tableau-NTP` | - |
| `Tableau-Inbound_Email` | - |
| `Tableau-LDAP` | - |
| `Tableau-NetBIOS.Session.Service` | - |
| `Tableau-RTMP` | - |
| `Tableau-NetBIOS.Name.Service` | - |
| `Druva-Other` | - |
| `Druva-Web` | - |
| `Druva-ICMP` | - |
| `Druva-DNS` | - |
| `Druva-Outbound_Email` | - |
| `Druva-SSH` | - |
| `Druva-FTP` | - |
| `Druva-NTP` | - |
| `Druva-Inbound_Email` | - |
| `Druva-LDAP` | - |
| `Druva-NetBIOS.Session.Service` | - |
| `Druva-RTMP` | - |
| `Druva-NetBIOS.Name.Service` | - |
| `Act-on-Other` | - |
| `Act-on-Web` | - |
| `Act-on-ICMP` | - |
| `Act-on-DNS` | - |
| `Act-on-Outbound_Email` | - |
| `Act-on-SSH` | - |
| `Act-on-FTP` | - |
| `Act-on-NTP` | - |
| `Act-on-Inbound_Email` | - |
| `Act-on-LDAP` | - |
| `Act-on-NetBIOS.Session.Service` | - |
| `Act-on-RTMP` | - |
| `Act-on-NetBIOS.Name.Service` | - |
| `GoodData-Other` | - |
| `GoodData-Web` | - |
| `GoodData-ICMP` | - |
| `GoodData-DNS` | - |
| `GoodData-Outbound_Email` | - |
| `GoodData-SSH` | - |
| `GoodData-FTP` | - |
| `GoodData-NTP` | - |
| `GoodData-Inbound_Email` | - |
| `GoodData-LDAP` | - |
| `GoodData-NetBIOS.Session.Service` | - |
| `GoodData-RTMP` | - |
| `GoodData-NetBIOS.Name.Service` | - |
| `SurveyMonkey-Other` | - |
| `SurveyMonkey-Web` | - |
| `SurveyMonkey-ICMP` | - |
| `SurveyMonkey-DNS` | - |
| `SurveyMonkey-Outbound_Email` | - |
| `SurveyMonkey-SSH` | - |
| `SurveyMonkey-FTP` | - |
| `SurveyMonkey-NTP` | - |
| `SurveyMonkey-Inbound_Email` | - |
| `SurveyMonkey-LDAP` | - |
| `SurveyMonkey-NetBIOS.Session.Service` | - |
| `SurveyMonkey-RTMP` | - |
| `SurveyMonkey-NetBIOS.Name.Service` | - |
| `Cvent-Other` | - |
| `Cvent-Web` | - |
| `Cvent-ICMP` | - |
| `Cvent-DNS` | - |
| `Cvent-Outbound_Email` | - |
| `Cvent-SSH` | - |
| `Cvent-FTP` | - |
| `Cvent-NTP` | - |
| `Cvent-Inbound_Email` | - |
| `Cvent-LDAP` | - |
| `Cvent-NetBIOS.Session.Service` | - |
| `Cvent-RTMP` | - |
| `Cvent-NetBIOS.Name.Service` | - |
| `Blackbaud-Other` | - |
| `Blackbaud-Web` | - |
| `Blackbaud-ICMP` | - |
| `Blackbaud-DNS` | - |
| `Blackbaud-Outbound_Email` | - |
| `Blackbaud-SSH` | - |
| `Blackbaud-FTP` | - |
| `Blackbaud-NTP` | - |
| `Blackbaud-Inbound_Email` | - |
| `Blackbaud-LDAP` | - |
| `Blackbaud-NetBIOS.Session.Service` | - |
| `Blackbaud-RTMP` | - |
| `Blackbaud-NetBIOS.Name.Service` | - |
| `InsideSales-Other` | - |
| `InsideSales-Web` | - |
| `InsideSales-ICMP` | - |
| `InsideSales-DNS` | - |
| `InsideSales-Outbound_Email` | - |
| `InsideSales-SSH` | - |
| `InsideSales-FTP` | - |
| `InsideSales-NTP` | - |
| `InsideSales-Inbound_Email` | - |
| `InsideSales-LDAP` | - |
| `InsideSales-NetBIOS.Session.Service` | - |
| `InsideSales-RTMP` | - |
| `InsideSales-NetBIOS.Name.Service` | - |
| `ServiceMax-Other` | - |
| `ServiceMax-Web` | - |
| `ServiceMax-ICMP` | - |
| `ServiceMax-DNS` | - |
| `ServiceMax-Outbound_Email` | - |
| `ServiceMax-SSH` | - |
| `ServiceMax-FTP` | - |
| `ServiceMax-NTP` | - |
| `ServiceMax-Inbound_Email` | - |
| `ServiceMax-LDAP` | - |
| `ServiceMax-NetBIOS.Session.Service` | - |
| `ServiceMax-RTMP` | - |
| `ServiceMax-NetBIOS.Name.Service` | - |
| `Apptio-Other` | - |
| `Apptio-Web` | - |
| `Apptio-ICMP` | - |
| `Apptio-DNS` | - |
| `Apptio-Outbound_Email` | - |
| `Apptio-SSH` | - |
| `Apptio-FTP` | - |
| `Apptio-NTP` | - |
| `Apptio-Inbound_Email` | - |
| `Apptio-LDAP` | - |
| `Apptio-NetBIOS.Session.Service` | - |
| `Apptio-RTMP` | - |
| `Apptio-NetBIOS.Name.Service` | - |
| `Veracode-Other` | - |
| `Veracode-Web` | - |
| `Veracode-ICMP` | - |
| `Veracode-DNS` | - |
| `Veracode-Outbound_Email` | - |
| `Veracode-SSH` | - |
| `Veracode-FTP` | - |
| `Veracode-NTP` | - |
| `Veracode-Inbound_Email` | - |
| `Veracode-LDAP` | - |
| `Veracode-NetBIOS.Session.Service` | - |
| `Veracode-RTMP` | - |
| `Veracode-NetBIOS.Name.Service` | - |
| `Anaplan-Other` | - |
| `Anaplan-Web` | - |
| `Anaplan-ICMP` | - |
| `Anaplan-DNS` | - |
| `Anaplan-Outbound_Email` | - |
| `Anaplan-SSH` | - |
| `Anaplan-FTP` | - |
| `Anaplan-NTP` | - |
| `Anaplan-Inbound_Email` | - |
| `Anaplan-LDAP` | - |
| `Anaplan-NetBIOS.Session.Service` | - |
| `Anaplan-RTMP` | - |
| `Anaplan-NetBIOS.Name.Service` | - |
| `Rapid7-Other` | - |
| `Rapid7-Web` | - |
| `Rapid7-ICMP` | - |
| `Rapid7-DNS` | - |
| `Rapid7-Outbound_Email` | - |
| `Rapid7-SSH` | - |
| `Rapid7-FTP` | - |
| `Rapid7-NTP` | - |
| `Rapid7-Inbound_Email` | - |
| `Rapid7-LDAP` | - |
| `Rapid7-NetBIOS.Session.Service` | - |
| `Rapid7-RTMP` | - |
| `Rapid7-NetBIOS.Name.Service` | - |
| `AnyDesk-AnyDesk` | - |
| `ESET-Eset.Service` | - |
| `Slack-Other` | - |
| `Slack-Web` | - |
| `Slack-ICMP` | - |
| `Slack-DNS` | - |
| `Slack-Outbound_Email` | - |
| `Slack-SSH` | - |
| `Slack-FTP` | - |
| `Slack-NTP` | - |
| `Slack-Inbound_Email` | - |
| `Slack-LDAP` | - |
| `Slack-NetBIOS.Session.Service` | - |
| `Slack-RTMP` | - |
| `Slack-NetBIOS.Name.Service` | - |
| `Slack-Slack` | - |
| `ADP-Other` | - |
| `ADP-Web` | - |
| `ADP-ICMP` | - |
| `ADP-DNS` | - |
| `ADP-Outbound_Email` | - |
| `ADP-SSH` | - |
| `ADP-FTP` | - |
| `ADP-NTP` | - |
| `ADP-Inbound_Email` | - |
| `ADP-LDAP` | - |
| `ADP-NetBIOS.Session.Service` | - |
| `ADP-RTMP` | - |
| `ADP-NetBIOS.Name.Service` | - |
| `Blackboard-Other` | - |
| `Blackboard-Web` | - |
| `Blackboard-ICMP` | - |
| `Blackboard-DNS` | - |
| `Blackboard-Outbound_Email` | - |
| `Blackboard-SSH` | - |
| `Blackboard-FTP` | - |
| `Blackboard-NTP` | - |
| `Blackboard-Inbound_Email` | - |
| `Blackboard-LDAP` | - |
| `Blackboard-NetBIOS.Session.Service` | - |
| `Blackboard-RTMP` | - |
| `Blackboard-NetBIOS.Name.Service` | - |
| `SAP-Other` | - |
| `SAP-Web` | - |
| `SAP-ICMP` | - |
| `SAP-DNS` | - |
| `SAP-Outbound_Email` | - |
| `SAP-SSH` | - |
| `SAP-FTP` | - |
| `SAP-NTP` | - |
| `SAP-Inbound_Email` | - |
| `SAP-LDAP` | - |
| `SAP-NetBIOS.Session.Service` | - |
| `SAP-RTMP` | - |
| `SAP-NetBIOS.Name.Service` | - |
| `SAP-HANA` | - |
| `SAP-SuccessFactors` | - |
| `Snap-Snapchat` | - |
| `Zoom.us-Zoom.Meeting` | - |
| `Sophos-Other` | - |
| `Sophos-Web` | - |
| `Sophos-ICMP` | - |
| `Sophos-DNS` | - |
| `Sophos-Outbound_Email` | - |
| `Sophos-SSH` | - |
| `Sophos-FTP` | - |
| `Sophos-NTP` | - |
| `Sophos-Inbound_Email` | - |
| `Sophos-LDAP` | - |
| `Sophos-NetBIOS.Session.Service` | - |
| `Sophos-RTMP` | - |
| `Sophos-NetBIOS.Name.Service` | - |
| `Cloudflare-Other` | - |
| `Cloudflare-Web` | - |
| `Cloudflare-ICMP` | - |
| `Cloudflare-DNS` | - |
| `Cloudflare-Outbound_Email` | - |
| `Cloudflare-SSH` | - |
| `Cloudflare-FTP` | - |
| `Cloudflare-NTP` | - |
| `Cloudflare-Inbound_Email` | - |
| `Cloudflare-LDAP` | - |
| `Cloudflare-NetBIOS.Session.Service` | - |
| `Cloudflare-RTMP` | - |
| `Cloudflare-NetBIOS.Name.Service` | - |
| `Cloudflare-CDN` | - |
| `Pexip-Pexip.Meeting` | - |
| `Zscaler-Other` | - |
| `Zscaler-Web` | - |
| `Zscaler-ICMP` | - |
| `Zscaler-DNS` | - |
| `Zscaler-Outbound_Email` | - |
| `Zscaler-SSH` | - |
| `Zscaler-FTP` | - |
| `Zscaler-NTP` | - |
| `Zscaler-Inbound_Email` | - |
| `Zscaler-LDAP` | - |
| `Zscaler-NetBIOS.Session.Service` | - |
| `Zscaler-RTMP` | - |
| `Zscaler-NetBIOS.Name.Service` | - |
| `Zscaler-Zscaler.Cloud` | - |
| `Yandex-Other` | - |
| `Yandex-Web` | - |
| `Yandex-ICMP` | - |
| `Yandex-DNS` | - |
| `Yandex-Outbound_Email` | - |
| `Yandex-SSH` | - |
| `Yandex-FTP` | - |
| `Yandex-NTP` | - |
| `Yandex-Inbound_Email` | - |
| `Yandex-LDAP` | - |
| `Yandex-NetBIOS.Session.Service` | - |
| `Yandex-RTMP` | - |
| `Yandex-NetBIOS.Name.Service` | - |
| `mail.ru-Other` | - |
| `mail.ru-Web` | - |
| `mail.ru-ICMP` | - |
| `mail.ru-DNS` | - |
| `mail.ru-Outbound_Email` | - |
| `mail.ru-SSH` | - |
| `mail.ru-FTP` | - |
| `mail.ru-NTP` | - |
| `mail.ru-Inbound_Email` | - |
| `mail.ru-LDAP` | - |
| `mail.ru-NetBIOS.Session.Service` | - |
| `mail.ru-RTMP` | - |
| `mail.ru-NetBIOS.Name.Service` | - |
| `Alibaba-Other` | - |
| `Alibaba-Web` | - |
| `Alibaba-ICMP` | - |
| `Alibaba-DNS` | - |
| `Alibaba-Outbound_Email` | - |
| `Alibaba-SSH` | - |
| `Alibaba-FTP` | - |
| `Alibaba-NTP` | - |
| `Alibaba-Inbound_Email` | - |
| `Alibaba-LDAP` | - |
| `Alibaba-NetBIOS.Session.Service` | - |
| `Alibaba-RTMP` | - |
| `Alibaba-NetBIOS.Name.Service` | - |
| `Alibaba-Alibaba.Cloud` | - |
| `GoDaddy-Other` | - |
| `GoDaddy-Web` | - |
| `GoDaddy-ICMP` | - |
| `GoDaddy-DNS` | - |
| `GoDaddy-Outbound_Email` | - |
| `GoDaddy-SSH` | - |
| `GoDaddy-FTP` | - |
| `GoDaddy-NTP` | - |
| `GoDaddy-Inbound_Email` | - |
| `GoDaddy-LDAP` | - |
| `GoDaddy-NetBIOS.Session.Service` | - |
| `GoDaddy-RTMP` | - |
| `GoDaddy-NetBIOS.Name.Service` | - |
| `GoDaddy-GoDaddy.Email` | - |
| `Webroot-Webroot.SecureAnywhere` | - |
| `Avast-Other` | - |
| `Avast-Web` | - |
| `Avast-ICMP` | - |
| `Avast-DNS` | - |
| `Avast-Outbound_Email` | - |
| `Avast-SSH` | - |
| `Avast-FTP` | - |
| `Avast-NTP` | - |
| `Avast-Inbound_Email` | - |
| `Avast-LDAP` | - |
| `Avast-NetBIOS.Session.Service` | - |
| `Avast-RTMP` | - |
| `Avast-NetBIOS.Name.Service` | - |
| `Avast-Avast.Security` | - |
| `Wetransfer-Other` | - |
| `Wetransfer-Web` | - |
| `Wetransfer-ICMP` | - |
| `Wetransfer-DNS` | - |
| `Wetransfer-Outbound_Email` | - |
| `Wetransfer-SSH` | - |
| `Wetransfer-FTP` | - |
| `Wetransfer-NTP` | - |
| `Wetransfer-Inbound_Email` | - |
| `Wetransfer-LDAP` | - |
| `Wetransfer-NetBIOS.Session.Service` | - |
| `Wetransfer-RTMP` | - |
| `Wetransfer-NetBIOS.Name.Service` | - |
| `Sendgrid-Sendgrid.Email` | - |
| `Ubiquiti-UniFi` | - |
| `Lifesize-Lifesize.Cloud` | - |
| `Okta-Other` | - |
| `Okta-Web` | - |
| `Okta-ICMP` | - |
| `Okta-DNS` | - |
| `Okta-Outbound_Email` | - |
| `Okta-SSH` | - |
| `Okta-FTP` | - |
| `Okta-NTP` | - |
| `Okta-Inbound_Email` | - |
| `Okta-LDAP` | - |
| `Okta-NetBIOS.Session.Service` | - |
| `Okta-RTMP` | - |
| `Okta-NetBIOS.Name.Service` | - |
| `Okta-Okta` | - |
| `Cybozu-Other` | - |
| `Cybozu-Web` | - |
| `Cybozu-ICMP` | - |
| `Cybozu-DNS` | - |
| `Cybozu-Outbound_Email` | - |
| `Cybozu-SSH` | - |
| `Cybozu-FTP` | - |
| `Cybozu-NTP` | - |
| `Cybozu-Inbound_Email` | - |
| `Cybozu-LDAP` | - |
| `Cybozu-NetBIOS.Session.Service` | - |
| `Cybozu-RTMP` | - |
| `Cybozu-NetBIOS.Name.Service` | - |
| `RealVNC-Other` | - |
| `RealVNC-Web` | - |
| `RealVNC-ICMP` | - |
| `RealVNC-DNS` | - |
| `RealVNC-Outbound_Email` | - |
| `RealVNC-SSH` | - |
| `RealVNC-FTP` | - |
| `RealVNC-NTP` | - |
| `RealVNC-Inbound_Email` | - |
| `RealVNC-LDAP` | - |
| `RealVNC-NetBIOS.Session.Service` | - |
| `RealVNC-RTMP` | - |
| `RealVNC-NetBIOS.Name.Service` | - |
| `Egnyte-Egnyte` | - |
| `CrowdStrike-CrowdStrike.Falcon.Cloud` | - |
| `Aruba.it-Other` | - |
| `Aruba.it-Web` | - |
| `Aruba.it-ICMP` | - |
| `Aruba.it-DNS` | - |
| `Aruba.it-Outbound_Email` | - |
| `Aruba.it-SSH` | - |
| `Aruba.it-FTP` | - |
| `Aruba.it-NTP` | - |
| `Aruba.it-Inbound_Email` | - |
| `Aruba.it-LDAP` | - |
| `Aruba.it-NetBIOS.Session.Service` | - |
| `Aruba.it-RTMP` | - |
| `Aruba.it-NetBIOS.Name.Service` | - |
| `ISLOnline-Other` | - |
| `ISLOnline-Web` | - |
| `ISLOnline-ICMP` | - |
| `ISLOnline-DNS` | - |
| `ISLOnline-Outbound_Email` | - |
| `ISLOnline-SSH` | - |
| `ISLOnline-FTP` | - |
| `ISLOnline-NTP` | - |
| `ISLOnline-Inbound_Email` | - |
| `ISLOnline-LDAP` | - |
| `ISLOnline-NetBIOS.Session.Service` | - |
| `ISLOnline-RTMP` | - |
| `ISLOnline-NetBIOS.Name.Service` | - |
| `Akamai-CDN` | - |
| `Rackspace-CDN` | - |
| `Instart-CDN` | - |
| `Bitdefender-Other` | - |
| `Bitdefender-Web` | - |
| `Bitdefender-ICMP` | - |
| `Bitdefender-DNS` | - |
| `Bitdefender-Outbound_Email` | - |
| `Bitdefender-SSH` | - |
| `Bitdefender-FTP` | - |
| `Bitdefender-NTP` | - |
| `Bitdefender-Inbound_Email` | - |
| `Bitdefender-LDAP` | - |
| `Bitdefender-NetBIOS.Session.Service` | - |
| `Bitdefender-RTMP` | - |
| `Bitdefender-NetBIOS.Name.Service` | - |
| `UptimeRobot-UptimeRobot.Monitor` | - |
| `Quovadisglobal-Other` | - |
| `Quovadisglobal-Web` | - |
| `Quovadisglobal-ICMP` | - |
| `Quovadisglobal-DNS` | - |
| `Quovadisglobal-Outbound_Email` | - |
| `Quovadisglobal-SSH` | - |
| `Quovadisglobal-FTP` | - |
| `Quovadisglobal-NTP` | - |
| `Quovadisglobal-Inbound_Email` | - |
| `Quovadisglobal-LDAP` | - |
| `Quovadisglobal-NetBIOS.Session.Service` | - |
| `Quovadisglobal-RTMP` | - |
| `Quovadisglobal-NetBIOS.Name.Service` | - |
| `Splashtop-Splashtop` | - |
| `Zoox-Other` | - |
| `Zoox-Web` | - |
| `Zoox-ICMP` | - |
| `Zoox-DNS` | - |
| `Zoox-Outbound_Email` | - |
| `Zoox-SSH` | - |
| `Zoox-FTP` | - |
| `Zoox-NTP` | - |
| `Zoox-Inbound_Email` | - |
| `Zoox-LDAP` | - |
| `Zoox-NetBIOS.Session.Service` | - |
| `Zoox-RTMP` | - |
| `Zoox-NetBIOS.Name.Service` | - |
| `Skyfii-Other` | - |
| `Skyfii-Web` | - |
| `Skyfii-ICMP` | - |
| `Skyfii-DNS` | - |
| `Skyfii-Outbound_Email` | - |
| `Skyfii-SSH` | - |
| `Skyfii-FTP` | - |
| `Skyfii-NTP` | - |
| `Skyfii-Inbound_Email` | - |
| `Skyfii-LDAP` | - |
| `Skyfii-NetBIOS.Session.Service` | - |
| `Skyfii-RTMP` | - |
| `Skyfii-NetBIOS.Name.Service` | - |
| `CoffeeBean-Other` | - |
| `CoffeeBean-Web` | - |
| `CoffeeBean-ICMP` | - |
| `CoffeeBean-DNS` | - |
| `CoffeeBean-Outbound_Email` | - |
| `CoffeeBean-SSH` | - |
| `CoffeeBean-FTP` | - |
| `CoffeeBean-NTP` | - |
| `CoffeeBean-Inbound_Email` | - |
| `CoffeeBean-LDAP` | - |
| `CoffeeBean-NetBIOS.Session.Service` | - |
| `CoffeeBean-RTMP` | - |
| `CoffeeBean-NetBIOS.Name.Service` | - |
| `Cloud4Wi-Other` | - |
| `Cloud4Wi-Web` | - |
| `Cloud4Wi-ICMP` | - |
| `Cloud4Wi-DNS` | - |
| `Cloud4Wi-Outbound_Email` | - |
| `Cloud4Wi-SSH` | - |
| `Cloud4Wi-FTP` | - |
| `Cloud4Wi-NTP` | - |
| `Cloud4Wi-Inbound_Email` | - |
| `Cloud4Wi-LDAP` | - |
| `Cloud4Wi-NetBIOS.Session.Service` | - |
| `Cloud4Wi-RTMP` | - |
| `Cloud4Wi-NetBIOS.Name.Service` | - |
| `Panda-Panda.Security` | - |
| `Ewon-Talk2M` | - |
| `Nutanix-Nutanix.Cloud` | - |
| `Backblaze-Other` | - |
| `Backblaze-Web` | - |
| `Backblaze-ICMP` | - |
| `Backblaze-DNS` | - |
| `Backblaze-Outbound_Email` | - |
| `Backblaze-SSH` | - |
| `Backblaze-FTP` | - |
| `Backblaze-NTP` | - |
| `Backblaze-Inbound_Email` | - |
| `Backblaze-LDAP` | - |
| `Backblaze-NetBIOS.Session.Service` | - |
| `Backblaze-RTMP` | - |
| `Backblaze-NetBIOS.Name.Service` | - |
| `Extreme-Extreme.Cloud` | - |
| `XING-Other` | - |
| `XING-Web` | - |
| `XING-ICMP` | - |
| `XING-DNS` | - |
| `XING-Outbound_Email` | - |
| `XING-SSH` | - |
| `XING-FTP` | - |
| `XING-NTP` | - |
| `XING-Inbound_Email` | - |
| `XING-LDAP` | - |
| `XING-NetBIOS.Session.Service` | - |
| `XING-RTMP` | - |
| `XING-NetBIOS.Name.Service` | - |
| `Genesys-PureCloud` | - |
| `BlackBerry-Cylance` | - |
| `DigiCert-OCSP` | - |
| `Infomaniak-SwissTransfer` | - |
| `Fuze-Fuze` | - |
| `Truecaller-Truecaller` | - |
| `GlobalSign-OCSP` | - |
| `VeriSign-OCSP` | - |
| `Sony-PlayStation.Network` | - |
| `Acronis-Cyber.Cloud` | - |
| `RingCentral-RingCentral` | - |
| `FSecure-FSecure` | - |
| `Kaseya-Kaseya.Cloud` | - |
| `Shodan-Scanner` | - |
| `Censys-Scanner` | - |
| `Valve-Steam` | - |
| `YouSeeU-Bongo` | - |
| `Cato-Cato.Cloud` | - |
| `SolarWinds-SpamExperts` | - |
| `SolarWinds-Pingdom.Probe` | - |
| `8X8-8X8.Cloud` | - |
| `Zattoo-Zattoo.TV` | - |
| `Datto-Datto.RMM` | - |
| `Barracuda-Barracuda.Cloud` | - |
| `Naver-Line` | - |
| `Disney-Disney+` | - |
| `DNS-DoH_DoT` | - |
| `Quad9-Quad9.Standard.DNS` | - |
| `Stretchoid-Scanner` | - |
| `Poly-RealConnect.Service` | - |
| `Telegram-Telegram` | - |
| `Spotify-Spotify` | - |
| `NextDNS-NextDNS` | - |
| `Fastly-CDN` | - |
| `Neustar-UltraDNS.Probes` | - |
| `Microsoft-Intune` | - |
| `Microsoft-Office365.Published.Optimize` | - |
| `Microsoft-Office365.Published.Allow` | - |
| `Microsoft-Office365.Published.USGOV` | - |
| `Microsoft-Azure.Monitor` | - |
| `Microsoft-Azure.SQL` | - |
| `Microsoft-Azure.AD` | - |
| `Microsoft-Azure.Data.Factory` | - |
| `Microsoft-Azure.Virtual.Desktop` | - |
| `Microsoft-Azure.Power.BI` | - |
| `Amazon-Twitch` | - |
| `Amazon-AWS.GovCloud.US` | - |
| `Amazon-AWS.EBS` | - |
| `Amazon-AWS.Cloud9` | - |
| `Amazon-AWS.DynamoDB` | - |
| `Amazon-AWS.Route53` | - |
| `Amazon-AWS.S3` | - |
| `Amazon-AWS.Kinesis.Video.Streams` | - |
| `Amazon-AWS.Global.Accelerator` | - |
| `Amazon-AWS.EC2` | - |
| `Amazon-AWS.API.Gateway` | - |
| `Amazon-AWS.Chime.Voice.Connector` | - |
| `Amazon-AWS.Connect` | - |
| `Amazon-AWS.CloudFront` | - |
| `Amazon-AWS.CodeBuild` | - |
| `Amazon-AWS.Chime.Meetings` | - |
| `Amazon-AWS.AppFlow` | - |
| `Amazon-Amazon.SES` | - |
| `Adobe-Adobe.Sign` | - |
| `Fortinet-FortiVoice.Cloud` | - |
| `Fortinet-FortiGuard.Secure.DNS` | - |
| `Fortinet-FortiEDR` | - |
| `Zoho-Site24x7.Monitor` | - |
| `Cisco-Webex.FedRAMP` | - |
| `Cisco-Secure.Endpoint` | - |
| `Atlassian-Atlassian.Cloud` | - |
| `Atlassian-Atlassian.Notification` | - |
| `Akamai-Linode.Cloud` | - |
| `SolarWinds-SolarWinds.RMM` | - |
| `DNS-Root.Name.Servers` | - |
| `Malicious-Malicious.Server` | - |
| `NIST-ITS` | - |
| `Jamf-Jamf.Cloud` | - |
| `Alcatel.Lucent-Rainbow` | - |
| `Forcepoint-Forcepoint.Cloud` | - |
| `Datadog-Datadog` | - |
| `Mimecast-Mimecast` | - |
| `MediaFire-Other` | - |
| `MediaFire-Web` | - |
| `MediaFire-ICMP` | - |
| `MediaFire-DNS` | - |
| `MediaFire-Outbound_Email` | - |
| `MediaFire-SSH` | - |
| `MediaFire-FTP` | - |
| `MediaFire-NTP` | - |
| `MediaFire-Inbound_Email` | - |
| `MediaFire-LDAP` | - |
| `MediaFire-NetBIOS.Session.Service` | - |
| `MediaFire-RTMP` | - |
| `MediaFire-NetBIOS.Name.Service` | - |
| `Pandora-Pandora` | - |
| `SiriusXM-SiriusXM` | - |
| `Hopin-Hopin` | - |
| `RedShield-RedShield.Cloud` | - |
| `InterneTTL-Scanner` | - |
| `VadeSecure-VadeSecure.Cloud` | - |
| `Netskope-Netskope.Cloud` | - |
| `ClickMeeting-ClickMeeting` | - |
| `Tenable-Tenable.io.Cloud.Scanner` | - |
| `Vidyo-VidyoCloud` | - |
| `OpenNIC-OpenNIC.DNS` | - |
| `Sectigo-Sectigo` | - |
| `DigitalOcean-DigitalOcean.Platform` | - |
| `Pitney.Bowes-Pitney.Bowes.Data.Center` | - |
| `VPN-Anonymous.VPN` | - |
| `Blockchain-Crypto.Mining.Pool` | - |
| `FactSet-FactSet` | - |
| `Bloomberg-Bloomberg` | - |
| `Five9-Five9` | - |
| `Gigas-Gigas.Cloud` | - |
| `Imperva-Imperva.Cloud.WAF` | - |
| `HorizonIQ-HorizonIQ` | - |
| `Azion-Azion.Platform` | - |
| `Hurricane.Electric-Hurricane.Electric.Internet.Services` | - |
| `NodePing-NodePing.Probe` | - |
| `Frontline-Frontline` | - |
| `Tally-Tally.ERP` | - |
| `Hosting-Bulletproof.Hosting` | - |
| `Okko-Okko.TV` | - |
| `Voximplant-Voximplant.Platform` | - |
| `OVHcloud-OVHcloud` | - |
| `SentinelOne-SentinelOne.Cloud` | - |
| `Kakao-Kakao.Services` | - |
| `Stripe-Stripe` | - |
| `NetScout-Scanner` | - |
| `Recyber-Scanner` | - |
| `Cyber.Casa-Scanner` | - |
| `GTHost-Dedicated.Instant.Servers` | - |
| `ivi-ivi.Streaming` | - |
| `BinaryEdge-Scanner` | - |
| `Fintech-MarketMap.Terminal` | - |
| `xMatters-xMatters.Platform` | - |
| `Blizzard-Battle.Net` | - |
| `Axon-Evidence` | - |
| `CDN77-CDN` | - |
| `GCore.Labs-CDN` | - |
| `Matrix42-FastViewer` | - |
| `Bunny.net-CDN` | - |
| `StackPath-CDN` | - |
| `Edgio-CDN` | - |
| `CacheFly-CDN` | - |
| `Bluejeans-Bluejeans.Meeting` | - |
| `Microsoft-Azure.Connectors` | - |
| `Microsoft-Teams.Published.Worldwide.Optimize` | - |
| `Microsoft-Teams.Published.Worldwide.Allow` | - |
| `Microsoft-Azure.Front.Door` | - |
| `Microsoft-Azure.Service.Bus` | - |
| `Microsoft-Azure.Microsoft.Defender` | - |
| `Microsoft-Azure.Resource.Manager` | - |
| `Microsoft-Azure.Arc.Infrastructure` | - |
| `Microsoft-Azure.Storage` | - |
| `Microsoft-Azure.ATP` | - |
| `Microsoft-Azure.Traffic.Manager` | - |
| `Microsoft-Azure.Windows.Admin.Center` | - |
| `Microsoft-Azure.KeyVault` | - |
| `Microsoft-Azure.Databricks` | - |
| `Microsoft-Azure.Event.Hub` | - |
| `Microsoft-Azure.Power.Platform` | - |
| `Microsoft-Azure.Front.Door.MicrosoftSecurity` | - |
| `Microsoft-Azure.OneDsCollector` | - |
| `Salesforce-Hyperforce` | - |
| `Fortinet-FortiClient.EMS` | - |
| `Fortinet-FortiWeb.Cloud` | - |
| `Fortinet-FortiSASE` | - |
| `Fortinet-FortiGuard.SOCaaS` | - |
| `Fortinet-FortiDLP.Cloud` | - |
| `Fortinet-FortiMonitor` | - |
| `Fortinet-FortiSandbox` | - |
| `Fortinet-FortiSandbox.Cloud` | - |
| `Tencent-VooV.Meeting` | - |
| `NewRelic-Synthetic.Monitor` | - |
| `Rapid7-Scanner` | - |
| `SAP-SAP.Ariba` | - |
| `Alibaba-DingTalk` | - |
| `ISLOnline-ISLOnline` | - |
| `Datto-Datto.BCDR` | - |
| `DNS-ARPA.Name.Servers` | - |
| `DNS-Generic.TLD.Name.Servers` | - |
| `OVHcloud-OVH.Telecom` | - |
| `Paylocity-Paylocity` | - |
| `Qualys-Qualys.Cloud.Platform` | - |
| `Dailymotion-Other` | - |
| `Dailymotion-Web` | - |
| `Dailymotion-ICMP` | - |
| `Dailymotion-DNS` | - |
| `Dailymotion-Outbound_Email` | - |
| `Dailymotion-SSH` | - |
| `Dailymotion-FTP` | - |
| `Dailymotion-NTP` | - |
| `Dailymotion-Inbound_Email` | - |
| `Dailymotion-LDAP` | - |
| `Dailymotion-NetBIOS.Session.Service` | - |
| `Dailymotion-RTMP` | - |
| `Dailymotion-NetBIOS.Name.Service` | - |
| `LaunchDarkly-LaunchDarkly.Platform` | - |
| `Medianova-CDN` | - |
| `NetDocuments-NetDocuments.Platform` | - |
| `Vonage-Vonage.Contact.Center` | - |
| `Vonage-Vonage.Video.API` | - |
| `Veritas-Enterprise.Vault.Cloud` | - |
| `UK.NCSC-Scanner` | - |
| `Restream-Restream.Platform` | - |
| `ArcticWolf-ArcticWolf.Cloud` | - |
| `CounterPath-Bria` | - |
| `CriminalIP-Scanner` | - |
| `IPFS-IPFS.Gateway` | - |
| `Internet.Census.Group-Scanner` | - |
| `Performive-Performive.Cloud` | - |
| `OneLogin-OneLogin` | - |
| `Shadowserver-Scanner` | - |
| `Turkcell-Suit.Conference` | - |
| `LeakIX-Scanner` | - |
| `Infoblox-BloxOne` | - |
| `Nice-CXone` | - |
| `Hetzner-Hetzner.Hosting.Service` | - |
| `ThreatLocker-ThreatLocker` | - |
| `ZPE-ZPE.Cloud` | - |
| `ColoCrossing-ColoCrossing.Hosting.Service` | - |
| `Sinch-Mailgun` | - |
| `SpaceX-Starlink` | - |
| `Ingenuity-Ingenuity.Cloud.Service` | - |
| `Skyhigh.Security-Secure.Web.Gateway` | - |
| `THE.Hosting-THE.Hosting.Hosting.Service` | - |
| `StatusCake-StatusCake.Monitor` | - |
| `NAP-NAPLAN` | - |
| `Elastic-Elastic.Cloud` | - |
| `NFON-NFON` | - |
| `SERVERD-SERVERD.Hosting.Service` | - |
| `MEGA-MEGA.Cloud` | - |
| `Hadrian-Scanner` | - |
| `Dotcom.Monitor-Dotcom.Monitor` | - |
| `Ahrefs-AhrefsBot` | - |
| `Semrush-SemrushBot` | - |
| `Zero.Networks-Zero.Networks` | - |
| `Vultr-Vultr.Cloud` | - |
| `EGI-EGI.Hosting.Service` | - |
| `ONYPHE-Scanner` | - |
| `Proofpoint-Proofpoint` | - |
| `Lookout-Lookout.Cloud` | - |
| `Heimdal-Heimdal.Security` | - |
| `Yealink-Yealink.Meeting` | - |
| `Secomea-Secomea` | - |
| `CallTower-CT.Cloud` | - |
| `OpenAI-OpenAI.Bot` | - |
| `OpenAI-GPT.Actions` | - |
| `Alpemix-Alpemix` | - |
| `M247-M247.Hosting.Service` | - |
| `Quintex-Quintex.Hosting.Service` | - |
| `Aeza-Aeza.Hosting.Service` | - |
| `Amanah-Amanah.Hosting.Service` | - |
| `ByteDance-Lark` | - |
| `KnowBe4-KnowBe4` | - |
| `Keeper-Keeper.Security` | - |
| `NinjaOne-NinjaOne` | - |
| `Modat-Scanner` | - |
| `Make-Make.Platform` | - |
| `Cloudzy-Cloudzy.Hosting.Service` | - |
| `Nokia-Deepfield.Genome.Crawler` | - |
| `Neat-Neat.Cloud` | - |
| `Brightree-Brightree` | - |
| `PagerDuty-PagerDuty` | - |
| `JFrog-JFrog` | - |
| `Tailscale-Tailscale` | - |
| `Gamma-Horizon` | - |
| `Automox-Automox` | - |
| `Pulseway-Pulseway.RMM` | - |
| `3xK-3xK.Hosting.Service` | - |
| `ASEM-UBIQUITY` | - |
| `Dialpad-Dialpad` | - |
| `iboss-iboss.Cloud` | - |
| `Redstor-Redstor` | - |
| `Anthropic-Claude` | - |
| `NETLOCK-NETLOCK` | - |
| `Aircall-Aircall` | - |
| `Mendix-Mendix.Cloud` | - |
| `Palo.Alto.Networks-Cortex.Xpanse.Scanner` | - |
| `Microsoft-Azure.Sentinel` | - |
| `Tor-Tor.Node` | - |
| `Zendesk-Other` | - |
| `Zendesk-Web` | - |
| `Zendesk-ICMP` | - |
| `Zendesk-DNS` | - |
| `Zendesk-Outbound_Email` | - |
| `Zendesk-SSH` | - |
| `Zendesk-FTP` | - |
| `Zendesk-NTP` | - |
| `Zendesk-Inbound_Email` | - |
| `Zendesk-LDAP` | - |
| `Zendesk-NetBIOS.Session.Service` | - |
| `Zendesk-RTMP` | - |
| `Zendesk-NetBIOS.Name.Service` | - |
| `Pingdom-Other` | - |
| `Pingdom-Web` | - |
| `Pingdom-ICMP` | - |
| `Pingdom-DNS` | - |
| `Pingdom-Outbound_Email` | - |
| `Pingdom-SSH` | - |
| `Pingdom-FTP` | - |
| `Pingdom-NTP` | - |
| `Pingdom-Inbound_Email` | - |
| `Pingdom-LDAP` | - |
| `Pingdom-NetBIOS.Session.Service` | - |
| `Pingdom-RTMP` | - |
| `Pingdom-NetBIOS.Name.Service` | - |
| `UptimeRobot-Other` | - |
| `UptimeRobot-Web` | - |
| `UptimeRobot-ICMP` | - |
| `UptimeRobot-DNS` | - |
| `UptimeRobot-Outbound_Email` | - |
| `UptimeRobot-SSH` | - |
| `UptimeRobot-FTP` | - |
| `UptimeRobot-NTP` | - |
| `UptimeRobot-Inbound_Email` | - |
| `UptimeRobot-LDAP` | - |
| `UptimeRobot-NetBIOS.Session.Service` | - |
| `UptimeRobot-RTMP` | - |
| `UptimeRobot-NetBIOS.Name.Service` | - |
| `Microsoft-Azure.IoT.Hub` | - |

### Schedules

| Schedule Name | Start Time | End Time | Recurring Days |
| :--- | :--- | :--- | :--- |
| `always` | `Always` | `Always` | `sunday, monday, tuesday, wednesday, thursday, friday, saturday` |
| `none` | `Always` | `Always` | `All` |
| `default-darrp-optimize` | `01:00` | `01:30` | `sunday, monday, tuesday, wednesday, thursday, friday, saturday` |

### Universal Threat Prevention & Profile Groups

| Profile Group Name | Antivirus | Vulnerability (IPS) | Anti-Spyware | URL Filtering | File Blocking | Sandbox | Decryption | Description |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `SPG_IPS_default` | `default` | `default` | `default` | `default` | `basic-file-blocking` | `default` | `certificate-inspection` | Auto-generated profile group for FortiGate UTM (IPS_default) |
| `Migrated_Profiles` | `default` | `default` | `default` | `default` | `basic-file-blocking` | `default` | `certificate-inspection` | Auto-generated profile group for FortiGate UTM (General) |
| `SPG_IPS_high_security` | `default` | `high_security` | `default` | `default` | `basic-file-blocking` | `default` | `certificate-inspection` | Auto-generated profile group for FortiGate UTM (IPS_high_security) |
| `SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio` | `default` | `high_security` | `default` | `deleum_webfilter` | `basic-file-blocking` | `default` | `certificate-inspection` | Auto-generated profile group for FortiGate UTM (IPS_high_security, WF_deleum_webfilter, APP_deleum application control) |
| `SPG_WF_deleum_webfilter_APP_deleum_application_control` | `default` | `default` | `default` | `deleum_webfilter` | `basic-file-blocking` | `default` | `certificate-inspection` | Auto-generated profile group for FortiGate UTM (WF_deleum_webfilter, APP_deleum application control) |
| `SPG_APP_deleum_application_control` | `default` | `default` | `default` | `default` | `basic-file-blocking` | `default` | `certificate-inspection` | Auto-generated profile group for FortiGate UTM (APP_deleum application control) |
| `SPG_WF_wifi__deleum_webfilter_APP_deleum_application_control_fo` | `default` | `default` | `default` | `wifi_ deleum_webfilter` | `basic-file-blocking` | `default` | `certificate-inspection` | Auto-generated profile group for FortiGate UTM (WF_wifi_ deleum_webfilter, APP_deleum application control for IOS) |
| `SPG_WF_wifi__deleum_webfilter_APP_deleum_application_control` | `default` | `default` | `default` | `wifi_ deleum_webfilter` | `basic-file-blocking` | `default` | `certificate-inspection` | Auto-generated profile group for FortiGate UTM (WF_wifi_ deleum_webfilter, APP_deleum application control) |
| `SPG_IPS_default_WF_deleum_webfilter_APP_deleum_application_cont` | `default` | `default` | `default` | `deleum_webfilter` | `basic-file-blocking` | `default` | `certificate-inspection` | Auto-generated profile group for FortiGate UTM (IPS_default, WF_deleum_webfilter, APP_deleum application control) |
| `SPG_AV_default_IPS_high_security_WF_deleum_webfilter_APP_deleum` | `default` | `high_security` | `default` | `deleum_webfilter` | `basic-file-blocking` | `default` | `certificate-inspection` | Auto-generated profile group for FortiGate UTM (AV_default, IPS_high_security, WF_deleum_webfilter, APP_deleum application control) |
| `SPG_IPS_high_security_APP_deleum_application_control` | `default` | `high_security` | `default` | `default` | `basic-file-blocking` | `default` | `certificate-inspection` | Auto-generated profile group for FortiGate UTM (IPS_high_security, APP_deleum application control) |

## 5. 📋 Rulebase & Policies

### Security Policies

| # | Policy Name | From Zone | To Zone | Source | Destination | ISDB Destination | Service | Action | Status | Profiles | Description |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `,` | `trust` | `dmz` | `DOSSB_Labuan_Leased_Line-10.10.2.0/24, DOSSB_Labuan-192.168.2.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_default` | - |
| 2 | `252` | `untrust` | `dmz` | `DOSSB_Labuan-192.168.2.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 3 | `253` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `DOSSB_Labuan-192.168.2.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 4 | `258` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `DOSSB_Labuan-192.168.2.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 5 | `263` | `untrust` | `dmz` | `DOSSB_Labuan-192.168.2.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` |  (Reverse of 258) |
| 6 | `255` | `trust` | `untrust` | `pulse_new_172.16.0.0/24` | `DOSSB_Labuan-192.168.2.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 7 | `259` | `trust` | `untrust` | `pulse_new_172.16.0.0/24` | `DOSSB_Labuan-192.168.2.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 8 | `264` | `untrust` | `trust` | `DOSSB_Labuan-192.168.2.0/24` | `pulse_new_172.16.0.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` |  (Reverse of 259) |
| 9 | `257` | `trust` | `untrust` | `Trust-192.168.0.0/23` | `DOSSB_Labuan-192.168.2.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 10 | `260` | `trust` | `untrust` | `Trust-192.168.0.0/23` | `DOSSB_Labuan-192.168.2.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 11 | `256` | `untrust` | `trust` | `DOSSB_Labuan-192.168.2.0/24` | `pulse_new_172.16.0.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` |  (Reverse of 255) |
| 12 | `254` | `untrust` | `untrust` | `SSL_VPN_HQ` | `DOSSB_Labuan-192.168.2.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 13 | `261` | `untrust` | `untrust` | `SSL_VPN_HQ` | `DOSSB_Labuan-192.168.2.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 14 | `9` | `trust` | `untrust` | `DOSSB_Labuan_Leased_Line-10.10.2.0/24, DOSSB_Labuan-192.168.2.0/24, DOSSB_Labuan_wifi_10.10.22.0/24` | `any` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `Migrated_Profiles` | - |
| 15 | `85` | `trust` | `untrust` | `FAZ200F_192.168.30.2` | `Miri_WS-192.168.8.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | - |
| 16 | `206` | `trust` | `untrust` | `FAZ200F_192.168.30.2` | `Miri_WS-192.168.8.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 85 |
| 17 | `153` | `trust` | `untrust` | `FAZ200F_192.168.30.2` | `DOSSB_KSB-192.168.4.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 85 |
| 18 | `163` | `untrust` | `trust` | `DOSSB_KSB-192.168.4.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Reverse of 153 |
| 19 | `170` | `trust` | `untrust` | `FAZ200F_192.168.30.2` | `DPSB_CKJ_192.168.14.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 87 |
| 20 | `179` | `trust` | `untrust` | `FAZ200F_192.168.30.2` | `DOSSB_KSB-192.168.4.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 170 |
| 21 | `204` | `untrust` | `trust` | `DOSSB_KSB-192.168.4.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Reverse of 179 |
| 22 | `111` | `trust` | `untrust` | `FAZ200F_192.168.30.2` | `DPSB_CKJ_192.168.14.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | - |
| 23 | `187` | `trust` | `untrust` | `FAZ200F_192.168.30.2` | `DPSB_TK_new_192.168.7.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 111 |
| 24 | `268` | `trust` | `untrust` | `FAZ200F_192.168.30.2` | `Miri_DTS_192.168.6.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 111 (Copy of 187) (Copy of ) |
| 25 | `285` | `trust` | `untrust` | `FAZ200F_192.168.30.2` | `Bintulu1_192.168.11.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 26 | `298` | `trust` | `untrust` | `FAZ200F_192.168.30.2` | `Bintulu1_192.168.11.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 27 | `288` | `trust` | `untrust` | `FAZ200F_192.168.30.2` | `Bintulu2-192.168.3.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` |  (Copy of 285) (Copy of ) |
| 28 | `302` | `trust` | `untrust` | `FAZ200F_192.168.30.2` | `Bintulu2-192.168.3.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 29 | `286` | `untrust` | `trust` | `Bintulu1_192.168.11.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` |  (Reverse of 285) |
| 30 | `295` | `untrust` | `trust` | `Bintulu1_192.168.11.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 31 | `292` | `untrust` | `trust` | `Bintulu2-192.168.3.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 32 | `303` | `untrust` | `trust` | `Bintulu2-192.168.3.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` |  (Copy of 292) (Copy of ) |
| 33 | `275` | `trust` | `untrust` | `FAZ200F_192.168.30.2` | `Miri_DTS_192.168.6.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | - |
| 34 | `273` | `untrust` | `trust` | `Miri_DTS_192.168.6.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 111 (Copy of 187) (Copy of ) (Reverse of 268) |
| 35 | `279` | `untrust` | `trust` | `Miri_DTS_192.168.6.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | - |
| 36 | `269` | `trust` | `untrust` | `trust_dhcp` | `Miri_DTS_192.168.6.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | - |
| 37 | `282` | `trust` | `untrust` | `trust_dhcp` | `Bintulu1_192.168.11.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` |  (Copy of 269) (Copy of ) |
| 38 | `297` | `trust` | `untrust` | `trust_dhcp` | `Bintulu1_192.168.11.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` |   |
| 39 | `291` | `trust` | `untrust` | `trust_dhcp` | `Bintulu2-192.168.3.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | - |
| 40 | `305` | `trust` | `untrust` | `trust_dhcp` | `Bintulu2-192.168.3.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | - |
| 41 | `281` | `trust` | `untrust` | `trust_dhcp` | `Miri_DTS_192.168.6.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` |  (Copy of 269) (Copy of ) |
| 42 | `270` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `Miri_DTS_192.168.6.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | - |
| 43 | `284` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `Bintulu1_192.168.11.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 44 | `299` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `Bintulu1_192.168.11.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 45 | `289` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `Bintulu2-192.168.3.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 46 | `301` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `Bintulu2-192.168.3.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 47 | `287` | `untrust` | `dmz` | `Bintulu1_192.168.11.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` |  (Reverse of 284) |
| 48 | `296` | `untrust` | `dmz` | `Bintulu1_192.168.11.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 49 | `293` | `untrust` | `dmz` | `Bintulu2-192.168.3.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` |   |
| 50 | `304` | `untrust` | `dmz` | `Bintulu2-192.168.3.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` |   (Copy of 293) (Copy of ) |
| 51 | `277` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `Miri_DTS_192.168.6.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | - |
| 52 | `274` | `untrust` | `dmz` | `Miri_DTS_192.168.6.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` |  (Reverse of 270) |
| 53 | `280` | `untrust` | `dmz` | `Miri_DTS_192.168.6.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | - |
| 54 | `199` | `untrust` | `trust` | `DPSB_TK_new_192.168.7.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Reverse of 187 |
| 55 | `189` | `trust` | `untrust` | `FAZ200F_192.168.30.2` | `DPSB_TK_new_192.168.7.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 187 |
| 56 | `221` | `trust` | `untrust` | `FAZ200F_192.168.30.2` | `DOSSB_KK-192.168.13.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 189 |
| 57 | `250` | `trust` | `untrust` | `FAZ200F_192.168.30.2` | `DOSSB_Labuan-192.168.2.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | - |
| 58 | `262` | `trust` | `untrust` | `FAZ200F_192.168.30.2` | `DOSSB_Labuan-192.168.2.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | - |
| 59 | `265` | `untrust` | `trust` | `DOSSB_Labuan-192.168.2.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | - |  (Reverse of 262) |
| 60 | `251` | `untrust` | `trust` | `DOSSB_Labuan-192.168.2.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | - |  (Reverse of 250) |
| 61 | `223` | `untrust` | `trust` | `DOSSB_KK-192.168.13.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Reverse of 221 |
| 62 | `220` | `trust` | `untrust` | `FAZ200F_192.168.30.2` | `DOSSB_KK-192.168.13.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 189 |
| 63 | `222` | `untrust` | `trust` | `DOSSB_KK-192.168.13.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Reverse of 220 |
| 64 | `200` | `untrust` | `trust` | `DPSB_TK_new_192.168.7.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Reverse of 189 |
| 65 | `95` | `trust` | `trust` | `FAZ200F_192.168.30.2` | `DOSSB_Labuan-192.168.2.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | - |
| 66 | `96` | `trust` | `trust` | `DOSSB_Labuan-192.168.2.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Reverse of 95 |
| 67 | `177` | `untrust` | `trust` | `DPSB_CKJ_192.168.14.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 88 |
| 68 | `117` | `untrust` | `trust` | `DOSSB_Miri-192.168.5.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 88 |
| 69 | `215` | `untrust` | `trust` | `DOSSB_Miri-192.168.5.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 117 |
| 70 | `107` | `untrust` | `trust` | `DPSB_CKJ_192.168.14.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | - |
| 71 | `86` | `untrust` | `trust` | `Miri_WS-192.168.8.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Reverse of 85 |
| 72 | `209` | `untrust` | `trust` | `Miri_WS-192.168.8.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 86 |
| 73 | `4` | `dmz` | `trust` | `Server-192.168.42.0/24` | `DOSSB_Labuan_Leased_Line-10.10.2.0/24, DOSSB_Labuan-192.168.2.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Reverse of , |
| 74 | `17` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `Branches_LAN` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | - |
| 75 | `128` | `trust` | `dmz` | `trust_dhcp` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_high_security` | Clone of 23 |
| 76 | `23` | `trust` | `dmz` | `trust_dhcp` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio` | Reverse of 22 |
| 77 | `127` | `trust` | `untrust` | `trust_dhcp` | `Branches_LAN` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | Clone of 32 |
| 78 | `186` | `trust` | `untrust` | `Trust-192.168.0.0/23` | `banking` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_WF_deleum_webfilter_APP_deleum_application_control` |  (Copy of 32) (Copy of ) |
| 79 | `32` | `trust` | `untrust` | `Trust-192.168.0.0/23` | `banking` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | - | - |
| 80 | `to_MicrosoftTeams` | `trust` | `untrust` | `Trust-192.168.0.0/23` | `any` | `Microsoft-Skype_Teams` | `any` | 🟢 `ALLOW` | Active | - | Clone of 137 |
| 81 | `137` | `trust` | `untrust` | `trust_fixed_IP` | `any` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_APP_deleum_application_control` | Clone of FSSO policy |
| 82 | `FSSO policy` | `trust` | `untrust` | `trust_dhcp` | `any` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_WF_deleum_webfilter_APP_deleum_application_control` | - |
| 83 | `33` | `trust` | `untrust` | `trust_dhcp` | `any` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio` | - |
| 84 | `to_MicrosoftTeams_from_wifi` | `trust` | `untrust` | `HQ_Wifi_User-10.10.10.0/23` | `any` | `Microsoft-Skype_Teams` | `any` | 🟢 `ALLOW` | Active | - | Clone of to_MicrosoftTeams |
| 85 | `quic allowed` | `trust` | `untrust` | `exclude QUIC` | `any` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_WF_wifi__deleum_webfilter_APP_deleum_application_control_fo` | - |
| 86 | `39` | `trust` | `untrust` | `HQ_Wifi_User-10.10.10.0/23` | `any` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_WF_wifi__deleum_webfilter_APP_deleum_application_control` | - |
| 87 | `147` | `trust` | `dmz` | `pulse_new_172.16.0.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio` | - |
| 88 | `151` | `dmz` | `trust` | `Server-192.168.42.0/24` | `pulse_new_172.16.0.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Reverse of 147 |
| 89 | `148` | `trust` | `trust` | `pulse_new_172.16.0.0/24` | `Trust-192.168.0.0/23` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Clone of 147 |
| 90 | `152` | `trust` | `trust` | `trust_dhcp` | `pulse_new_172.16.0.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_high_security` | Clone of 126 |
| 91 | `150` | `trust` | `trust` | `trust_dhcp` | `pulse_new_172.16.0.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | Reverse of 148 |
| 92 | `154` | `trust` | `trust` | `pulse_new_172.16.0.0/24` | `DBATT_192.168.10.7` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_default` | Clone of 144 |
| 93 | `160` | `trust` | `trust` | `pulse_new_172.16.0.0/24` | `DOSSB_Labuan-192.168.2.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_default` | Clone of 142 |
| 94 | `174` | `trust` | `trust` | `DOSSB_Labuan-192.168.2.0/24` | `pulse_new_172.16.0.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_default` | Reverse of 160 |
| 95 | `155` | `trust` | `untrust` | `pulse_new_172.16.0.0/24` | `Branches_LAN` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_default` | Clone of 45 |
| 96 | `157` | `untrust` | `trust` | `Branches_LAN` | `pulse_new_172.16.0.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_default` | Reverse of 155 |
| 97 | `156` | `trust` | `untrust` | `pulse_new_172.16.0.0/24` | `any` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_WF_deleum_webfilter_APP_deleum_application_control` | Clone of 46 |
| 98 | `172` | `trust` | `untrust` | `pulse_new_172.16.0.0/24` | `DPSB_CKJ_192.168.14.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Clone of 161 |
| 99 | `161` | `trust` | `untrust` | `pulse_new_172.16.0.0/24` | `DOSSB_KSB-192.168.4.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Clone of 172 |
| 100 | `180` | `untrust` | `trust` | `DPSB_CKJ_192.168.14.0/24` | `pulse_new_172.16.0.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Clone of 179 |
| 101 | `162` | `trust` | `untrust` | `pulse_new_172.16.0.0/24` | `DPSB_CKJ_192.168.14.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Clone of 109 |
| 102 | `188` | `trust` | `untrust` | `pulse_new_172.16.0.0/24` | `DPSB_TK_new_192.168.7.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Clone of 162 |
| 103 | `272` | `trust` | `untrust` | `pulse_new_172.16.0.0/24` | `Miri_DTS_192.168.6.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 104 | `276` | `trust` | `untrust` | `pulse_new_172.16.0.0/24` | `Miri_DTS_192.168.6.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 105 | `190` | `trust` | `untrust` | `pulse_new_172.16.0.0/24` | `DPSB_TK_new_192.168.7.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Clone of 188 |
| 106 | `178` | `untrust` | `trust` | `DPSB_CKJ_192.168.14.0/24` | `pulse_new_172.16.0.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Reverse of 162 |
| 107 | `164` | `trust` | `untrust` | `pulse_new_172.16.0.0/24` | `DOSSB_Miri-192.168.5.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Clone of 143 |
| 108 | `171` | `untrust` | `trust` | `DOSSB_Miri-192.168.5.0/24` | `pulse_new_172.16.0.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Reverse of 164 |
| 109 | `216` | `untrust` | `trust` | `DOSSB_Miri-192.168.5.0/24` | `pulse_new_172.16.0.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Clone of 171 |
| 110 | `224` | `untrust` | `trust` | `DOSSB_KK-192.168.13.0/24` | `pulse_new_172.16.0.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Clone of 216 |
| 111 | `226` | `trust` | `untrust` | `pulse_new_172.16.0.0/24` | `DOSSB_KK-192.168.13.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Reverse of 224 |
| 112 | `225` | `untrust` | `trust` | `DOSSB_KK-192.168.13.0/24` | `pulse_new_172.16.0.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Clone of 224 |
| 113 | `227` | `trust` | `untrust` | `pulse_new_172.16.0.0/24` | `DOSSB_KK-192.168.13.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Reverse of 225 |
| 114 | `173` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `DPSB_CKJ_192.168.14.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 51 |
| 115 | `201` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `DOSSB_KSB-192.168.4.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 173 |
| 116 | `205` | `untrust` | `dmz` | `DOSSB_KSB-192.168.4.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio` | Reverse of 201 |
| 117 | `230` | `untrust` | `dmz` | `DOSSB_KK-192.168.13.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Clone of 205 |
| 118 | `231` | `untrust` | `dmz` | `DOSSB_KK-192.168.13.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Clone of 230 |
| 119 | `176` | `trust` | `untrust` | `trust_dhcp` | `DPSB_CKJ_192.168.14.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | Clone of 129 |
| 120 | `242` | `trust` | `untrust` | `trust_dhcp` | `DPSB_CKJ_192.168.14.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_high_security` | Clone of 129 (Copy of 176) |
| 121 | `203` | `trust` | `untrust` | `trust_dhcp` | `DOSSB_KSB-192.168.4.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | Clone of 176 |
| 122 | `245` | `trust` | `untrust` | `trust_dhcp` | `DOSSB_KSB-192.168.4.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_high_security` | Clone of 176 (Copy of 203) |
| 123 | `131` | `trust` | `untrust` | `trust_dhcp` | `DPSB_CKJ_192.168.14.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | Clone of 110 |
| 124 | `241` | `trust` | `untrust` | `trust_dhcp` | `DPSB_CKJ_192.168.14.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_high_security` | Clone of 110 (Copy of 131) |
| 125 | `240` | `trust` | `untrust` | `trust_dhcp` | `DPSB_TK_new_192.168.7.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | Clone of 131 (Copy of 195) |
| 126 | `195` | `trust` | `untrust` | `trust_dhcp` | `DPSB_TK_new_192.168.7.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_high_security` | Clone of 131 |
| 127 | `196` | `trust` | `untrust` | `trust_dhcp` | `DPSB_TK_new_192.168.7.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | Clone of 195 |
| 128 | `246` | `trust` | `untrust` | `trust_dhcp` | `DPSB_TK_new_192.168.7.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_high_security` | Clone of 195 (Copy of 196) |
| 129 | `167` | `untrust` | `untrust` | `SSL_VPN_HQ_new` | `ICT_HQ_192.168.111.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | Clone of 131 |
| 130 | `236` | `untrust` | `untrust` | `SSL_VPN_HQ_new` | `ICT_HQ_192.168.111.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | - |
| 131 | `169` | `untrust` | `trust` | `ICT_HQ_192.168.111.0/24` | `Trust-192.168.0.0/23` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | Reverse of 167 |
| 132 | `133` | `untrust` | `dmz` | `ICT_HQ_192.168.111.0/24, DR-192.168.43.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | Clone of 169 |
| 133 | `247` | `untrust` | `trust` | `ICT_HQ_192.168.111.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 169 (Copy of 133) |
| 134 | `248` | `trust` | `untrust` | `FAZ200F_192.168.30.2` | `ICT_HQ_192.168.111.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 169 (Copy of 133) (Copy of 247) (Reverse of 247) |
| 135 | `165` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `DR-192.168.43.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | Reverse of 133 |
| 136 | `184` | `trust` | `untrust` | `Trust-192.168.0.0/23` | `DR-192.168.43.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | Clone of 165 |
| 137 | `182` | `untrust` | `dmz` | `DPSB_CKJ_192.168.14.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default_WF_deleum_webfilter_APP_deleum_application_cont` | Clone of 52 |
| 138 | `82` | `untrust` | `dmz` | `Miri_WS-192.168.8.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 139 | `211` | `untrust` | `dmz` | `Miri_WS-192.168.8.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Clone of 82 |
| 140 | `168` | `untrust` | `trust` | `Miri_WS-192.168.8.0/24` | `pulse_new_172.16.0.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 141 | `210` | `untrust` | `trust` | `Miri_WS-192.168.8.0/24` | `pulse_new_172.16.0.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Clone of 168 |
| 142 | `83` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `Miri_WS-192.168.8.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Reverse of 82 |
| 143 | `207` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `Miri_WS-192.168.8.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 83 |
| 144 | `134` | `trust` | `untrust` | `trust_dhcp` | `Miri_WS-192.168.8.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | Clone of 112 |
| 145 | `112` | `trust` | `untrust` | `trust_dhcp` | `Miri_WS-192.168.8.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_high_security` | - |
| 146 | `238` | `trust` | `untrust` | `trust_dhcp` | `Miri_WS-192.168.8.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | Clone of 112 (Copy of 212) |
| 147 | `212` | `trust` | `untrust` | `trust_dhcp` | `Miri_WS-192.168.8.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_high_security` | Clone of 112 |
| 148 | `232` | `trust` | `untrust` | `trust_dhcp` | `DOSSB_KK-192.168.13.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | Clone of 212 |
| 149 | `244` | `trust` | `untrust` | `trust_dhcp` | `DOSSB_KK-192.168.13.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_high_security` | Clone of 212 (Copy of 232) |
| 150 | `239` | `trust` | `untrust` | `trust_dhcp` | `DOSSB_KK-192.168.13.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | Clone of 232 (Copy of 233) |
| 151 | `233` | `trust` | `untrust` | `trust_dhcp` | `DOSSB_KK-192.168.13.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_high_security` | Clone of 232 |
| 152 | `20` | `dmz` | `trust` | `Server-192.168.42.0/24` | `Biometric-192.168.10.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | - | - |
| 153 | `135` | `trust` | `dmz` | `Biometric-192.168.10.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_default` | Clone of 25 |
| 154 | `25` | `trust` | `dmz` | `Biometric-192.168.10.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_AV_default_IPS_high_security_WF_deleum_webfilter_APP_deleum` | Reverse of 20 |
| 155 | `136` | `trust` | `trust` | `Biometric-192.168.10.0/24` | `Trust-192.168.0.0/23` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Clone of 26 |
| 156 | `26` | `trust` | `trust` | `Biometric-192.168.10.0/24` | `Trust-192.168.0.0/23` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 157 | `21` | `dmz` | `trust` | `Server-192.168.42.0/24` | `HQ_Wifi_User-10.10.10.0/23` | `-` | `PING, TRACEROUTE` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_AV_default_IPS_high_security_WF_deleum_webfilter_APP_deleum` | - |
| 158 | `22` | `dmz` | `trust` | `Server-192.168.42.0/24` | `Trust-192.168.0.0/23` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 159 | `138` | `trust` | `dmz` | `trust_fixed_IP` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Clone of 23 |
| 160 | `119` | `trust` | `trust` | `Trust-192.168.0.0/23` | `Biometric-192.168.10.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Clone of 34 |
| 161 | `34` | `trust` | `trust` | `Trust-192.168.0.0/23` | `Biometric-192.168.10.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio` | - |
| 162 | `267` | `dmz` | `untrust` | `server_no_internet` | `croudstrike1, croudstrike2` | `-` | `HTTPS` | 🟢 `ALLOW` | Active | - |  (Copy of 185) (Copy of ) |
| 163 | `185` | `dmz` | `untrust` | `server_no_internet` | `any` | `-` | `ALL` | 🔴 `DENY` | Active | - | - |
| 164 | `18` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `any` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | - |
| 165 | `124` | `trust` | `trust` | `trust_dhcp` | `DOSSB_Labuan_Leased_Line-10.10.2.0/24, DOSSB_Labuan-192.168.2.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_high_security` | Clone of 27 |
| 166 | `149` | `untrust` | `trust` | `any` | `secure.deleum.com_175.143.1.50` | `-` | `HTTPS` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_high_security_APP_deleum_application_control` | Clone of 37 |
| 167 | `MiniOrange_LDAPgw` | `untrust` | `dmz` | `miniOrange_Cloud` | `eformproxy_60.53.219.66` | `-` | `HTTPS, port_8081` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_default` | - |
| 168 | `36` | `untrust` | `dmz` | `any` | `unifi_VIP_server` | `-` | `Web Access` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security_APP_deleum_application_control` | - |
| 169 | `61` | `untrust` | `dmz` | `SSL_VPN_HQ` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 170 | `64` | `untrust` | `trust` | `SSL_VPN_HQ` | `DOSSB_Labuan_Leased_Line-10.10.2.0/24, DOSSB_Labuan-192.168.2.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | - | - |
| 171 | `175` | `untrust` | `untrust` | `SSL_VPN_HQ` | `DPSB_CKJ_192.168.14.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 69 |
| 172 | `234` | `untrust` | `untrust` | `SSL_VPN_HQ` | `DOSSB_KK-192.168.13.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 175 |
| 173 | `235` | `untrust` | `untrust` | `SSL_VPN_HQ` | `DOSSB_KK-192.168.13.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 234 |
| 174 | `202` | `untrust` | `untrust` | `SSL_VPN_HQ` | `DOSSB_KSB-192.168.4.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 175 |
| 175 | `108` | `untrust` | `untrust` | `SSL_VPN_HQ` | `DPSB_CKJ_192.168.14.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | - |
| 176 | `193` | `untrust` | `untrust` | `SSL_VPN_HQ` | `DPSB_TK_new_192.168.7.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 108 |
| 177 | `271` | `untrust` | `untrust` | `SSL_VPN_HQ` | `Miri_DTS_192.168.6.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | - |
| 178 | `283` | `untrust` | `untrust` | `SSL_VPN_HQ` | `Bintulu1_192.168.11.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 179 | `294` | `untrust` | `untrust` | `SSL_VPN_HQ` | `Bintulu1_192.168.11.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 180 | `290` | `untrust` | `untrust` | `SSL_VPN_HQ` | `Bintulu2-192.168.3.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `Migrated_Profiles` | - |
| 181 | `300` | `untrust` | `untrust` | `SSL_VPN_HQ` | `Bintulu2-192.168.3.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `Migrated_Profiles` |  (Copy of 290) (Copy of ) |
| 182 | `278` | `untrust` | `untrust` | `SSL_VPN_HQ` | `Miri_DTS_192.168.6.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | - |
| 183 | `194` | `untrust` | `untrust` | `SSL_VPN_HQ` | `DPSB_TK_new_192.168.7.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 193 |
| 184 | `118` | `untrust` | `untrust` | `SSL_VPN_HQ` | `DOSSB_Miri-192.168.5.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 70 |
| 185 | `214` | `untrust` | `untrust` | `SSL_VPN_HQ` | `DOSSB_Miri-192.168.5.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 118 |
| 186 | `84` | `untrust` | `untrust` | `SSL_VPN_HQ` | `Miri_WS-192.168.8.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | - |
| 187 | `208` | `untrust` | `untrust` | `SSL_VPN_HQ` | `Miri_WS-192.168.8.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 84 |
| 188 | `62` | `untrust` | `trust` | `SSL_VPN_HQ` | `Trust-192.168.0.0/23` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 189 | `145` | `untrust` | `trust` | `SSL_VPN_HQ` | `pulse_new_172.16.0.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 62 |
| 190 | `144` | `untrust` | `untrust` | `SSL_VPN_HQ` | `DOSSB_KSB-192.168.4.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 74 |
| 191 | `63` | `untrust` | `untrust` | `SSL_VPN_HQ` | `any` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | - |
| 192 | `75` | `untrust` | `trust` | `SSL_VPN_HQ` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | - |
| 193 | `78` | `trust` | `trust` | `HQ_Wifi_User-10.10.10.0/23` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_high_security` | - |
| 194 | `123` | `trust` | `trust` | `trust_dhcp` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Clone of 76 |
| 195 | `76` | `trust` | `trust` | `trust_dhcp` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 196 | `77` | `dmz` | `trust` | `Server-192.168.42.0/24` | `FAZ200F_192.168.30.2` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | - |
| 197 | `79` | `trust` | `untrust` | `FAZ200F_192.168.30.2` | `any` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio` | - |
| 198 | `vpn_to_CKJ_unifi_local` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `DPSB_CKJ_192.168.14.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | VPN: to_CKJ_unifi (Created by VPN wizard) |
| 199 | `191` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `DPSB_TK_new_192.168.7.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of vpn_to_CKJ_unifi_local |
| 200 | `198` | `untrust` | `dmz` | `DPSB_TK_new_192.168.7.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Reverse of 191 |
| 201 | `192` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `DPSB_TK_new_192.168.7.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 191 |
| 202 | `197` | `untrust` | `dmz` | `DPSB_TK_new_192.168.7.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Reverse of 192 |
| 203 | `vpn_to_CKJ_unifi_remote` | `untrust` | `dmz` | `DPSB_CKJ_192.168.14.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | VPN: to_CKJ_unifi (Created by VPN wizard) |
| 204 | `141` | `untrust` | `dmz` | `DOSSB_KSB-192.168.4.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of vpn_to_CKJ_unifi_remote |
| 205 | `142` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `DOSSB_KSB-192.168.4.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Reverse of 141 |
| 206 | `146` | `trust` | `untrust` | `trust_dhcp` | `DOSSB_KSB-192.168.4.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | Clone of 142 |
| 207 | `243` | `trust` | `untrust` | `trust_dhcp` | `DOSSB_KSB-192.168.4.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | Clone of 142 (Copy of 146) |
| 208 | `143` | `trust` | `untrust` | `pulse_new_172.16.0.0/24` | `DOSSB_KSB-192.168.4.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | Clone of 142 |
| 209 | `vpn_to_DOSSB_Miri_local` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `DOSSB_Miri-192.168.5.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | VPN: to_DOSSB_Miri (Created by VPN wizard) |
| 210 | `213` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `DOSSB_Miri-192.168.5.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of vpn_to_DOSSB_Miri_local |
| 211 | `228` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `DOSSB_KK-192.168.13.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 213 |
| 212 | `229` | `dmz` | `untrust` | `Server-192.168.42.0/24` | `DOSSB_KK-192.168.13.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Clone of 228 |
| 213 | `115` | `untrust` | `dmz` | `DOSSB_Miri-192.168.5.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | - | Reverse of vpn_to_DOSSB_Miri_local |
| 214 | `217` | `untrust` | `dmz` | `DOSSB_Miri-192.168.5.0/24` | `Server-192.168.42.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | Clone of 115 |
| 215 | `132` | `trust` | `untrust` | `trust_dhcp` | `DOSSB_Miri-192.168.5.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | Clone of 116 |
| 216 | `116` | `trust` | `untrust` | `trust_dhcp` | `DOSSB_Miri-192.168.5.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_high_security` | - |
| 217 | `237` | `trust` | `untrust` | `trust_dhcp` | `DOSSB_Miri-192.168.5.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_high_security` | Clone of 116 (Copy of 218) |
| 218 | `218` | `trust` | `untrust` | `trust_dhcp` | `DOSSB_Miri-192.168.5.0/24` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | `SPG_IPS_high_security` | Clone of 116 |
| 219 | `vpn_toDOSSB_KSB_remote` | `untrust` | `untrust` | `toDOSSB_KSB_remote` | `toDOSSB_KSB_local` | `-` | `ALL` | 🟢 `ALLOW` | ⚠️ *Disabled* | - | VPN: toDOSSB_KSB (Created by VPN wizard) |
| 220 | `219` | `trust` | `untrust` | `pulse_new_172.16.0.0/24` | `DOSSB_Miri-192.168.5.0/24` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_IPS_default` | - |
| 221 | `266` | `trust` | `untrust` | `DBATT_192.168.10.7, CCTVnvr_192.168.10.8` | `any` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_AV_default_IPS_high_security_WF_deleum_webfilter_APP_deleum` | - |
| 222 | `FortiClient_IPSEC_Internet` | `untrust` | `untrust` | `any` | `any` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_WF_deleum_webfilter_APP_deleum_application_control` | VPN: Test_IPSEC_2 (Created by VPN wizard) (Copy of vpn_Test_IPSEC_2_remote_1) (Copy of ) |
| 223 | `FortiClient_IPSEC_Deny` | `untrust` | `dmz` | `any` | `any` | `-` | `ALL` | 🔴 `DENY` | Active | - |  (Copy of FortiClient_IPSEC) (Copy of ) |
| 224 | `FortiClient_IPSEC` | `untrust` | `dmz` | `any` | `any` | `-` | `ALL` | 🟢 `ALLOW` | Active | `SPG_AV_default_IPS_high_security_WF_deleum_webfilter_APP_deleum` | - |

### NAT Rules

| Rule Name | Type | From Zone | To Zone | Source | Destination | Translated Source | Translated Dest | Service | Description |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `unifi_60.53.219.65` | `SOURCE` | `any` | `any` | `any` | `any` | `60.53.219.65` | - | `any` | - |
| `deleumeform.com_60.53.219.68` | `DESTINATION` | `virtual-wan-link` | `any` | `any` | `deleumeform.com_60.53.219.68` | - | `192.168.42.26` | `any` | - |
| `deleumintranet.com_60.53.219.67` | `DESTINATION` | `virtual-wan-link` | `any` | `any` | `deleumintranet.com_60.53.219.67` | - | `192.168.42.22` | `any` | - |
| `eformproxy_60.53.219.66` | `DESTINATION` | `virtual-wan-link` | `any` | `any` | `eformproxy_60.53.219.66` | - | `192.168.42.28` | `any` | - |
| `ess.deleum.com_60.53.219.69` | `DESTINATION` | `virtual-wan-link` | `any` | `any` | `ess.deleum.com_60.53.219.69` | - | `192.168.42.10` | `any` | - |
| `secure.deleum.com_175.143.1.50` | `DESTINATION` | `virtual-wan-link` | `any` | `any` | `secure.deleum.com_175.143.1.50` | - | `172.16.0.100` | `any` | - |

## 6. 📄 Raw Canonical Intermediate Representation (JSON)

This section provides the full, machine-readable Intermediate Representation (`IRConfig`) JSON export for pipeline automation and external audit validation.

<details><summary><b>View Full Normalized JSON Data</b> - Click to expand</summary>

```json
{
  "metadata": {
    "hostname": "deleumHQ",
    "source_vendor": "fortigate",
    "target_vendor": "Palo Alto Networks (PAN-OS / Panorama)",
    "migration_timestamp": "2026-08-20T13:02:16.268395Z"
  },
  "zones": [
    {
      "name": "untrust",
      "interfaces": [
        "ha",
        "port1",
        "port3",
        "port7",
        "port12",
        "port13",
        "port14",
        "port15",
        "port16",
        "x1",
        "x2",
        "x3",
        "x4",
        "x5",
        "x6",
        "x7",
        "x8",
        "port17",
        "port18",
        "port19",
        "port20",
        "modem",
        "naf.root",
        "l2t.root",
        "ssl.root",
        "toMiriWH",
        "to_CKJ_unifi",
        "to_DOSSB_Miri",
        "toDOSSB_KSB",
        "toIT_fromHQ",
        "toCKJ_secondary",
        "to_TKY",
        "toTKY_secondary",
        "toKSB_secondary",
        "MiriWHsecondary",
        "Miri_secondary",
        "toKK_secondary",
        "to_KK",
        "toLabuan",
        "toLabuan_second",
        "toIT_secondary",
        "maxis",
        "toMiri_DTS",
        "MiriDTS_second",
        "toBintulu1",
        "toBintulu2",
        "Bintulu1_second",
        "Bintulu2_second",
        "FortiClient"
      ],
      "description": null
    },
    {
      "name": "trust",
      "interfaces": [
        "mgmt",
        "port5",
        "port6",
        "port8",
        "port9",
        "port11",
        "HQ_Vlan20",
        "HQ_Vlan70"
      ],
      "description": null
    },
    {
      "name": "virtual-wan-link",
      "interfaces": [
        "port2",
        "port4",
        "unifi_port1",
        "unifi2_Vlan",
        "unifi3"
      ],
      "description": null
    },
    {
      "name": "dmz",
      "interfaces": [
        "port10"
      ],
      "description": null
    }
  ],
  "interfaces": [
    {
      "name": "ha",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "mgmt",
      "zone": "trust",
      "ip": "192.168.100.99/24",
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "port1",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "port2",
      "zone": "virtual-wan-link",
      "ip": "172.16.1.100/24",
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": "untrust 300MB",
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "port3",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "port4",
      "zone": "virtual-wan-link",
      "ip": "103.27.106.130/29",
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": "Metro-E_Internet 20MB",
      "status": false,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "port5",
      "zone": "trust",
      "ip": "192.168.30.1/24",
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": "FAZ200F_192.168.30.0/24",
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "port6",
      "zone": "trust",
      "ip": "10.10.10.1/23",
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": "wifi_user_10.10.10.0/23",
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "port7",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "port8",
      "zone": "trust",
      "ip": "192.168.10.254/24",
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": "Biometric_192.168.10.0/24",
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "port9",
      "zone": "trust",
      "ip": "192.168.0.100/23",
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": "trust_192.168.0.0/23",
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "port10",
      "zone": "dmz",
      "ip": "192.168.42.30/24",
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": "server_192.168.42.0/24",
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "port11",
      "zone": "trust",
      "ip": "172.16.0.1/24",
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": "Pulse2_172.16.0.0/24",
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "port12",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "port13",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "port14",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "port15",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "port16",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "x1",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "x2",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "x3",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "x4",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "x5",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "x6",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "x7",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "x8",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "port17",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "port18",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "port19",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "port20",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "modem",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": false,
      "vlanid": null,
      "pppoe_mode": "pppoe",
      "pppoe_username": null
    },
    {
      "name": "naf.root",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "l2t.root",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "ssl.root",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": null,
      "tag": null,
      "alias": "SSL VPN interface",
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "unifi_port1",
      "zone": "virtual-wan-link",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "port1",
      "tag": 500,
      "alias": null,
      "status": true,
      "vlanid": 500,
      "pppoe_mode": "pppoe",
      "pppoe_username": "deleum05@unifibiz"
    },
    {
      "name": "HQ_Vlan20",
      "zone": "trust",
      "ip": "10.10.2.1/24",
      "description": null,
      "management_profile": null,
      "parent": "port3",
      "tag": 20,
      "alias": "Labuan-10.10.2.1/24",
      "status": true,
      "vlanid": 20,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "HQ_Vlan70",
      "zone": "trust",
      "ip": "10.10.7.1/24",
      "description": null,
      "management_profile": null,
      "parent": "port3",
      "tag": 70,
      "alias": "DPSB_TK_10.10.7.1/24",
      "status": true,
      "vlanid": 70,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "toMiriWH",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi_port1",
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "to_CKJ_unifi",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi_port1",
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "to_DOSSB_Miri",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi_port1",
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "unifi2_Vlan",
      "zone": "virtual-wan-link",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "port12",
      "tag": 500,
      "alias": null,
      "status": true,
      "vlanid": 500,
      "pppoe_mode": "pppoe",
      "pppoe_username": "delcom.oilfieldsb1@unifibiz"
    },
    {
      "name": "toDOSSB_KSB",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi_port1",
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "toIT_fromHQ",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi_port1",
      "tag": null,
      "alias": null,
      "status": false,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "toCKJ_secondary",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi2_Vlan",
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "unifi3",
      "zone": "virtual-wan-link",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "port7",
      "tag": 500,
      "alias": null,
      "status": true,
      "vlanid": 500,
      "pppoe_mode": "pppoe",
      "pppoe_username": "delcom@unifibiz"
    },
    {
      "name": "to_TKY",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi_port1",
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "toTKY_secondary",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi2_Vlan",
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "toKSB_secondary",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi2_Vlan",
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "MiriWHsecondary",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi2_Vlan",
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "Miri_secondary",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi2_Vlan",
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "toKK_secondary",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi2_Vlan",
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "to_KK",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi_port1",
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "toLabuan",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi_port1",
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "toLabuan_second",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi2_Vlan",
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "toIT_secondary",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi2_Vlan",
      "tag": null,
      "alias": null,
      "status": false,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "maxis",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "port13",
      "tag": 500,
      "alias": null,
      "status": true,
      "vlanid": 500,
      "pppoe_mode": "pppoe",
      "pppoe_username": "95187@sme.maxis.com.my"
    },
    {
      "name": "toMiri_DTS",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi_port1",
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "MiriDTS_second",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi2_Vlan",
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "toBintulu1",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi_port1",
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "toBintulu2",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi_port1",
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "Bintulu1_second",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi2_Vlan",
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "Bintulu2_second",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi2_Vlan",
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    },
    {
      "name": "FortiClient",
      "zone": "untrust",
      "ip": null,
      "description": null,
      "management_profile": null,
      "parent": "unifi2_Vlan",
      "tag": null,
      "alias": null,
      "status": true,
      "vlanid": null,
      "pppoe_mode": null,
      "pppoe_username": null
    }
  ],
  "addresses": [
    {
      "name": "SSLVPN_TUNNEL_ADDR1",
      "type": "range",
      "subnet": null,
      "ip_range_start": "10.212.134.200",
      "ip_range_end": "10.212.134.230",
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "Biometric-192.168.10.0/24",
      "type": "network",
      "subnet": "192.168.10.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "DPSB_CKJ_192.168.14.0/24",
      "type": "network",
      "subnet": "192.168.14.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "Miri_DTS_192.168.6.0/24",
      "type": "network",
      "subnet": "192.168.6.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "DPSB_Miri-192.168.9.0/24",
      "type": "network",
      "subnet": "192.168.9.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "DPSB_Miri_Leased_Line-10.10.9.0/24",
      "type": "network",
      "subnet": "10.10.9.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "DPSB_TK_new_192.168.7.0/24",
      "type": "network",
      "subnet": "192.168.7.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "DPSB_TK_wifi_10.10.77.0/24",
      "type": "network",
      "subnet": "10.10.77.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "DPSB_Teluk_Kalong_Leased_Line-10.10.7.0/24",
      "type": "network",
      "subnet": "10.10.7.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "DPSB_bintulu-192.168.11.0/24",
      "type": "network",
      "subnet": "192.168.11.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "DR-192.168.43.0/24",
      "type": "network",
      "subnet": "192.168.43.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "DRSSB_Bintulu-192.168.12.0/24",
      "type": "network",
      "subnet": "192.168.12.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "Bintulu2-192.168.3.0/24",
      "type": "network",
      "subnet": "192.168.3.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "DRSSB_Kajang_Leased_Line-10.10.3.0/24",
      "type": "network",
      "subnet": "10.10.3.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "HQ_Wifi_User-10.10.10.0/23",
      "type": "network",
      "subnet": "10.10.10.0/23",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "ICT_HQ_192.168.111.0/24",
      "type": "network",
      "subnet": "192.168.111.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "DOSSB_KSB-192.168.4.0/24",
      "type": "network",
      "subnet": "192.168.4.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "DOSSB_KK-192.168.13.0/24",
      "type": "network",
      "subnet": "192.168.13.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "DOSSB_Labuan-192.168.2.0/24",
      "type": "network",
      "subnet": "192.168.2.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "DOSSB_Labuan_Leased_Line-10.10.2.0/24",
      "type": "network",
      "subnet": "10.10.2.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "DOSSB_Miri-192.168.5.0/24",
      "type": "network",
      "subnet": "192.168.5.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "DOSSB_Miri_Leased_Line-10.10.5.0/24",
      "type": "network",
      "subnet": "10.10.5.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "Miri_WS-192.168.8.0/24",
      "type": "network",
      "subnet": "192.168.8.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "Peplink_175.138.64.170",
      "type": "network",
      "subnet": "175.138.64.170/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "Metro-E_Internet",
      "type": "network",
      "subnet": "103.27.106.128/29",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "SSL_VPN_HQ",
      "type": "network",
      "subnet": "10.10.100.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "Server-192.168.42.0/24",
      "type": "network",
      "subnet": "192.168.42.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "Trust-192.168.0.0/23",
      "type": "network",
      "subnet": "192.168.0.0/23",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "unifi",
      "type": "network",
      "subnet": "60.53.219.65/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "pulse secure_local-172.16.1.0/24",
      "type": "network",
      "subnet": "172.16.1.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "peplink WAN IP range",
      "type": "network",
      "subnet": "172.16.0.0/16",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "ariba",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "ariba.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "SSL_VPN_HQ_new",
      "type": "network",
      "subnet": "10.10.100.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "FAZ200F_192.168.30.2",
      "type": "network",
      "subnet": "192.168.30.2/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "ps.compliance.protection.outlook.com",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "ps.compliance.protection.outlook.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "microsoft1",
      "type": "network",
      "subnet": "40.92.0.0/15",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "microsoft2",
      "type": "network",
      "subnet": "40.107.0.0/16",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "microsoft3",
      "type": "network",
      "subnet": "52.100.0.0/14",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "microsoft4",
      "type": "network",
      "subnet": "52.238.78.88/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "microsoft5",
      "type": "network",
      "subnet": "104.47.0.0/17",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "jobsmalaysia.gov.my",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "jobsmalaysia.gov.my",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "192.168.1.5/32",
      "type": "network",
      "subnet": "192.168.1.5/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "to_CKJ_unifi_local_subnet_1",
      "type": "network",
      "subnet": "192.168.42.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "to_CKJ_unifi_remote_subnet_1",
      "type": "network",
      "subnet": "192.168.14.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "DOSSB_Labuan_wifi_10.10.22.0/24",
      "type": "network",
      "subnet": "10.10.22.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "Labuan_172.16.2.0/24_temp",
      "type": "network",
      "subnet": "172.16.2.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "DPSB_TK 172.16.7.0/24_temp",
      "type": "network",
      "subnet": "172.16.7.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "trust_fixed_IP",
      "type": "range",
      "subnet": null,
      "ip_range_start": "192.168.0.1",
      "ip_range_end": "192.168.0.100",
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "trust_dhcp_reserved",
      "type": "range",
      "subnet": null,
      "ip_range_start": "192.168.1.249",
      "ip_range_end": "192.168.1.250",
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "ceac.state.gov",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "ceac.state.gov",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "DBATT_192.168.10.7",
      "type": "network",
      "subnet": "192.168.10.7/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "India IP",
      "type": "geo",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": "unknown",
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "IPS_malaysia IP",
      "type": "geo",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": "unknown",
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "pulse_new_172.16.0.0/24",
      "type": "network",
      "subnet": "172.16.0.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "trust_dhcp",
      "type": "range",
      "subnet": null,
      "ip_range_start": "192.168.0.101",
      "ip_range_end": "192.168.1.250",
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "vpn.deleum.com",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "vpn.deleum.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "secure.deleum.com",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "secure.deleum.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "secure.deleum.com_publicIP",
      "type": "network",
      "subnet": "175.143.1.50/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "vpn.deleum.com_publicIP",
      "type": "network",
      "subnet": "60.53.219.70/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "vpnPulse_175.138.64.172",
      "type": "network",
      "subnet": "175.138.64.172/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "Malaysia IP",
      "type": "geo",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": "unknown",
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "deleum.com_public_IP",
      "type": "network",
      "subnet": "60.53.219.66/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "VC_pc_192.168.0.133",
      "type": "network",
      "subnet": "192.168.0.133/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "Owl_VC",
      "type": "network",
      "subnet": "10.10.10.58/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "AGM2022_1",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "apc01.safelinks.protection.outlook.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "AGM2022_2",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "us02web.zoom.us",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "AGM2022_3",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "app-uat.tiih.com.my",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "PSA_172.16.0.100",
      "type": "network",
      "subnet": "172.16.0.100/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "login.microsoftonline.com",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "login.microsoftonline.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "login.microsoft.com",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "login.microsoft.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "login.windows.net",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "login.windows.net",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "gmail.com",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "gmail.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "wildcard.google.com",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.google.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "wildcard.dropbox.com",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.dropbox.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "metroE_test_192.168.0.80",
      "type": "network",
      "subnet": "192.168.0.80/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "ipad 1",
      "type": "mac",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": "00:00:00:00:00:00",
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": "Created for DHCP Reservation",
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "ipad 2",
      "type": "mac",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": "00:00:00:00:00:00",
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": "Created for DHCP Reservation",
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "TimeAtt-192.168.10.7",
      "type": "host",
      "subnet": "192.168.10.7/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "caterpillar",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "securemail.cat.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "securemail.cat.com",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "securemail.cat.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "test192.168.0.216",
      "type": "network",
      "subnet": "192.168.0.216/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "test192.168.0.140",
      "type": "network",
      "subnet": "192.168.0.140/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "test_192.168.0.147",
      "type": "network",
      "subnet": "192.168.0.147/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "s2b.standardchartered.com",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "s2b.standardchartered.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "mrates.maybank.com.my",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "mrates.maybank.com.my",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "hsbcnet.com",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "hsbcnet.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "qtn.mac_00:00:00:00:00:00",
      "type": "mac",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": "00:00:00:00:00:00",
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": "Quarantine dummy MAC to keep the addrgrp",
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "efiling.rd.go.th",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "efiling.rd.go.th",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "server_192.168.42.17",
      "type": "network",
      "subnet": "192.168.42.17/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "server_192.168.42.18",
      "type": "network",
      "subnet": "192.168.42.18/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "server_192.168.42.19",
      "type": "network",
      "subnet": "192.168.42.19/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "server_192.168.42.6",
      "type": "network",
      "subnet": "192.168.42.6/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "croudstrike1",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "ts01-gyr-maverick.cloudsink.net",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "croudstrike2",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "lfodown01-gyr-maverick.cloudsink.net",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "server_192.168.42.12",
      "type": "network",
      "subnet": "192.168.42.12/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "server_192.168.42.9",
      "type": "network",
      "subnet": "192.168.42.17/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "Bintulu1_192.168.11.0/24",
      "type": "network",
      "subnet": "192.168.11.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "KaiZenHR",
      "type": "fqdn",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "ess.deleum.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "DBFS_192.168.42.25",
      "type": "network",
      "subnet": "192.168.42.25/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "Deleum_AD",
      "type": "network",
      "subnet": "192.168.42.43/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "Test_IPSEC2_range",
      "type": "range",
      "subnet": null,
      "ip_range_start": "10.10.100.120",
      "ip_range_end": "10.10.100.130",
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": "VPN: Test_IPSEC2 (Created by VPN wizard)",
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "Test_IPSEC_2_range",
      "type": "range",
      "subnet": null,
      "ip_range_start": "10.10.100.120",
      "ip_range_end": "10.10.100.130",
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": "VPN: Test_IPSEC_2 (Created by VPN wizard)",
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "miniOrange_52.55.147.107",
      "type": "network",
      "subnet": "52.55.147.107/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "miniOrange_52.86.38.163",
      "type": "network",
      "subnet": "52.86.38.163/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "miniOrange_54.165.245.227",
      "type": "network",
      "subnet": "54.165.245.227/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "LDAPgateway",
      "type": "network",
      "subnet": "192.168.42.28/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "CCTVnvr_192.168.10.8",
      "type": "network",
      "subnet": "192.168.10.8/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "192.168.0.70",
      "type": "network",
      "subnet": "192.168.0.70/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "SangforCP_192.24.64.0/24",
      "type": "network",
      "subnet": "192.24.64.0/24",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "server_192.168.42.60",
      "type": "network",
      "subnet": "192.168.42.60/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "all_hosts",
      "type": "host",
      "subnet": "224.0.0.1/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": true
    },
    {
      "name": "all_routers",
      "type": "host",
      "subnet": "224.0.0.2/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": true
    },
    {
      "name": "Bonjour",
      "type": "host",
      "subnet": "224.0.0.251/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": true
    },
    {
      "name": "cdn-apple",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.cdn-apple.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "mzstatic-apple",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.mzstatic.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "google-play",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.play.google.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "update.microsoft.com",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.update.microsoft.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "swscan.apple.com",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.swscan.apple.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "autoupdate.opera.com",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.autoupdate.opera.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "adobe",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.adobe.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "Adobe Login",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.adobelogin.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "android",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.android.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "apple",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.apple.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "appstore",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.appstore.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "auth.gfx.ms",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.auth.gfx.ms",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "citrix",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.citrixonline.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "dropbox.com",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.dropbox.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "eease",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.eease.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "firefox update server",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "aus*.mozilla.org",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "fortinet",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.fortinet.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "googleapis.com",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.googleapis.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "google-drive",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.drive.google.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "google-play2",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.ggpht.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "google-play3",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.books.google.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "Gotomeeting",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.gotomeeting.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "icloud",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.icloud.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "itunes",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.itunes.apple.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "microsoft",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.microsoft.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "skype",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.messenger.live.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "softwareupdate.vmware.com",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.softwareupdate.vmware.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "verisign",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.verisign.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "Windows update 2",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.windowsupdate.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "live.com",
      "type": "wildcard",
      "subnet": null,
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": "*.live.com",
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": null,
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "deleumeform.com_60.53.219.68",
      "type": "host",
      "subnet": "60.53.219.68/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": "Auto-generated Address for VIP deleumeform.com_60.53.219.68",
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "deleumintranet.com_60.53.219.67",
      "type": "host",
      "subnet": "60.53.219.67/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": "Auto-generated Address for VIP deleumintranet.com_60.53.219.67",
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "eformproxy_60.53.219.66",
      "type": "host",
      "subnet": "60.53.219.66/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": "Auto-generated Address for VIP eformproxy_60.53.219.66",
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "ess.deleum.com_60.53.219.69",
      "type": "host",
      "subnet": "60.53.219.69/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": "Auto-generated Address for VIP ess.deleum.com_60.53.219.69",
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    },
    {
      "name": "secure.deleum.com_175.143.1.50",
      "type": "host",
      "subnet": "175.143.1.50/32",
      "ip_range_start": null,
      "ip_range_end": null,
      "fqdn": null,
      "mac": null,
      "geo_code": null,
      "wildcard_mask": null,
      "dynamic_filter": null,
      "tag_name": null,
      "parse_error": null,
      "raw_value": null,
      "description": "Auto-generated Address for VIP secure.deleum.com_175.143.1.50",
      "tags": [],
      "is_ipv6": false,
      "is_multicast": false
    }
  ],
  "address_groups": [
    {
      "name": "EMS_ALL_UNKNOWN_CLIENTS",
      "members": [],
      "description": "Migrated FortiClient EMS Dynamic Tag: EMS_ALL_UNKNOWN_CLIENTS",
      "is_dynamic": true,
      "dynamic_filter": "'EMS_ALL_UNKNOWN_CLIENTS'",
      "tags": [
        "EMS_ALL_UNKNOWN_CLIENTS"
      ]
    },
    {
      "name": "EMS_ALL_UNMANAGEABLE_CLIENTS",
      "members": [],
      "description": "Migrated FortiClient EMS Dynamic Tag: EMS_ALL_UNMANAGEABLE_CLIENTS",
      "is_dynamic": true,
      "dynamic_filter": "'EMS_ALL_UNMANAGEABLE_CLIENTS'",
      "tags": [
        "EMS_ALL_UNMANAGEABLE_CLIENTS"
      ]
    },
    {
      "name": "FCTEMS_ALL_FORTICLOUD_SERVERS",
      "members": [],
      "description": "Migrated FortiClient EMS Dynamic Tag: FCTEMS_ALL_FORTICLOUD_SERVERS",
      "is_dynamic": true,
      "dynamic_filter": "'FCTEMS_ALL_FORTICLOUD_SERVERS'",
      "tags": [
        "FCTEMS_ALL_FORTICLOUD_SERVERS"
      ]
    },
    {
      "name": "EMS1_ZTNA_all_registered_clients",
      "members": [],
      "description": "Migrated FortiClient EMS Dynamic Tag: EMS1_ZTNA_all_registered_clients",
      "is_dynamic": true,
      "dynamic_filter": "'EMS1_ZTNA_all_registered_clients'",
      "tags": [
        "EMS1_ZTNA_all_registered_clients"
      ]
    },
    {
      "name": "MAC_EMS1_ZTNA_all_registered_clients",
      "members": [],
      "description": "Migrated FortiClient EMS Dynamic Tag: MAC_EMS1_ZTNA_all_registered_clients",
      "is_dynamic": true,
      "dynamic_filter": "'MAC_EMS1_ZTNA_all_registered_clients'",
      "tags": [
        "MAC_EMS1_ZTNA_all_registered_clients"
      ]
    },
    {
      "name": "EMS1_ZTNA_Deleum_ADUser",
      "members": [],
      "description": "Active Directory User",
      "is_dynamic": true,
      "dynamic_filter": "'EMS1_ZTNA_Deleum_ADUser'",
      "tags": [
        "EMS1_ZTNA_Deleum_ADUser"
      ]
    },
    {
      "name": "MAC_EMS1_ZTNA_Deleum_ADUser",
      "members": [],
      "description": "Active Directory User",
      "is_dynamic": true,
      "dynamic_filter": "'MAC_EMS1_ZTNA_Deleum_ADUser'",
      "tags": [
        "MAC_EMS1_ZTNA_Deleum_ADUser"
      ]
    },
    {
      "name": "EMS1_ZTNA_Deleum_AV",
      "members": [],
      "description": "Antivirus Installed",
      "is_dynamic": true,
      "dynamic_filter": "'EMS1_ZTNA_Deleum_AV'",
      "tags": [
        "EMS1_ZTNA_Deleum_AV"
      ]
    },
    {
      "name": "MAC_EMS1_ZTNA_Deleum_AV",
      "members": [],
      "description": "Antivirus Installed",
      "is_dynamic": true,
      "dynamic_filter": "'MAC_EMS1_ZTNA_Deleum_AV'",
      "tags": [
        "MAC_EMS1_ZTNA_Deleum_AV"
      ]
    },
    {
      "name": "EMS1_ZTNA_Deleum_CriticalVul",
      "members": [],
      "description": "Critical Vulnerability",
      "is_dynamic": true,
      "dynamic_filter": "'EMS1_ZTNA_Deleum_CriticalVul'",
      "tags": [
        "EMS1_ZTNA_Deleum_CriticalVul"
      ]
    },
    {
      "name": "MAC_EMS1_ZTNA_Deleum_CriticalVul",
      "members": [],
      "description": "Critical Vulnerability",
      "is_dynamic": true,
      "dynamic_filter": "'MAC_EMS1_ZTNA_Deleum_CriticalVul'",
      "tags": [
        "MAC_EMS1_ZTNA_Deleum_CriticalVul"
      ]
    },
    {
      "name": "EMS1_ZTNA_Not_Log_Domain_Name",
      "members": [],
      "description": "Domain_Name",
      "is_dynamic": true,
      "dynamic_filter": "'EMS1_ZTNA_Not_Log_Domain_Name'",
      "tags": [
        "EMS1_ZTNA_Not_Log_Domain_Name"
      ]
    },
    {
      "name": "EMS1_ZTNA_Outdated_Windows",
      "members": [],
      "description": "Outdated Windows",
      "is_dynamic": true,
      "dynamic_filter": "'EMS1_ZTNA_Outdated_Windows'",
      "tags": [
        "EMS1_ZTNA_Outdated_Windows"
      ]
    },
    {
      "name": "MAC_EMS1_ZTNA_Outdated_Windows",
      "members": [],
      "description": "Outdated Windows",
      "is_dynamic": true,
      "dynamic_filter": "'MAC_EMS1_ZTNA_Outdated_Windows'",
      "tags": [
        "MAC_EMS1_ZTNA_Outdated_Windows"
      ]
    },
    {
      "name": "EMS1_ZTNA_Deleum_OSVersion",
      "members": [],
      "description": "Allowed OS",
      "is_dynamic": true,
      "dynamic_filter": "'EMS1_ZTNA_Deleum_OSVersion'",
      "tags": [
        "EMS1_ZTNA_Deleum_OSVersion"
      ]
    },
    {
      "name": "MAC_EMS1_ZTNA_Deleum_OSVersion",
      "members": [],
      "description": "Allowed OS",
      "is_dynamic": true,
      "dynamic_filter": "'MAC_EMS1_ZTNA_Deleum_OSVersion'",
      "tags": [
        "MAC_EMS1_ZTNA_Deleum_OSVersion"
      ]
    },
    {
      "name": "EMS1_ZTNA_Not_Deleum",
      "members": [],
      "description": "Not Deleum Domain",
      "is_dynamic": true,
      "dynamic_filter": "'EMS1_ZTNA_Not_Deleum'",
      "tags": [
        "EMS1_ZTNA_Not_Deleum"
      ]
    },
    {
      "name": "MAC_EMS1_ZTNA_Not_Deleum",
      "members": [],
      "description": "Not Deleum Domain",
      "is_dynamic": true,
      "dynamic_filter": "'MAC_EMS1_ZTNA_Not_Deleum'",
      "tags": [
        "MAC_EMS1_ZTNA_Not_Deleum"
      ]
    },
    {
      "name": "EMS1_ZTNA_Crit_Vul",
      "members": [],
      "description": "Critical Vulnerability Presence",
      "is_dynamic": true,
      "dynamic_filter": "'EMS1_ZTNA_Crit_Vul'",
      "tags": [
        "EMS1_ZTNA_Crit_Vul"
      ]
    },
    {
      "name": "MAC_EMS1_ZTNA_Crit_Vul",
      "members": [],
      "description": "Critical Vulnerability Presence",
      "is_dynamic": true,
      "dynamic_filter": "'MAC_EMS1_ZTNA_Crit_Vul'",
      "tags": [
        "MAC_EMS1_ZTNA_Crit_Vul"
      ]
    },
    {
      "name": "Branches_LAN",
      "members": [
        "DOSSB_KK-192.168.13.0/24",
        "DOSSB_Labuan-192.168.2.0/24",
        "DOSSB_Miri-192.168.5.0/24",
        "DPSB_Miri-192.168.9.0/24",
        "DPSB_TK_new_192.168.7.0/24",
        "Miri_WS-192.168.8.0/24"
      ],
      "description": null,
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "branches_leased_line",
      "members": [
        "DOSSB_Labuan_Leased_Line-10.10.2.0/24",
        "DPSB_Teluk_Kalong_Leased_Line-10.10.7.0/24"
      ],
      "description": null,
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "protection.outlook.com",
      "members": [
        "microsoft1",
        "microsoft2",
        "microsoft3",
        "microsoft4",
        "microsoft5"
      ],
      "description": null,
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "FAZ to_branch untrust group",
      "members": [
        "DPSB_Miri-192.168.9.0/24"
      ],
      "description": null,
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "to_CKJ_unifi_local",
      "members": [
        "to_CKJ_unifi_local_subnet_1"
      ],
      "description": "VPN: to_CKJ_unifi (Created by VPN wizard)",
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "to_CKJ_unifi_remote",
      "members": [
        "to_CKJ_unifi_remote_subnet_1"
      ],
      "description": "VPN: to_CKJ_unifi (Created by VPN wizard)",
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "to_DOSSB_Miri_local",
      "members": [
        "to_DOSSB_Miri_local_subnet_1"
      ],
      "description": "VPN: to_DOSSB_Miri (Created by VPN wizard)",
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "to_DOSSB_Miri_remote",
      "members": [
        "to_DOSSB_Miri_remote_subnet_1"
      ],
      "description": "VPN: to_DOSSB_Miri (Created by VPN wizard)",
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "single_session",
      "members": [
        "ariba",
        "ceac.state.gov",
        "jobsmalaysia.gov.my"
      ],
      "description": null,
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "toDOSSB_KSB_local",
      "members": [
        "toDOSSB_KSB_local_subnet_1"
      ],
      "description": "VPN: toDOSSB_KSB (Created by VPN wizard)",
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "toDOSSB_KSB_remote",
      "members": [
        "toDOSSB_KSB_remote_subnet_1"
      ],
      "description": "VPN: toDOSSB_KSB (Created by VPN wizard)",
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "Microsoft Office 365",
      "members": [
        "login.microsoftonline.com",
        "login.microsoft.com",
        "login.windows.net"
      ],
      "description": null,
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "G Suite",
      "members": [
        "gmail.com",
        "wildcard.google.com"
      ],
      "description": null,
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "exclude QUIC",
      "members": [
        "ipad 1",
        "ipad 2"
      ],
      "description": null,
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "banking",
      "members": [
        "s2b.standardchartered.com",
        "hsbcnet.com",
        "mrates.maybank.com.my"
      ],
      "description": null,
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "QuarantinedDevices",
      "members": [
        "qtn.mac_00:00:00:00:00:00"
      ],
      "description": null,
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "Unifi2_route",
      "members": [
        "securemail.cat.com",
        "efiling.rd.go.th"
      ],
      "description": null,
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "server_no_internet",
      "members": [
        "server_192.168.42.17",
        "server_192.168.42.19",
        "server_192.168.42.18",
        "server_192.168.42.9",
        "server_192.168.42.12"
      ],
      "description": null,
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "Deleum_VPN",
      "members": [
        "EMS1_ZTNA_all_registered_clients",
        "MAC_EMS1_ZTNA_all_registered_clients"
      ],
      "description": null,
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "Deleum_ICT",
      "members": [
        "EMS1_ZTNA_Deleum_ADUser",
        "EMS1_ZTNA_Deleum_AV",
        "EMS1_ZTNA_Deleum_CriticalVul",
        "MAC_EMS1_ZTNA_all_registered_clients",
        "MAC_EMS1_ZTNA_Deleum_ADUser",
        "MAC_EMS1_ZTNA_Deleum_AV",
        "MAC_EMS1_ZTNA_Deleum_CriticalVul",
        "EMS1_ZTNA_all_registered_clients"
      ],
      "description": null,
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "Deleum_IPSEC_split",
      "members": [
        "all"
      ],
      "description": "VPN: Deleum_IPSEC (Created by VPN wizard)",
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "Test_IPSEC2_split",
      "members": [
        "all"
      ],
      "description": "VPN: Test_IPSEC2 (Created by VPN wizard)",
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "FortiClient_split",
      "members": [
        "all"
      ],
      "description": "VPN: FortiClient (Created by VPN wizard)",
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "miniOrange_Cloud",
      "members": [
        "miniOrange_52.55.147.107",
        "miniOrange_52.86.38.163",
        "miniOrange_54.165.245.227"
      ],
      "description": null,
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    },
    {
      "name": "SangforCP_split",
      "members": [
        "Server-192.168.42.0/24"
      ],
      "description": "VPN: SangforCP (Created by VPN wizard)",
      "is_dynamic": false,
      "dynamic_filter": null,
      "tags": []
    }
  ],
  "services": [
    {
      "name": "ALL",
      "ports": [
        {
          "protocol": "tcp",
          "port": "any",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "FTP",
      "ports": [
        {
          "protocol": "tcp",
          "port": "21",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "FTP_GET",
      "ports": [
        {
          "protocol": "tcp",
          "port": "21",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "FTP_PUT",
      "ports": [
        {
          "protocol": "tcp",
          "port": "21",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "DNS",
      "ports": [
        {
          "protocol": "tcp",
          "port": "53",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "53",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "HTTP",
      "ports": [
        {
          "protocol": "tcp",
          "port": "80",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "HTTPS",
      "ports": [
        {
          "protocol": "tcp",
          "port": "443",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "IMAP",
      "ports": [
        {
          "protocol": "tcp",
          "port": "143",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "IMAPS",
      "ports": [
        {
          "protocol": "tcp",
          "port": "993",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "LDAP",
      "ports": [
        {
          "protocol": "tcp",
          "port": "389",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "DCE-RPC",
      "ports": [
        {
          "protocol": "tcp",
          "port": "135",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "135",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "POP3",
      "ports": [
        {
          "protocol": "tcp",
          "port": "110",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "POP3S",
      "ports": [
        {
          "protocol": "tcp",
          "port": "995",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "SAMBA",
      "ports": [
        {
          "protocol": "tcp",
          "port": "139",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "SMTP",
      "ports": [
        {
          "protocol": "tcp",
          "port": "25",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "SMTPS",
      "ports": [
        {
          "protocol": "tcp",
          "port": "465",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "KERBEROS",
      "ports": [
        {
          "protocol": "tcp",
          "port": "88",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "tcp",
          "port": "464",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "88",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "464",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "LDAP_UDP",
      "ports": [
        {
          "protocol": "udp",
          "port": "389",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "SMB",
      "ports": [
        {
          "protocol": "tcp",
          "port": "445",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "ALL_TCP",
      "ports": [
        {
          "protocol": "tcp",
          "port": "1-65535",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "ALL_UDP",
      "ports": [
        {
          "protocol": "udp",
          "port": "1-65535",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "ALL_ICMP",
      "ports": [
        {
          "protocol": "icmp",
          "port": "any",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "ALL_ICMP6",
      "ports": [
        {
          "protocol": "icmp",
          "port": "any",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "GRE",
      "ports": [
        {
          "protocol": "ip",
          "port": "47",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "AH",
      "ports": [
        {
          "protocol": "ip",
          "port": "51",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "ESP",
      "ports": [
        {
          "protocol": "ip",
          "port": "50",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "AOL",
      "ports": [
        {
          "protocol": "tcp",
          "port": "5190-5194",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "BGP",
      "ports": [
        {
          "protocol": "tcp",
          "port": "179",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "DHCP",
      "ports": [
        {
          "protocol": "udp",
          "port": "67-68",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "FINGER",
      "ports": [
        {
          "protocol": "tcp",
          "port": "79",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "GOPHER",
      "ports": [
        {
          "protocol": "tcp",
          "port": "70",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "H323",
      "ports": [
        {
          "protocol": "tcp",
          "port": "1720",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "tcp",
          "port": "1503",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "1719",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "IKE",
      "ports": [
        {
          "protocol": "udp",
          "port": "500",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "4500",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "Internet-Locator-Service",
      "ports": [
        {
          "protocol": "tcp",
          "port": "389",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "IRC",
      "ports": [
        {
          "protocol": "tcp",
          "port": "6660-6669",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "L2TP",
      "ports": [
        {
          "protocol": "tcp",
          "port": "1701",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "1701",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "NetMeeting",
      "ports": [
        {
          "protocol": "tcp",
          "port": "1720",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "NFS",
      "ports": [
        {
          "protocol": "tcp",
          "port": "111",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "tcp",
          "port": "2049",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "111",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "2049",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "NNTP",
      "ports": [
        {
          "protocol": "tcp",
          "port": "119",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "NTP",
      "ports": [
        {
          "protocol": "tcp",
          "port": "123",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "123",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "OSPF",
      "ports": [
        {
          "protocol": "ip",
          "port": "89",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "PC-Anywhere",
      "ports": [
        {
          "protocol": "tcp",
          "port": "5631",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "5632",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "PING",
      "ports": [
        {
          "protocol": "icmp",
          "port": "any",
          "icmptype": 8,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "TIMESTAMP",
      "ports": [
        {
          "protocol": "icmp",
          "port": "any",
          "icmptype": 13,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "INFO_REQUEST",
      "ports": [
        {
          "protocol": "icmp",
          "port": "any",
          "icmptype": 15,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "INFO_ADDRESS",
      "ports": [
        {
          "protocol": "icmp",
          "port": "any",
          "icmptype": 17,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "ONC-RPC",
      "ports": [
        {
          "protocol": "tcp",
          "port": "111",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "111",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "PPTP",
      "ports": [
        {
          "protocol": "tcp",
          "port": "1723",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "QUAKE",
      "ports": [
        {
          "protocol": "udp",
          "port": "26000",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "27000",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "27910",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "27960",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "RAUDIO",
      "ports": [
        {
          "protocol": "udp",
          "port": "7070",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "REXEC",
      "ports": [
        {
          "protocol": "tcp",
          "port": "512",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "RIP",
      "ports": [
        {
          "protocol": "udp",
          "port": "520",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "RLOGIN",
      "ports": [
        {
          "protocol": "tcp",
          "port": "513",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "RSH",
      "ports": [
        {
          "protocol": "tcp",
          "port": "514",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "SCCP",
      "ports": [
        {
          "protocol": "tcp",
          "port": "2000",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "SIP",
      "ports": [
        {
          "protocol": "tcp",
          "port": "5060",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "5060",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "SIP-MSNmessenger",
      "ports": [
        {
          "protocol": "tcp",
          "port": "1863",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "SNMP",
      "ports": [
        {
          "protocol": "tcp",
          "port": "161-162",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "161-162",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "SSH",
      "ports": [
        {
          "protocol": "tcp",
          "port": "22",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "SYSLOG",
      "ports": [
        {
          "protocol": "udp",
          "port": "514",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "TALK",
      "ports": [
        {
          "protocol": "udp",
          "port": "517-518",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "TELNET",
      "ports": [
        {
          "protocol": "tcp",
          "port": "23",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "TFTP",
      "ports": [
        {
          "protocol": "udp",
          "port": "69",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "MGCP",
      "ports": [
        {
          "protocol": "udp",
          "port": "2427",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "2727",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "UUCP",
      "ports": [
        {
          "protocol": "tcp",
          "port": "540",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "VDOLIVE",
      "ports": [
        {
          "protocol": "tcp",
          "port": "7000-7010",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "WAIS",
      "ports": [
        {
          "protocol": "tcp",
          "port": "210",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "WINFRAME",
      "ports": [
        {
          "protocol": "tcp",
          "port": "1494",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "tcp",
          "port": "2598",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "X-WINDOWS",
      "ports": [
        {
          "protocol": "tcp",
          "port": "6000-6063",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "PING6",
      "ports": [
        {
          "protocol": "icmp",
          "port": "any",
          "icmptype": 128,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "MS-SQL",
      "ports": [
        {
          "protocol": "tcp",
          "port": "1433",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "tcp",
          "port": "1434",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "MYSQL",
      "ports": [
        {
          "protocol": "tcp",
          "port": "3306",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "RDP",
      "ports": [
        {
          "protocol": "tcp",
          "port": "3389",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "VNC",
      "ports": [
        {
          "protocol": "tcp",
          "port": "5900",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "DHCP6",
      "ports": [
        {
          "protocol": "udp",
          "port": "546",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "547",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "SQUID",
      "ports": [
        {
          "protocol": "tcp",
          "port": "3128",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "SOCKS",
      "ports": [
        {
          "protocol": "tcp",
          "port": "1080",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "1080",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "WINS",
      "ports": [
        {
          "protocol": "tcp",
          "port": "1512",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "1512",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "RADIUS",
      "ports": [
        {
          "protocol": "udp",
          "port": "1812",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "1813",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "RADIUS-OLD",
      "ports": [
        {
          "protocol": "udp",
          "port": "1645",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "1646",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "CVSPSERVER",
      "ports": [
        {
          "protocol": "tcp",
          "port": "2401",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "2401",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "AFS3",
      "ports": [
        {
          "protocol": "tcp",
          "port": "7000-7009",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "7000-7009",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "TRACEROUTE",
      "ports": [
        {
          "protocol": "udp",
          "port": "33434-33535",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "RTSP",
      "ports": [
        {
          "protocol": "tcp",
          "port": "554",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "tcp",
          "port": "7070",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "tcp",
          "port": "8554",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "554",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "MMS",
      "ports": [
        {
          "protocol": "tcp",
          "port": "1755",
          "icmptype": null,
          "icmpcode": null
        },
        {
          "protocol": "udp",
          "port": "1024-5000",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "NONE",
      "ports": [
        {
          "protocol": "tcp",
          "port": "1-65535",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "webproxy",
      "ports": [
        {
          "protocol": "tcp",
          "port": "1-65535",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "port_8081",
      "ports": [
        {
          "protocol": "tcp",
          "port": "8081",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    },
    {
      "name": "LDAPS",
      "ports": [
        {
          "protocol": "tcp",
          "port": "636",
          "icmptype": null,
          "icmpcode": null
        }
      ],
      "description": null
    }
  ],
  "service_groups": [
    {
      "name": "Email Access",
      "members": [
        "DNS",
        "IMAP",
        "IMAPS",
        "POP3",
        "POP3S",
        "SMTP",
        "SMTPS"
      ],
      "description": null
    },
    {
      "name": "Web Access",
      "members": [
        "DNS",
        "HTTP",
        "HTTPS"
      ],
      "description": null
    },
    {
      "name": "Windows AD",
      "members": [
        "DCE-RPC",
        "DNS",
        "KERBEROS",
        "LDAP",
        "LDAP_UDP",
        "SAMBA",
        "SMB"
      ],
      "description": null
    },
    {
      "name": "Exchange Server",
      "members": [
        "DCE-RPC",
        "DNS",
        "HTTPS"
      ],
      "description": null
    }
  ],
  "schedules": [
    {
      "name": "always",
      "start": null,
      "end": null,
      "days": [
        "sunday",
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday",
        "saturday"
      ]
    },
    {
      "name": "none",
      "start": null,
      "end": null,
      "days": []
    },
    {
      "name": "default-darrp-optimize",
      "start": "01:00",
      "end": "01:30",
      "days": [
        "sunday",
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday",
        "saturday"
      ]
    }
  ],
  "security_profile_groups": [
    {
      "name": "SPG_IPS_default",
      "antivirus": "default",
      "vulnerability": "default",
      "anti_spyware": "default",
      "url_filtering": "default",
      "file_blocking": "basic-file-blocking",
      "wildfire": "default",
      "ssl_decryption": "certificate-inspection",
      "description": "Auto-generated profile group for FortiGate UTM (IPS_default)"
    },
    {
      "name": "Migrated_Profiles",
      "antivirus": "default",
      "vulnerability": "default",
      "anti_spyware": "default",
      "url_filtering": "default",
      "file_blocking": "basic-file-blocking",
      "wildfire": "default",
      "ssl_decryption": "certificate-inspection",
      "description": "Auto-generated profile group for FortiGate UTM (General)"
    },
    {
      "name": "SPG_IPS_high_security",
      "antivirus": "default",
      "vulnerability": "high_security",
      "anti_spyware": "default",
      "url_filtering": "default",
      "file_blocking": "basic-file-blocking",
      "wildfire": "default",
      "ssl_decryption": "certificate-inspection",
      "description": "Auto-generated profile group for FortiGate UTM (IPS_high_security)"
    },
    {
      "name": "SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio",
      "antivirus": "default",
      "vulnerability": "high_security",
      "anti_spyware": "default",
      "url_filtering": "deleum_webfilter",
      "file_blocking": "basic-file-blocking",
      "wildfire": "default",
      "ssl_decryption": "certificate-inspection",
      "description": "Auto-generated profile group for FortiGate UTM (IPS_high_security, WF_deleum_webfilter, APP_deleum application control)"
    },
    {
      "name": "SPG_WF_deleum_webfilter_APP_deleum_application_control",
      "antivirus": "default",
      "vulnerability": "default",
      "anti_spyware": "default",
      "url_filtering": "deleum_webfilter",
      "file_blocking": "basic-file-blocking",
      "wildfire": "default",
      "ssl_decryption": "certificate-inspection",
      "description": "Auto-generated profile group for FortiGate UTM (WF_deleum_webfilter, APP_deleum application control)"
    },
    {
      "name": "SPG_APP_deleum_application_control",
      "antivirus": "default",
      "vulnerability": "default",
      "anti_spyware": "default",
      "url_filtering": "default",
      "file_blocking": "basic-file-blocking",
      "wildfire": "default",
      "ssl_decryption": "certificate-inspection",
      "description": "Auto-generated profile group for FortiGate UTM (APP_deleum application control)"
    },
    {
      "name": "SPG_WF_wifi__deleum_webfilter_APP_deleum_application_control_fo",
      "antivirus": "default",
      "vulnerability": "default",
      "anti_spyware": "default",
      "url_filtering": "wifi_ deleum_webfilter",
      "file_blocking": "basic-file-blocking",
      "wildfire": "default",
      "ssl_decryption": "certificate-inspection",
      "description": "Auto-generated profile group for FortiGate UTM (WF_wifi_ deleum_webfilter, APP_deleum application control for IOS)"
    },
    {
      "name": "SPG_WF_wifi__deleum_webfilter_APP_deleum_application_control",
      "antivirus": "default",
      "vulnerability": "default",
      "anti_spyware": "default",
      "url_filtering": "wifi_ deleum_webfilter",
      "file_blocking": "basic-file-blocking",
      "wildfire": "default",
      "ssl_decryption": "certificate-inspection",
      "description": "Auto-generated profile group for FortiGate UTM (WF_wifi_ deleum_webfilter, APP_deleum application control)"
    },
    {
      "name": "SPG_IPS_default_WF_deleum_webfilter_APP_deleum_application_cont",
      "antivirus": "default",
      "vulnerability": "default",
      "anti_spyware": "default",
      "url_filtering": "deleum_webfilter",
      "file_blocking": "basic-file-blocking",
      "wildfire": "default",
      "ssl_decryption": "certificate-inspection",
      "description": "Auto-generated profile group for FortiGate UTM (IPS_default, WF_deleum_webfilter, APP_deleum application control)"
    },
    {
      "name": "SPG_AV_default_IPS_high_security_WF_deleum_webfilter_APP_deleum",
      "antivirus": "default",
      "vulnerability": "high_security",
      "anti_spyware": "default",
      "url_filtering": "deleum_webfilter",
      "file_blocking": "basic-file-blocking",
      "wildfire": "default",
      "ssl_decryption": "certificate-inspection",
      "description": "Auto-generated profile group for FortiGate UTM (AV_default, IPS_high_security, WF_deleum_webfilter, APP_deleum application control)"
    },
    {
      "name": "SPG_IPS_high_security_APP_deleum_application_control",
      "antivirus": "default",
      "vulnerability": "high_security",
      "anti_spyware": "default",
      "url_filtering": "default",
      "file_blocking": "basic-file-blocking",
      "wildfire": "default",
      "ssl_decryption": "certificate-inspection",
      "description": "Auto-generated profile group for FortiGate UTM (IPS_high_security, APP_deleum application control)"
    }
  ],
  "policies": [
    {
      "name": ",",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "DOSSB_Labuan_Leased_Line-10.10.2.0/24",
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "252",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "253",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "258",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "263",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": " (Reverse of 258)",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "255",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "pulse_new_172.16.0.0/24"
      ],
      "destination": [
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "259",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "pulse_new_172.16.0.0/24"
      ],
      "destination": [
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "264",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "destination": [
        "pulse_new_172.16.0.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": " (Reverse of 259)",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "257",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Trust-192.168.0.0/23"
      ],
      "destination": [
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "260",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Trust-192.168.0.0/23"
      ],
      "destination": [
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "256",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "destination": [
        "pulse_new_172.16.0.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": " (Reverse of 255)",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "254",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "261",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "9",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "DOSSB_Labuan_Leased_Line-10.10.2.0/24",
        "DOSSB_Labuan-192.168.2.0/24",
        "DOSSB_Labuan_wifi_10.10.22.0/24"
      ],
      "destination": [
        "any"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "Migrated_Profiles",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "85",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "FAZ200F_192.168.30.2"
      ],
      "destination": [
        "Miri_WS-192.168.8.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "206",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "FAZ200F_192.168.30.2"
      ],
      "destination": [
        "Miri_WS-192.168.8.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 85",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "153",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "FAZ200F_192.168.30.2"
      ],
      "destination": [
        "DOSSB_KSB-192.168.4.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 85",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "163",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "DOSSB_KSB-192.168.4.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 153",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "170",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "FAZ200F_192.168.30.2"
      ],
      "destination": [
        "DPSB_CKJ_192.168.14.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 87",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "179",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "FAZ200F_192.168.30.2"
      ],
      "destination": [
        "DOSSB_KSB-192.168.4.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 170",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "204",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "DOSSB_KSB-192.168.4.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 179",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "111",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "FAZ200F_192.168.30.2"
      ],
      "destination": [
        "DPSB_CKJ_192.168.14.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "187",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "FAZ200F_192.168.30.2"
      ],
      "destination": [
        "DPSB_TK_new_192.168.7.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 111",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "268",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "FAZ200F_192.168.30.2"
      ],
      "destination": [
        "Miri_DTS_192.168.6.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 111 (Copy of 187) (Copy of )",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "285",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "FAZ200F_192.168.30.2"
      ],
      "destination": [
        "Bintulu1_192.168.11.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "298",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "FAZ200F_192.168.30.2"
      ],
      "destination": [
        "Bintulu1_192.168.11.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "288",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "FAZ200F_192.168.30.2"
      ],
      "destination": [
        "Bintulu2-192.168.3.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": " (Copy of 285) (Copy of )",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "302",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "FAZ200F_192.168.30.2"
      ],
      "destination": [
        "Bintulu2-192.168.3.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "286",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "Bintulu1_192.168.11.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": " (Reverse of 285)",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "295",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "Bintulu1_192.168.11.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "292",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "Bintulu2-192.168.3.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "303",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "Bintulu2-192.168.3.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": " (Copy of 292) (Copy of )",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "275",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "FAZ200F_192.168.30.2"
      ],
      "destination": [
        "Miri_DTS_192.168.6.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "273",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "Miri_DTS_192.168.6.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 111 (Copy of 187) (Copy of ) (Reverse of 268)",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "279",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "Miri_DTS_192.168.6.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "269",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "Miri_DTS_192.168.6.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "282",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "Bintulu1_192.168.11.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": " (Copy of 269) (Copy of )",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "297",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "Bintulu1_192.168.11.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": " ",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "291",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "Bintulu2-192.168.3.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "305",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "Bintulu2-192.168.3.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "281",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "Miri_DTS_192.168.6.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": " (Copy of 269) (Copy of )",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "270",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "Miri_DTS_192.168.6.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "284",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "Bintulu1_192.168.11.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "299",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "Bintulu1_192.168.11.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "289",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "Bintulu2-192.168.3.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "301",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "Bintulu2-192.168.3.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "287",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "Bintulu1_192.168.11.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": " (Reverse of 284)",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "296",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "Bintulu1_192.168.11.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "293",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "Bintulu2-192.168.3.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": " ",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "304",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "Bintulu2-192.168.3.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "  (Copy of 293) (Copy of )",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "277",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "Miri_DTS_192.168.6.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "274",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "Miri_DTS_192.168.6.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": " (Reverse of 270)",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "280",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "Miri_DTS_192.168.6.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "199",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "DPSB_TK_new_192.168.7.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 187",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "189",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "FAZ200F_192.168.30.2"
      ],
      "destination": [
        "DPSB_TK_new_192.168.7.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 187",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "221",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "FAZ200F_192.168.30.2"
      ],
      "destination": [
        "DOSSB_KK-192.168.13.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 189",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "250",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "FAZ200F_192.168.30.2"
      ],
      "destination": [
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "262",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "FAZ200F_192.168.30.2"
      ],
      "destination": [
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "265",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": " (Reverse of 262)",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "251",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": " (Reverse of 250)",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "223",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "DOSSB_KK-192.168.13.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 221",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "220",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "FAZ200F_192.168.30.2"
      ],
      "destination": [
        "DOSSB_KK-192.168.13.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 189",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "222",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "DOSSB_KK-192.168.13.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 220",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "200",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "DPSB_TK_new_192.168.7.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 189",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "95",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "FAZ200F_192.168.30.2"
      ],
      "destination": [
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "96",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 95",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "177",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "DPSB_CKJ_192.168.14.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 88",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "117",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "DOSSB_Miri-192.168.5.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 88",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "215",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "DOSSB_Miri-192.168.5.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 117",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "107",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "DPSB_CKJ_192.168.14.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "86",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "Miri_WS-192.168.8.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 85",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "209",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "Miri_WS-192.168.8.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 86",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "4",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "DOSSB_Labuan_Leased_Line-10.10.2.0/24",
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of ,",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "17",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "Branches_LAN"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "128",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 23",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "23",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 22",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "deleum_webfilter",
      "application_list": "deleum application control",
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "127",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "Branches_LAN"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 32",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "186",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Trust-192.168.0.0/23"
      ],
      "destination": [
        "banking"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": " (Copy of 32) (Copy of )",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_WF_deleum_webfilter_APP_deleum_application_control",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "deleum_webfilter",
      "application_list": "deleum application control",
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "32",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Trust-192.168.0.0/23"
      ],
      "destination": [
        "banking"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "to_MicrosoftTeams",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Trust-192.168.0.0/23"
      ],
      "destination": [],
      "service": [],
      "action": "allow",
      "description": "Clone of 137",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": [
        "Microsoft-Skype_Teams"
      ]
    },
    {
      "name": "137",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_fixed_IP"
      ],
      "destination": [
        "any"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of FSSO policy",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_APP_deleum_application_control",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": "deleum application control",
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "FSSO policy",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "any"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_WF_deleum_webfilter_APP_deleum_application_control",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "deleum_webfilter",
      "application_list": "deleum application control",
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "33",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "any"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "deleum_webfilter",
      "application_list": "deleum application control",
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "to_MicrosoftTeams_from_wifi",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "HQ_Wifi_User-10.10.10.0/23"
      ],
      "destination": [],
      "service": [],
      "action": "allow",
      "description": "Clone of to_MicrosoftTeams",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": [
        "Microsoft-Skype_Teams"
      ]
    },
    {
      "name": "quic allowed",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "exclude QUIC"
      ],
      "destination": [
        "any"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_WF_wifi__deleum_webfilter_APP_deleum_application_control_fo",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "wifi_ deleum_webfilter",
      "application_list": "deleum application control for IOS",
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "39",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "HQ_Wifi_User-10.10.10.0/23"
      ],
      "destination": [
        "any"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_WF_wifi__deleum_webfilter_APP_deleum_application_control",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "wifi_ deleum_webfilter",
      "application_list": "deleum application control",
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "147",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "pulse_new_172.16.0.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "deleum_webfilter",
      "application_list": "deleum application control",
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "151",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "pulse_new_172.16.0.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 147",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "148",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "pulse_new_172.16.0.0/24"
      ],
      "destination": [
        "Trust-192.168.0.0/23"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 147",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "152",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "pulse_new_172.16.0.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 126",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "150",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "pulse_new_172.16.0.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 148",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "154",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "pulse_new_172.16.0.0/24"
      ],
      "destination": [
        "DBATT_192.168.10.7"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 144",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "160",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "pulse_new_172.16.0.0/24"
      ],
      "destination": [
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 142",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "174",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "destination": [
        "pulse_new_172.16.0.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 160",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "155",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "pulse_new_172.16.0.0/24"
      ],
      "destination": [
        "Branches_LAN"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 45",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "157",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "Branches_LAN"
      ],
      "destination": [
        "pulse_new_172.16.0.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 155",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "156",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "pulse_new_172.16.0.0/24"
      ],
      "destination": [
        "any"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 46",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_WF_deleum_webfilter_APP_deleum_application_control",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "deleum_webfilter",
      "application_list": "deleum application control",
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "172",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "pulse_new_172.16.0.0/24"
      ],
      "destination": [
        "DPSB_CKJ_192.168.14.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 161",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "161",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "pulse_new_172.16.0.0/24"
      ],
      "destination": [
        "DOSSB_KSB-192.168.4.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 172",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "180",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "DPSB_CKJ_192.168.14.0/24"
      ],
      "destination": [
        "pulse_new_172.16.0.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 179",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "162",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "pulse_new_172.16.0.0/24"
      ],
      "destination": [
        "DPSB_CKJ_192.168.14.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 109",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "188",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "pulse_new_172.16.0.0/24"
      ],
      "destination": [
        "DPSB_TK_new_192.168.7.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 162",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "272",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "pulse_new_172.16.0.0/24"
      ],
      "destination": [
        "Miri_DTS_192.168.6.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "276",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "pulse_new_172.16.0.0/24"
      ],
      "destination": [
        "Miri_DTS_192.168.6.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "190",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "pulse_new_172.16.0.0/24"
      ],
      "destination": [
        "DPSB_TK_new_192.168.7.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 188",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "178",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "DPSB_CKJ_192.168.14.0/24"
      ],
      "destination": [
        "pulse_new_172.16.0.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 162",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "164",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "pulse_new_172.16.0.0/24"
      ],
      "destination": [
        "DOSSB_Miri-192.168.5.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 143",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "171",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "DOSSB_Miri-192.168.5.0/24"
      ],
      "destination": [
        "pulse_new_172.16.0.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 164",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "216",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "DOSSB_Miri-192.168.5.0/24"
      ],
      "destination": [
        "pulse_new_172.16.0.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 171",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "224",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "DOSSB_KK-192.168.13.0/24"
      ],
      "destination": [
        "pulse_new_172.16.0.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 216",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "226",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "pulse_new_172.16.0.0/24"
      ],
      "destination": [
        "DOSSB_KK-192.168.13.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 224",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "225",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "DOSSB_KK-192.168.13.0/24"
      ],
      "destination": [
        "pulse_new_172.16.0.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 224",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "227",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "pulse_new_172.16.0.0/24"
      ],
      "destination": [
        "DOSSB_KK-192.168.13.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 225",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "173",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "DPSB_CKJ_192.168.14.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 51",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "201",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "DOSSB_KSB-192.168.4.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 173",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "205",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "DOSSB_KSB-192.168.4.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 201",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "deleum_webfilter",
      "application_list": "deleum application control",
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "230",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "DOSSB_KK-192.168.13.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 205",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "231",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "DOSSB_KK-192.168.13.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 230",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "176",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "DPSB_CKJ_192.168.14.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 129",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "242",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "DPSB_CKJ_192.168.14.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 129 (Copy of 176)",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "203",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "DOSSB_KSB-192.168.4.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 176",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "245",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "DOSSB_KSB-192.168.4.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 176 (Copy of 203)",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "131",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "DPSB_CKJ_192.168.14.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 110",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "241",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "DPSB_CKJ_192.168.14.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 110 (Copy of 131)",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "240",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "DPSB_TK_new_192.168.7.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 131 (Copy of 195)",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "195",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "DPSB_TK_new_192.168.7.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 131",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "196",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "DPSB_TK_new_192.168.7.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 195",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "246",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "DPSB_TK_new_192.168.7.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 195 (Copy of 196)",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "167",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ_new"
      ],
      "destination": [
        "ICT_HQ_192.168.111.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 131",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "236",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ_new"
      ],
      "destination": [
        "ICT_HQ_192.168.111.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "169",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "ICT_HQ_192.168.111.0/24"
      ],
      "destination": [
        "Trust-192.168.0.0/23"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 167",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "133",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "ICT_HQ_192.168.111.0/24",
        "DR-192.168.43.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 169",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "247",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "ICT_HQ_192.168.111.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 169 (Copy of 133)",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "248",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "FAZ200F_192.168.30.2"
      ],
      "destination": [
        "ICT_HQ_192.168.111.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 169 (Copy of 133) (Copy of 247) (Reverse of 247)",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "165",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "DR-192.168.43.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 133",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "184",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Trust-192.168.0.0/23"
      ],
      "destination": [
        "DR-192.168.43.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 165",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "182",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "DPSB_CKJ_192.168.14.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 52",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default_WF_deleum_webfilter_APP_deleum_application_cont",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "deleum_webfilter",
      "application_list": "deleum application control",
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "82",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "Miri_WS-192.168.8.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "211",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "Miri_WS-192.168.8.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 82",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "168",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "Miri_WS-192.168.8.0/24"
      ],
      "destination": [
        "pulse_new_172.16.0.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "210",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "Miri_WS-192.168.8.0/24"
      ],
      "destination": [
        "pulse_new_172.16.0.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 168",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "83",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "Miri_WS-192.168.8.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 82",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "207",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "Miri_WS-192.168.8.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 83",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "134",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "Miri_WS-192.168.8.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 112",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "112",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "Miri_WS-192.168.8.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": true,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "238",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "Miri_WS-192.168.8.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 112 (Copy of 212)",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "212",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "Miri_WS-192.168.8.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 112",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": true,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "232",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "DOSSB_KK-192.168.13.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 212",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "244",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "DOSSB_KK-192.168.13.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 212 (Copy of 232)",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": true,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "239",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "DOSSB_KK-192.168.13.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 232 (Copy of 233)",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "233",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "DOSSB_KK-192.168.13.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 232",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": true,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "20",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "Biometric-192.168.10.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "135",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "Biometric-192.168.10.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 25",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "25",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "Biometric-192.168.10.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 20",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_AV_default_IPS_high_security_WF_deleum_webfilter_APP_deleum",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "deleum_webfilter",
      "application_list": "deleum application control",
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "136",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "Biometric-192.168.10.0/24"
      ],
      "destination": [
        "Trust-192.168.0.0/23"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 26",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "26",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "Biometric-192.168.10.0/24"
      ],
      "destination": [
        "Trust-192.168.0.0/23"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "21",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "HQ_Wifi_User-10.10.10.0/23"
      ],
      "service": [
        "PING",
        "TRACEROUTE"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_AV_default_IPS_high_security_WF_deleum_webfilter_APP_deleum",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "deleum_webfilter",
      "application_list": "deleum application control",
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "22",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "Trust-192.168.0.0/23"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "138",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "trust_fixed_IP"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 23",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "119",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "Trust-192.168.0.0/23"
      ],
      "destination": [
        "Biometric-192.168.10.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 34",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "34",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "Trust-192.168.0.0/23"
      ],
      "destination": [
        "Biometric-192.168.10.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "deleum_webfilter",
      "application_list": "deleum application control",
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "267",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "server_no_internet"
      ],
      "destination": [
        "croudstrike1",
        "croudstrike2"
      ],
      "service": [
        "HTTPS"
      ],
      "action": "allow",
      "description": " (Copy of 185) (Copy of )",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "185",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "server_no_internet"
      ],
      "destination": [
        "any"
      ],
      "service": [
        "ALL"
      ],
      "action": "deny",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "18",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "any"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "124",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "DOSSB_Labuan_Leased_Line-10.10.2.0/24",
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 27",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "149",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "any"
      ],
      "destination": [
        "secure.deleum.com_175.143.1.50"
      ],
      "service": [
        "HTTPS"
      ],
      "action": "allow",
      "description": "Clone of 37",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_IPS_high_security_APP_deleum_application_control",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": "deleum application control",
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "MiniOrange_LDAPgw",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "miniOrange_Cloud"
      ],
      "destination": [
        "eformproxy_60.53.219.66"
      ],
      "service": [
        "HTTPS",
        "port_8081"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "36",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "any"
      ],
      "destination": [
        "unifi_VIP_server"
      ],
      "service": [
        "Web Access"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security_APP_deleum_application_control",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": "deleum application control",
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "61",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "64",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "DOSSB_Labuan_Leased_Line-10.10.2.0/24",
        "DOSSB_Labuan-192.168.2.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "175",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "DPSB_CKJ_192.168.14.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 69",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "234",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "DOSSB_KK-192.168.13.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 175",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "235",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "DOSSB_KK-192.168.13.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 234",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "202",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "DOSSB_KSB-192.168.4.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 175",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "108",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "DPSB_CKJ_192.168.14.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "193",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "DPSB_TK_new_192.168.7.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 108",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "271",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "Miri_DTS_192.168.6.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "283",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "Bintulu1_192.168.11.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "294",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "Bintulu1_192.168.11.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "290",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "Bintulu2-192.168.3.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "Migrated_Profiles",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "300",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "Bintulu2-192.168.3.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": " (Copy of 290) (Copy of )",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "Migrated_Profiles",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "278",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "Miri_DTS_192.168.6.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "194",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "DPSB_TK_new_192.168.7.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 193",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "118",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "DOSSB_Miri-192.168.5.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 70",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "214",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "DOSSB_Miri-192.168.5.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 118",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "84",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "Miri_WS-192.168.8.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "208",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "Miri_WS-192.168.8.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 84",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "62",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "Trust-192.168.0.0/23"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "145",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "pulse_new_172.16.0.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 62",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "144",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "DOSSB_KSB-192.168.4.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 74",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "63",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "any"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "75",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "SSL_VPN_HQ"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "78",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "HQ_Wifi_User-10.10.10.0/23"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "123",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 76",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "76",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "77",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "trust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "FAZ200F_192.168.30.2"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "79",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "FAZ200F_192.168.30.2"
      ],
      "destination": [
        "any"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "deleum_webfilter",
      "application_list": "deleum application control",
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "vpn_to_CKJ_unifi_local",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "DPSB_CKJ_192.168.14.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "VPN: to_CKJ_unifi (Created by VPN wizard)",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "191",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "DPSB_TK_new_192.168.7.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of vpn_to_CKJ_unifi_local",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "198",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "DPSB_TK_new_192.168.7.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 191",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "192",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "DPSB_TK_new_192.168.7.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 191",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "197",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "DPSB_TK_new_192.168.7.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 192",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "vpn_to_CKJ_unifi_remote",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "DPSB_CKJ_192.168.14.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "VPN: to_CKJ_unifi (Created by VPN wizard)",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "141",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "DOSSB_KSB-192.168.4.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of vpn_to_CKJ_unifi_remote",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "142",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "DOSSB_KSB-192.168.4.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of 141",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "146",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "DOSSB_KSB-192.168.4.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 142",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "243",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "DOSSB_KSB-192.168.4.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 142 (Copy of 146)",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "143",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "pulse_new_172.16.0.0/24"
      ],
      "destination": [
        "DOSSB_KSB-192.168.4.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 142",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "vpn_to_DOSSB_Miri_local",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "DOSSB_Miri-192.168.5.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "VPN: to_DOSSB_Miri (Created by VPN wizard)",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "213",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "DOSSB_Miri-192.168.5.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of vpn_to_DOSSB_Miri_local",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "228",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "DOSSB_KK-192.168.13.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 213",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "229",
      "from_zone": [
        "dmz"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "Server-192.168.42.0/24"
      ],
      "destination": [
        "DOSSB_KK-192.168.13.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 228",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "115",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "DOSSB_Miri-192.168.5.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Reverse of vpn_to_DOSSB_Miri_local",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "217",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "DOSSB_Miri-192.168.5.0/24"
      ],
      "destination": [
        "Server-192.168.42.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 115",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "132",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "DOSSB_Miri-192.168.5.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 116",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "116",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "DOSSB_Miri-192.168.5.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": true,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "237",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "DOSSB_Miri-192.168.5.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 116 (Copy of 218)",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "218",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "trust_dhcp"
      ],
      "destination": [
        "DOSSB_Miri-192.168.5.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "Clone of 116",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": true,
      "security_profile_group": "SPG_IPS_high_security",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "vpn_toDOSSB_KSB_remote",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "toDOSSB_KSB_remote"
      ],
      "destination": [
        "toDOSSB_KSB_local"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "VPN: toDOSSB_KSB (Created by VPN wizard)",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": true,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "219",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "pulse_new_172.16.0.0/24"
      ],
      "destination": [
        "DOSSB_Miri-192.168.5.0/24"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_IPS_default",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "default",
      "application_list": null,
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "266",
      "from_zone": [
        "trust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "DBATT_192.168.10.7",
        "CCTVnvr_192.168.10.8"
      ],
      "destination": [
        "any"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_AV_default_IPS_high_security_WF_deleum_webfilter_APP_deleum",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "deleum_webfilter",
      "application_list": "deleum application control",
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "FortiClient_IPSEC_Internet",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "untrust"
      ],
      "source": [
        "any"
      ],
      "destination": [
        "any"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": "VPN: Test_IPSEC_2 (Created by VPN wizard) (Copy of vpn_Test_IPSEC_2_remote_1) (Copy of )",
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_WF_deleum_webfilter_APP_deleum_application_control",
      "antivirus": "default",
      "ips_sensor": "default",
      "webfilter": "deleum_webfilter",
      "application_list": "deleum application control",
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    },
    {
      "name": "FortiClient_IPSEC_Deny",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "any"
      ],
      "destination": [
        "any"
      ],
      "service": [
        "ALL"
      ],
      "action": "deny",
      "description": " (Copy of FortiClient_IPSEC) (Copy of )",
      "schedule": null,
      "log_start": false,
      "log_end": false,
      "disabled": false,
      "security_profile_group": null,
      "antivirus": null,
      "ips_sensor": null,
      "webfilter": null,
      "application_list": null,
      "ssl_ssh_profile": null,
      "applications": [],
      "internet_service": []
    },
    {
      "name": "FortiClient_IPSEC",
      "from_zone": [
        "untrust"
      ],
      "to_zone": [
        "dmz"
      ],
      "source": [
        "any"
      ],
      "destination": [
        "any"
      ],
      "service": [
        "ALL"
      ],
      "action": "allow",
      "description": null,
      "schedule": null,
      "log_start": true,
      "log_end": true,
      "disabled": false,
      "security_profile_group": "SPG_AV_default_IPS_high_security_WF_deleum_webfilter_APP_deleum",
      "antivirus": "default",
      "ips_sensor": "high_security",
      "webfilter": "deleum_webfilter",
      "application_list": "deleum application control",
      "ssl_ssh_profile": "certificate-inspection",
      "applications": [],
      "internet_service": []
    }
  ],
  "nat_rules": [
    {
      "name": "unifi_60.53.219.65",
      "type": "source",
      "from_zone": [],
      "to_zone": [],
      "source": [],
      "destination": [],
      "service": "any",
      "translated_source": "60.53.219.65",
      "translated_destination": null,
      "translated_port": null,
      "description": null
    },
    {
      "name": "deleumeform.com_60.53.219.68",
      "type": "destination",
      "from_zone": [
        "virtual-wan-link"
      ],
      "to_zone": [],
      "source": [],
      "destination": [
        "deleumeform.com_60.53.219.68"
      ],
      "service": "any",
      "translated_source": null,
      "translated_destination": "192.168.42.26",
      "translated_port": null,
      "description": null
    },
    {
      "name": "deleumintranet.com_60.53.219.67",
      "type": "destination",
      "from_zone": [
        "virtual-wan-link"
      ],
      "to_zone": [],
      "source": [],
      "destination": [
        "deleumintranet.com_60.53.219.67"
      ],
      "service": "any",
      "translated_source": null,
      "translated_destination": "192.168.42.22",
      "translated_port": null,
      "description": null
    },
    {
      "name": "eformproxy_60.53.219.66",
      "type": "destination",
      "from_zone": [
        "virtual-wan-link"
      ],
      "to_zone": [],
      "source": [],
      "destination": [
        "eformproxy_60.53.219.66"
      ],
      "service": "any",
      "translated_source": null,
      "translated_destination": "192.168.42.28",
      "translated_port": null,
      "description": null
    },
    {
      "name": "ess.deleum.com_60.53.219.69",
      "type": "destination",
      "from_zone": [
        "virtual-wan-link"
      ],
      "to_zone": [],
      "source": [],
      "destination": [
        "ess.deleum.com_60.53.219.69"
      ],
      "service": "any",
      "translated_source": null,
      "translated_destination": "192.168.42.10",
      "translated_port": null,
      "description": null
    },
    {
      "name": "secure.deleum.com_175.143.1.50",
      "type": "destination",
      "from_zone": [
        "virtual-wan-link"
      ],
      "to_zone": [],
      "source": [],
      "destination": [
        "secure.deleum.com_175.143.1.50"
      ],
      "service": "any",
      "translated_source": null,
      "translated_destination": "172.16.0.100",
      "translated_port": null,
      "description": null
    }
  ],
  "vpn_tunnels": [
    {
      "name": "toMiriWH",
      "peer_address": "219.93.103.225",
      "local_interface": "unifi_port1",
      "ike_version": "v1",
      "psk": "ENC JfKlUbczQVtaHibM5fMnZ5wPqGv+eP9ziDo30P7xomOlTEQ1buyxNgbyY4PaXVsXEqCyf327sCXxwEEP6GUlLGV6GAgaj9QqMRu5lcnrj5qQExcbmfsfItXsPtVsalhbrYOqGSjUqI6aNl7BGqbMVcN1l9Mhqfd+aKUrU2x/NMHsy/r9BMcg95racx+cY0PQnwWpjFlmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": null
    },
    {
      "name": "to_CKJ_unifi",
      "peer_address": "175.138.111.73",
      "local_interface": "unifi_port1",
      "ike_version": "v1",
      "psk": "ENC K6mcAkgEnSElMP1snKkoIZQvwghWKmzmaZscsDOdkKrQpnQkk/iaiQBFMbpD5mApXkJpYGhtt1JPj12znC1g3YE8v0ful7+pyrBYQjNxaUizM/cZcynB9rUt+bSDzbIoGW7nUnqw3Ud8KHrPCEK75aVf/Qif+EVcjke1qCKAlr3vE65NGDHDCim6gDKhpSMi1yY1Q1lmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": "VPN: to_CKJ_unifi (Created by VPN wizard)"
    },
    {
      "name": "to_DOSSB_Miri",
      "peer_address": "219.93.103.173",
      "local_interface": "unifi_port1",
      "ike_version": "v1",
      "psk": "ENC W6ufPmwcoGtiWAcqkIPVog5OxFF0fPXcqie//qnOYnNGGoDrmPfBQlMKuKoDBMS1uI2D2NKa8Lvnsi9ak1yD/EccJeoJy81FeIWU/BnbFnnh+0Q2vjxoxoU+1Iaqa7jttKiKlDWA5FLvcpnrgwpuNhvqX+AopqrGfQMZ5DNeg02eLwHjPquYtLZjOTZN6xJ75IhzFFlmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": "VPN: to_DOSSB_Miri (Created by VPN wizard)"
    },
    {
      "name": "toDOSSB_KSB",
      "peer_address": "210.186.145.17",
      "local_interface": "unifi_port1",
      "ike_version": "v1",
      "psk": "ENC zQAdlCbtuLftzoo3KqlcWNAD4FXcbapFmqNRgOOD7s4C3QBak1Hc0CpxncVOD0lclRFkDxN5jcWtLP+IxpIMWUWfHxp4+ze7LIBS237pyZBFM8MC9hKBBidaDetxtZksV2PtA3Jnz12eTnJ8E1LwZt868zzWF/SZ35OAsMQBReikn3mr6jNGT/hPhHnLIR0dXM4h5llmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": null
    },
    {
      "name": "toIT_fromHQ",
      "peer_address": "175.143.98.49",
      "local_interface": "unifi_port1",
      "ike_version": "v1",
      "psk": "ENC UMd3wp4CjKIAwrmfS9es7H8yWzbKTB3wPK6bFNrGwJRzzfHLUaiq8lcem5dDaLbfQIoY+TE9CdW4JiQZH1eoiSiW1qbk7BGV1LV7ETehbTd2hyN75yx/qS9KDbhpYFg8Pb0RCkh0c4lIbGJg5x9JeaJ8Hm605riees9/IBKd7ANDz5uKIUTnUsqyCyM/eU+8zImtu1lmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": null
    },
    {
      "name": "toCKJ_secondary",
      "peer_address": "175.138.111.73",
      "local_interface": "unifi2_Vlan",
      "ike_version": "v1",
      "psk": "ENC JYpCnWkO0zcw+iTrZkhI/VnCDdgZJvh5ZXO+sec9wAQK9J08KabZ42nOWQF55MkLgrDfhatB7REm9yDJQQsdyIZvIj5ykMRpOwxQa3n1+NRkVb7PGC7rYrZto4PUC7L6280wG6SX6+kkdTDGQ9i2c1EbdhwwJsEub6xYVn8ujQn6VZ05O/TOSDAZHQgHSceyMHhccllmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": null
    },
    {
      "name": "to_TKY",
      "peer_address": "175.144.112.161",
      "local_interface": "unifi_port1",
      "ike_version": "v1",
      "psk": "ENC 8y9KFANpOsBgD9iteObig4LFc0jn+5T9IzvKxuAL/YF2hyaa6UiGG6AOpSJCtcw/shJpcnhyTuWNiu1yCBbzq/XTA2JuZ+JvwN/hX8kxVKpKCGyaJwgNhEl6qWSxW6d2mqsXUYP4YTwJkZQMXtbFCNb8bJJhysWApkIv8GUyW9f6EjtXYFV2/NuqVT6do3SqksJIbllmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": null
    },
    {
      "name": "toTKY_secondary",
      "peer_address": "175.144.112.161",
      "local_interface": "unifi2_Vlan",
      "ike_version": "v1",
      "psk": "ENC ZpzjPhO3WMOz55Yg39CCXaIUfrzYrtg+7FuuVC6grseWVPxYrpahtHY8z72dDysUmWjcmJ4XVoQ3UW7dz7UVB3kLw5Bj//z79pcFsEixsljSUcCt8dQKCIFDtyo2ZZD4zodzzWmsqqAEPAQaMfTB0kyb2VNx26OASJNmxJI78lvjf3J3RY6Q0dfsA329YpzJksTXL1lmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": null
    },
    {
      "name": "toKSB_secondary",
      "peer_address": "210.186.145.17",
      "local_interface": "unifi2_Vlan",
      "ike_version": "v1",
      "psk": "ENC DTrRNPBqGwSbNfl21Z2NTeHaTC9B8B5xFlym+DpACaszbWcJH1OAOlUhriZaWovbSQdqRHB7oIITxefUUv/a2h4EVb79GZ8iZVA9qSU0TJCjjkq1ifhqnPk/i6nzm4+uBCkUlOzg1ANw5P+r108e5MXvuek3y3pqwlPRAkK9WzU3Ut/EgCVuH74AyfK1QAkWA66SsVlmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": null
    },
    {
      "name": "MiriWHsecondary",
      "peer_address": "219.93.103.225",
      "local_interface": "unifi2_Vlan",
      "ike_version": "v1",
      "psk": "ENC +Xue1XnWNaMMCuxr/EAXI3ldD0+8L6VNlsIMDWeHE+FBezlfygDH8B8prp1ODUcjpsVjo17FDteTWug9SXiZhUdPOd+PtEQSsrLMA+Lsg9dBuoWkUOTXg+KwBTD6Ni7B8Cz9S74wNb7soBBPHj/L/jOyYaVawivH4d+FhDgFDpw6x9I/5dX6GHa+JnBK/tCsGklqL1lmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": null
    },
    {
      "name": "Miri_secondary",
      "peer_address": "219.93.103.173",
      "local_interface": "unifi2_Vlan",
      "ike_version": "v1",
      "psk": "ENC 7L0NoXk2W3ZFXf5z32FJnuYdoiTwRm+Qllk143rvWUbfNNViKHI+6HvILqrzEBBVNCZ0V4te9FsmS4ONUQYzpH54iMr3l+CGVRHI1i6NbOhJ7Ip7K7Zu65iPOiC3g8nnqbuMgo7YblhwW6TXM8vZ1gDPR951E330z5QBJQ1/4vIfjjTZZq7DEjuynzyTH4b0y/fdTFlmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": null
    },
    {
      "name": "toKK_secondary",
      "peer_address": "60.51.57.249",
      "local_interface": "unifi2_Vlan",
      "ike_version": "v1",
      "psk": "ENC nzLsYjRZ3Yyz1F4l0XlFq/0ABaZ5wjXaTqIpAVwdrN0ekobBDe4QKhwd2e6wCA0jFBPkNt+v9N58F2LVdxfyj1Fa41VkQW9RezZFixwCkKofRZP88zlLUdsqqYKGUfMSk0Im/HjMy2SgrBkiWuO8ZpxUNuzUz38mOvbEZlUPKezTwQ/xnPLYBvNI9gcsh+uOeck6lFlmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": null
    },
    {
      "name": "to_KK",
      "peer_address": "60.51.57.249",
      "local_interface": "unifi_port1",
      "ike_version": "v1",
      "psk": "ENC +5FWdjhAmFxgFg+TEq8gK0kd9Ai7dCS0DOICLba5kDdTLj0WITI6Mgidf8DRLmeFN6sFl5t6xzbs9KusJaZP3T2phoSIAYt+HbjQ2co6JkGDTL7jhZspDPx4EaTqz/mqfUQX7seV4NsYllMKU/oTrIHknroRs89lEY6kdKU+/HJ2Wki6TB4JNsVxI5QfZsmlgViesllmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": null
    },
    {
      "name": "toLabuan",
      "peer_address": "175.139.233.117",
      "local_interface": "unifi_port1",
      "ike_version": "v1",
      "psk": "ENC TGSyXPQd3bc3RVubdP2mFkIpBmRgZmdYjuqLwspHPW+xVOKZonTgr4pHvcGdShXZjvm4cN4W2v/ryDISmErSjT9Yf26o3dSMv+OBuXtKjSu8OvIDQGdNDSRe8iJiAOghDlPesNaAivn1r1t7+XrgU9xctZqJqsBSdAMAFEJhEE0I5awbGNdnwT+Tjc0hk01r9+teC1lmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": null
    },
    {
      "name": "toLabuan_second",
      "peer_address": "175.139.233.117",
      "local_interface": "unifi2_Vlan",
      "ike_version": "v1",
      "psk": "ENC Z05FGtwyfPXfXwAXUMuYfe2kAYlJy4MPYDQKdMS/UKnxs2MlDn2zdKX4Pvd3UfWEOvQDKFOHBnQ487PI/4xJ1/A1vGNCglWlmDr+5bcEo0X/j3/Sf0cGn+0SdmtqbKf3UvtyfcSA/O3s0CdYnQdBNtQeqk2szXW/6i259Fo8mF1ZQjBYO9shYBEFvWZEI2MtOlkl2VlmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": null
    },
    {
      "name": "toIT_secondary",
      "peer_address": "175.143.98.49",
      "local_interface": "unifi2_Vlan",
      "ike_version": "v1",
      "psk": "ENC t0+hcWuwBX5oft7QfC81zlwWu1K2Bkxu1uTeVhX6JnXFix0CByi1g3oGdQatzZ8aMFHygPfsM0Ux2v9jFRv5bDQpnjk+i4Z64NztxET1zLQIySxCR9tPFu23rkRURWA7s+4LE7BacbDdJ5/vSb2KtLLWeN7MSTIV0MT8cRu78vCUn9sHQewROLEWaR3hRWpfRkzsaVlmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": null
    },
    {
      "name": "toMiri_DTS",
      "peer_address": "180.74.182.45",
      "local_interface": "unifi_port1",
      "ike_version": "v1",
      "psk": "ENC 06jDFtq+tOQ84ttopzmTaKU2WzEuYdo4F+0Fy12hgW75GdLXm+JGbkRfHPPVblTGUJ6SoZogF9is4rtb3q6KLklRuA9BRvMc5J1jsHJqJRE/3viZ3DzJOv088cUx3gvM/xL7jRYvreRc6BR2ZZbfbI0BWmk8tivx7YMHPfnI/XqyW1Qk+m5sv/n7qMwJnjQfqirUs1lmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": null
    },
    {
      "name": "MiriDTS_second",
      "peer_address": "180.74.182.45",
      "local_interface": "unifi2_Vlan",
      "ike_version": "v1",
      "psk": "ENC h34CrZ3F1ZTpvib8kTwZ48rXrcpc1bUCyGE7j2CCA2yEde76TvM9SqDlI7nl7Bqdf/FXixTxDzDMm46mVaUGuqe4TwXDMBr2yhovN1Zop4qD/WdQFYJtL+WCCJhjnWd9Kp9UHBFOOL2iIhDTh1JV/TJfMlTCc5oOtjelYhf50zGeAq/INOpMd0mAop365BQvaixTZFlmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": null
    },
    {
      "name": "toBintulu1",
      "peer_address": "210.187.179.169",
      "local_interface": "unifi_port1",
      "ike_version": "v1",
      "psk": "ENC YVoUocwSoqi8SjZJ4NQexZI+R5/hjTN6mGzIDr4D700s79QubZvsiqC9mUJ7KgwYVGkoipTja8Rxg0eI8pz8ShDFxkI5dSjJC0TKff6zmXwjIJ7mtBDzRMOVO5lrO7t+uFORX9eEy5H2tLMpZyHur+kCHff62wo5meCtHqv1wdZDtdDroXEZCJ80l8Uoh2wwFMZ2B1lmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": null
    },
    {
      "name": "toBintulu2",
      "peer_address": "180.74.181.209",
      "local_interface": "unifi_port1",
      "ike_version": "v1",
      "psk": "ENC VQcwoCUHJLdGbiCExG8o3+lku031OdxNsTmD0J3Cy+A5hcaktGLFn9eXEKcof2XiSmxaRP4pTxuZQdXLLWz5HDibLh/zl1VtTDJ/5qrD4zvd9566gvsgKBKBdBjdpLGInR/3ryi63rshdO98RYjsxqQ08Wr3ZnUbRHWWCfGC7YCTibhLxfEHJ3FX5eypzbARv5i6cVlmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": null
    },
    {
      "name": "Bintulu1_second",
      "peer_address": "210.187.179.169",
      "local_interface": "unifi2_Vlan",
      "ike_version": "v1",
      "psk": "ENC OssSsHNDg81G53hSs0LDdhf5XIttHcLUyqCKniGs0QtPdNiI202i/hF4DeaSYstPxj6jOQtBA+oLxiVN5jqyI/edQ06VaeThulWhGGjxxSpmU0hCuUhiDF/YirMFLZXViAZEMzJaeLTttQQG09z5L5G+t47gIaSTGh9mKMo5t8x6s182wfZ6v2791wEl9DtRTf9ibllmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": null
    },
    {
      "name": "Bintulu2_second",
      "peer_address": "180.74.181.209",
      "local_interface": "unifi2_Vlan",
      "ike_version": "v1",
      "psk": "ENC RlaQO96ueQPsRzQe7y10vd4Q+m+Et3uQ9T5ianSzkGGD10qGL37o5UBEJgyR+xbxabBiA6+M3T6EqUYkUbcvCFASIWhZtgjYe0fLBDLokvSUdoj4RFXvS7M/uS90L72pi7RhiX4CIjy5xZc+IhBOZxRzSS3tAO38DNpJXoCzDsD6iLSMByLfypkYaFSGXGVbdaMzFllmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": null
    },
    {
      "name": "FortiClient",
      "peer_address": "dynamic",
      "local_interface": "unifi2_Vlan",
      "ike_version": "v2",
      "psk": "ENC DxR/nWdjVe+1jdQonyK19tigP8pyTvRBtWqdzm5MXxjkDIuHGlcY/1iNgqXPDWOYaq5fPm0mfh89zo/0l+3hqsNz8joFqcZrfN7+zgkOtpJ7aTW+NphvewEuthsIKWrZWC4VTRrr6C/+mSqgK5BUd+GJsVdocY8ATjdQCq5l5IADhiMXCABVFGQzShvJuo0VPP1JUllmMjY3dkVA",
      "ike_crypto_profile": "default",
      "ipsec_crypto_profile": "default",
      "description": null
    }
  ],
  "routes": [
    {
      "name": "route_2",
      "destination": "192.168.2.0/24",
      "interface": "HQ_Vlan20",
      "next_hop": "10.10.2.254",
      "metric": 5,
      "description": null
    },
    {
      "name": "route_4",
      "destination": "0.0.0.0/0",
      "interface": null,
      "next_hop": null,
      "metric": 1,
      "description": null
    },
    {
      "name": "route_6",
      "destination": "192.168.7.0/24",
      "interface": "HQ_Vlan70",
      "next_hop": "10.10.7.254",
      "metric": 7,
      "description": null
    },
    {
      "name": "route_9",
      "destination": "10.10.77.0/24",
      "interface": "HQ_Vlan70",
      "next_hop": "10.10.7.254",
      "metric": 7,
      "description": null
    },
    {
      "name": "route_23",
      "destination": "192.168.8.0/24",
      "interface": "toMiriWH",
      "next_hop": null,
      "metric": 5,
      "description": null
    },
    {
      "name": "route_26",
      "destination": "192.168.43.0/24",
      "interface": "toIT_fromHQ",
      "next_hop": null,
      "metric": 4,
      "description": null
    },
    {
      "name": "route_29",
      "destination": "192.168.14.0/24",
      "interface": "to_CKJ_unifi",
      "next_hop": null,
      "metric": 6,
      "description": "VPN: to_CKJ_unifi (Created by VPN wizard)"
    },
    {
      "name": "route_30",
      "destination": "0.0.0.0/0",
      "interface": null,
      "next_hop": null,
      "metric": 254,
      "description": "VPN: to_CKJ_unifi (Created by VPN wizard)"
    },
    {
      "name": "route_31",
      "destination": "10.10.22.0/24",
      "interface": "HQ_Vlan20",
      "next_hop": "10.10.2.254",
      "metric": 5,
      "description": null
    },
    {
      "name": "route_32",
      "destination": "192.168.5.0/24",
      "interface": "to_DOSSB_Miri",
      "next_hop": null,
      "metric": 6,
      "description": "VPN: to_DOSSB_Miri (Created by VPN wizard)"
    },
    {
      "name": "route_33",
      "destination": "0.0.0.0/0",
      "interface": null,
      "next_hop": null,
      "metric": 254,
      "description": "VPN: to_DOSSB_Miri (Created by VPN wizard)"
    },
    {
      "name": "route_22",
      "destination": "0.0.0.0/0",
      "interface": "port4",
      "next_hop": "103.27.106.129",
      "metric": 10,
      "description": null
    },
    {
      "name": "route_27",
      "destination": "0.0.0.0/0",
      "interface": "toDOSSB_KSB",
      "next_hop": null,
      "metric": 6,
      "description": "VPN: toDOSSB_KSB (Created by VPN wizard)"
    },
    {
      "name": "route_34",
      "destination": "0.0.0.0/0",
      "interface": null,
      "next_hop": null,
      "metric": 254,
      "description": "VPN: toDOSSB_KSB (Created by VPN wizard)"
    },
    {
      "name": "route_35",
      "destination": "192.168.4.0/24",
      "interface": "toDOSSB_KSB",
      "next_hop": null,
      "metric": 6,
      "description": null
    },
    {
      "name": "route_36",
      "destination": "192.168.111.0/24",
      "interface": "toIT_fromHQ",
      "next_hop": null,
      "metric": 4,
      "description": null
    },
    {
      "name": "route_37",
      "destination": "192.168.14.0/24",
      "interface": "toCKJ_secondary",
      "next_hop": null,
      "metric": 4,
      "description": null
    },
    {
      "name": "route_38",
      "destination": "172.16.0.0/16",
      "interface": "port2",
      "next_hop": "172.16.1.1",
      "metric": 6,
      "description": null
    },
    {
      "name": "route_40",
      "destination": "192.168.13.0/24",
      "interface": "to_KK",
      "next_hop": null,
      "metric": 6,
      "description": null
    },
    {
      "name": "route_41",
      "destination": "192.168.111.0/24",
      "interface": "port2",
      "next_hop": "172.16.1.1",
      "metric": 5,
      "description": null
    },
    {
      "name": "route_25",
      "destination": "192.168.7.0/24",
      "interface": "to_TKY",
      "next_hop": null,
      "metric": 6,
      "description": null
    },
    {
      "name": "route_28",
      "destination": "192.168.7.0/24",
      "interface": "toTKY_secondary",
      "next_hop": null,
      "metric": 4,
      "description": null
    },
    {
      "name": "route_24",
      "destination": "192.168.4.0/24",
      "interface": "toKSB_secondary",
      "next_hop": null,
      "metric": 4,
      "description": null
    },
    {
      "name": "route_39",
      "destination": "192.168.8.0/24",
      "interface": "MiriWHsecondary",
      "next_hop": null,
      "metric": 4,
      "description": null
    },
    {
      "name": "route_42",
      "destination": "192.168.5.0/24",
      "interface": "Miri_secondary",
      "next_hop": null,
      "metric": 4,
      "description": null
    },
    {
      "name": "route_43",
      "destination": "192.168.13.0/24",
      "interface": "toKK_secondary",
      "next_hop": null,
      "metric": 4,
      "description": null
    },
    {
      "name": "route_44",
      "destination": "192.168.2.0/24",
      "interface": "toLabuan",
      "next_hop": null,
      "metric": 6,
      "description": null
    },
    {
      "name": "route_45",
      "destination": "192.168.2.0/24",
      "interface": "toLabuan_second",
      "next_hop": null,
      "metric": 4,
      "description": null
    },
    {
      "name": "route_46",
      "destination": "10.10.22.0/24",
      "interface": "toLabuan",
      "next_hop": null,
      "metric": 6,
      "description": null
    },
    {
      "name": "route_47",
      "destination": "10.10.22.0/24",
      "interface": "toLabuan_second",
      "next_hop": null,
      "metric": 4,
      "description": null
    },
    {
      "name": "route_48",
      "destination": "192.168.111.0/24",
      "interface": "toIT_secondary",
      "next_hop": null,
      "metric": 6,
      "description": null
    },
    {
      "name": "route_49",
      "destination": "0.0.0.0/0",
      "interface": "unifi2_Vlan",
      "next_hop": null,
      "metric": 10,
      "description": null
    },
    {
      "name": "route_50",
      "destination": "0.0.0.0/0",
      "interface": "unifi3",
      "next_hop": null,
      "metric": 10,
      "description": null
    },
    {
      "name": "route_51",
      "destination": "192.168.6.0/24",
      "interface": "toMiri_DTS",
      "next_hop": null,
      "metric": 6,
      "description": null
    },
    {
      "name": "route_52",
      "destination": "192.168.6.0/24",
      "interface": "MiriDTS_second",
      "next_hop": null,
      "metric": 4,
      "description": null
    },
    {
      "name": "route_53",
      "destination": "192.168.11.0/24",
      "interface": "toBintulu1",
      "next_hop": null,
      "metric": 6,
      "description": null
    },
    {
      "name": "route_54",
      "destination": "192.168.3.0/24",
      "interface": "toBintulu2",
      "next_hop": null,
      "metric": 6,
      "description": null
    },
    {
      "name": "route_55",
      "destination": "192.168.11.0/24",
      "interface": "Bintulu1_second",
      "next_hop": null,
      "metric": 4,
      "description": null
    },
    {
      "name": "route_56",
      "destination": "192.168.3.0/24",
      "interface": "Bintulu2_second",
      "next_hop": null,
      "metric": 4,
      "description": null
    }
  ],
  "internet_services": [
    {
      "name": "Google-Other",
      "description": null
    },
    {
      "name": "Google-Web",
      "description": null
    },
    {
      "name": "Google-ICMP",
      "description": null
    },
    {
      "name": "Google-DNS",
      "description": null
    },
    {
      "name": "Google-Outbound_Email",
      "description": null
    },
    {
      "name": "Google-SSH",
      "description": null
    },
    {
      "name": "Google-FTP",
      "description": null
    },
    {
      "name": "Google-NTP",
      "description": null
    },
    {
      "name": "Google-Inbound_Email",
      "description": null
    },
    {
      "name": "Google-LDAP",
      "description": null
    },
    {
      "name": "Google-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Google-RTMP",
      "description": null
    },
    {
      "name": "Google-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Google-Google.Cloud",
      "description": null
    },
    {
      "name": "Google-Google.Bot",
      "description": null
    },
    {
      "name": "Google-Gmail",
      "description": null
    },
    {
      "name": "Meta-Other",
      "description": null
    },
    {
      "name": "Meta-Web",
      "description": null
    },
    {
      "name": "Meta-ICMP",
      "description": null
    },
    {
      "name": "Meta-DNS",
      "description": null
    },
    {
      "name": "Meta-Outbound_Email",
      "description": null
    },
    {
      "name": "Meta-SSH",
      "description": null
    },
    {
      "name": "Meta-FTP",
      "description": null
    },
    {
      "name": "Meta-NTP",
      "description": null
    },
    {
      "name": "Meta-Inbound_Email",
      "description": null
    },
    {
      "name": "Meta-LDAP",
      "description": null
    },
    {
      "name": "Meta-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Meta-RTMP",
      "description": null
    },
    {
      "name": "Meta-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Meta-Whatsapp",
      "description": null
    },
    {
      "name": "Meta-Instagram",
      "description": null
    },
    {
      "name": "Apple-Other",
      "description": null
    },
    {
      "name": "Apple-Web",
      "description": null
    },
    {
      "name": "Apple-ICMP",
      "description": null
    },
    {
      "name": "Apple-DNS",
      "description": null
    },
    {
      "name": "Apple-Outbound_Email",
      "description": null
    },
    {
      "name": "Apple-SSH",
      "description": null
    },
    {
      "name": "Apple-FTP",
      "description": null
    },
    {
      "name": "Apple-NTP",
      "description": null
    },
    {
      "name": "Apple-Inbound_Email",
      "description": null
    },
    {
      "name": "Apple-LDAP",
      "description": null
    },
    {
      "name": "Apple-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Apple-RTMP",
      "description": null
    },
    {
      "name": "Apple-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Apple-App.Store",
      "description": null
    },
    {
      "name": "Apple-APNs",
      "description": null
    },
    {
      "name": "Yahoo-Other",
      "description": null
    },
    {
      "name": "Yahoo-Web",
      "description": null
    },
    {
      "name": "Yahoo-ICMP",
      "description": null
    },
    {
      "name": "Yahoo-DNS",
      "description": null
    },
    {
      "name": "Yahoo-Outbound_Email",
      "description": null
    },
    {
      "name": "Yahoo-SSH",
      "description": null
    },
    {
      "name": "Yahoo-FTP",
      "description": null
    },
    {
      "name": "Yahoo-NTP",
      "description": null
    },
    {
      "name": "Yahoo-Inbound_Email",
      "description": null
    },
    {
      "name": "Yahoo-LDAP",
      "description": null
    },
    {
      "name": "Yahoo-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Yahoo-RTMP",
      "description": null
    },
    {
      "name": "Yahoo-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Microsoft-Other",
      "description": null
    },
    {
      "name": "Microsoft-Web",
      "description": null
    },
    {
      "name": "Microsoft-ICMP",
      "description": null
    },
    {
      "name": "Microsoft-DNS",
      "description": null
    },
    {
      "name": "Microsoft-Outbound_Email",
      "description": null
    },
    {
      "name": "Microsoft-SSH",
      "description": null
    },
    {
      "name": "Microsoft-FTP",
      "description": null
    },
    {
      "name": "Microsoft-NTP",
      "description": null
    },
    {
      "name": "Microsoft-Inbound_Email",
      "description": null
    },
    {
      "name": "Microsoft-LDAP",
      "description": null
    },
    {
      "name": "Microsoft-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Microsoft-RTMP",
      "description": null
    },
    {
      "name": "Microsoft-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Microsoft-Skype_Teams",
      "description": null
    },
    {
      "name": "Microsoft-Office365",
      "description": null
    },
    {
      "name": "Microsoft-Azure",
      "description": null
    },
    {
      "name": "Microsoft-Bing.Bot",
      "description": null
    },
    {
      "name": "Microsoft-Outlook",
      "description": null
    },
    {
      "name": "Microsoft-Microsoft.Update",
      "description": null
    },
    {
      "name": "Microsoft-Dynamics",
      "description": null
    },
    {
      "name": "Microsoft-WNS",
      "description": null
    },
    {
      "name": "Microsoft-Office365.Published",
      "description": null
    },
    {
      "name": "Amazon-Other",
      "description": null
    },
    {
      "name": "Amazon-Web",
      "description": null
    },
    {
      "name": "Amazon-ICMP",
      "description": null
    },
    {
      "name": "Amazon-DNS",
      "description": null
    },
    {
      "name": "Amazon-Outbound_Email",
      "description": null
    },
    {
      "name": "Amazon-SSH",
      "description": null
    },
    {
      "name": "Amazon-FTP",
      "description": null
    },
    {
      "name": "Amazon-NTP",
      "description": null
    },
    {
      "name": "Amazon-Inbound_Email",
      "description": null
    },
    {
      "name": "Amazon-LDAP",
      "description": null
    },
    {
      "name": "Amazon-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Amazon-RTMP",
      "description": null
    },
    {
      "name": "Amazon-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Amazon-AWS",
      "description": null
    },
    {
      "name": "Amazon-AWS.WorkSpaces.Gateway",
      "description": null
    },
    {
      "name": "eBay-Other",
      "description": null
    },
    {
      "name": "eBay-Web",
      "description": null
    },
    {
      "name": "eBay-ICMP",
      "description": null
    },
    {
      "name": "eBay-DNS",
      "description": null
    },
    {
      "name": "eBay-Outbound_Email",
      "description": null
    },
    {
      "name": "eBay-SSH",
      "description": null
    },
    {
      "name": "eBay-FTP",
      "description": null
    },
    {
      "name": "eBay-NTP",
      "description": null
    },
    {
      "name": "eBay-Inbound_Email",
      "description": null
    },
    {
      "name": "eBay-LDAP",
      "description": null
    },
    {
      "name": "eBay-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "eBay-RTMP",
      "description": null
    },
    {
      "name": "eBay-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "PayPal-Other",
      "description": null
    },
    {
      "name": "PayPal-Web",
      "description": null
    },
    {
      "name": "PayPal-ICMP",
      "description": null
    },
    {
      "name": "PayPal-DNS",
      "description": null
    },
    {
      "name": "PayPal-Outbound_Email",
      "description": null
    },
    {
      "name": "PayPal-SSH",
      "description": null
    },
    {
      "name": "PayPal-FTP",
      "description": null
    },
    {
      "name": "PayPal-NTP",
      "description": null
    },
    {
      "name": "PayPal-Inbound_Email",
      "description": null
    },
    {
      "name": "PayPal-LDAP",
      "description": null
    },
    {
      "name": "PayPal-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "PayPal-RTMP",
      "description": null
    },
    {
      "name": "PayPal-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Box-Other",
      "description": null
    },
    {
      "name": "Box-Web",
      "description": null
    },
    {
      "name": "Box-ICMP",
      "description": null
    },
    {
      "name": "Box-DNS",
      "description": null
    },
    {
      "name": "Box-Outbound_Email",
      "description": null
    },
    {
      "name": "Box-SSH",
      "description": null
    },
    {
      "name": "Box-FTP",
      "description": null
    },
    {
      "name": "Box-NTP",
      "description": null
    },
    {
      "name": "Box-Inbound_Email",
      "description": null
    },
    {
      "name": "Box-LDAP",
      "description": null
    },
    {
      "name": "Box-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Box-RTMP",
      "description": null
    },
    {
      "name": "Box-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Salesforce-Other",
      "description": null
    },
    {
      "name": "Salesforce-Web",
      "description": null
    },
    {
      "name": "Salesforce-ICMP",
      "description": null
    },
    {
      "name": "Salesforce-DNS",
      "description": null
    },
    {
      "name": "Salesforce-Outbound_Email",
      "description": null
    },
    {
      "name": "Salesforce-SSH",
      "description": null
    },
    {
      "name": "Salesforce-FTP",
      "description": null
    },
    {
      "name": "Salesforce-NTP",
      "description": null
    },
    {
      "name": "Salesforce-Inbound_Email",
      "description": null
    },
    {
      "name": "Salesforce-LDAP",
      "description": null
    },
    {
      "name": "Salesforce-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Salesforce-RTMP",
      "description": null
    },
    {
      "name": "Salesforce-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Salesforce-Email.Relay",
      "description": null
    },
    {
      "name": "Dropbox-Other",
      "description": null
    },
    {
      "name": "Dropbox-Web",
      "description": null
    },
    {
      "name": "Dropbox-ICMP",
      "description": null
    },
    {
      "name": "Dropbox-DNS",
      "description": null
    },
    {
      "name": "Dropbox-Outbound_Email",
      "description": null
    },
    {
      "name": "Dropbox-SSH",
      "description": null
    },
    {
      "name": "Dropbox-FTP",
      "description": null
    },
    {
      "name": "Dropbox-NTP",
      "description": null
    },
    {
      "name": "Dropbox-Inbound_Email",
      "description": null
    },
    {
      "name": "Dropbox-LDAP",
      "description": null
    },
    {
      "name": "Dropbox-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Dropbox-RTMP",
      "description": null
    },
    {
      "name": "Dropbox-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Netflix-Other",
      "description": null
    },
    {
      "name": "Netflix-Web",
      "description": null
    },
    {
      "name": "Netflix-ICMP",
      "description": null
    },
    {
      "name": "Netflix-DNS",
      "description": null
    },
    {
      "name": "Netflix-Outbound_Email",
      "description": null
    },
    {
      "name": "Netflix-SSH",
      "description": null
    },
    {
      "name": "Netflix-FTP",
      "description": null
    },
    {
      "name": "Netflix-NTP",
      "description": null
    },
    {
      "name": "Netflix-Inbound_Email",
      "description": null
    },
    {
      "name": "Netflix-LDAP",
      "description": null
    },
    {
      "name": "Netflix-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Netflix-RTMP",
      "description": null
    },
    {
      "name": "Netflix-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "LinkedIn-Other",
      "description": null
    },
    {
      "name": "LinkedIn-Web",
      "description": null
    },
    {
      "name": "LinkedIn-ICMP",
      "description": null
    },
    {
      "name": "LinkedIn-DNS",
      "description": null
    },
    {
      "name": "LinkedIn-Outbound_Email",
      "description": null
    },
    {
      "name": "LinkedIn-SSH",
      "description": null
    },
    {
      "name": "LinkedIn-FTP",
      "description": null
    },
    {
      "name": "LinkedIn-NTP",
      "description": null
    },
    {
      "name": "LinkedIn-Inbound_Email",
      "description": null
    },
    {
      "name": "LinkedIn-LDAP",
      "description": null
    },
    {
      "name": "LinkedIn-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "LinkedIn-RTMP",
      "description": null
    },
    {
      "name": "LinkedIn-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Adobe-Other",
      "description": null
    },
    {
      "name": "Adobe-Web",
      "description": null
    },
    {
      "name": "Adobe-ICMP",
      "description": null
    },
    {
      "name": "Adobe-DNS",
      "description": null
    },
    {
      "name": "Adobe-Outbound_Email",
      "description": null
    },
    {
      "name": "Adobe-SSH",
      "description": null
    },
    {
      "name": "Adobe-FTP",
      "description": null
    },
    {
      "name": "Adobe-NTP",
      "description": null
    },
    {
      "name": "Adobe-Inbound_Email",
      "description": null
    },
    {
      "name": "Adobe-LDAP",
      "description": null
    },
    {
      "name": "Adobe-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Adobe-RTMP",
      "description": null
    },
    {
      "name": "Adobe-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Adobe-Adobe.Experience.Cloud",
      "description": null
    },
    {
      "name": "Oracle-Other",
      "description": null
    },
    {
      "name": "Oracle-Web",
      "description": null
    },
    {
      "name": "Oracle-ICMP",
      "description": null
    },
    {
      "name": "Oracle-DNS",
      "description": null
    },
    {
      "name": "Oracle-Outbound_Email",
      "description": null
    },
    {
      "name": "Oracle-SSH",
      "description": null
    },
    {
      "name": "Oracle-FTP",
      "description": null
    },
    {
      "name": "Oracle-NTP",
      "description": null
    },
    {
      "name": "Oracle-Inbound_Email",
      "description": null
    },
    {
      "name": "Oracle-LDAP",
      "description": null
    },
    {
      "name": "Oracle-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Oracle-RTMP",
      "description": null
    },
    {
      "name": "Oracle-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Oracle-Oracle.Cloud",
      "description": null
    },
    {
      "name": "Hulu-Other",
      "description": null
    },
    {
      "name": "Hulu-Web",
      "description": null
    },
    {
      "name": "Hulu-ICMP",
      "description": null
    },
    {
      "name": "Hulu-DNS",
      "description": null
    },
    {
      "name": "Hulu-Outbound_Email",
      "description": null
    },
    {
      "name": "Hulu-SSH",
      "description": null
    },
    {
      "name": "Hulu-FTP",
      "description": null
    },
    {
      "name": "Hulu-NTP",
      "description": null
    },
    {
      "name": "Hulu-Inbound_Email",
      "description": null
    },
    {
      "name": "Hulu-LDAP",
      "description": null
    },
    {
      "name": "Hulu-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Hulu-RTMP",
      "description": null
    },
    {
      "name": "Hulu-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Pinterest-Other",
      "description": null
    },
    {
      "name": "Pinterest-Web",
      "description": null
    },
    {
      "name": "Pinterest-ICMP",
      "description": null
    },
    {
      "name": "Pinterest-DNS",
      "description": null
    },
    {
      "name": "Pinterest-Outbound_Email",
      "description": null
    },
    {
      "name": "Pinterest-SSH",
      "description": null
    },
    {
      "name": "Pinterest-FTP",
      "description": null
    },
    {
      "name": "Pinterest-NTP",
      "description": null
    },
    {
      "name": "Pinterest-Inbound_Email",
      "description": null
    },
    {
      "name": "Pinterest-LDAP",
      "description": null
    },
    {
      "name": "Pinterest-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Pinterest-RTMP",
      "description": null
    },
    {
      "name": "Pinterest-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "LogMeIn-Other",
      "description": null
    },
    {
      "name": "LogMeIn-Web",
      "description": null
    },
    {
      "name": "LogMeIn-ICMP",
      "description": null
    },
    {
      "name": "LogMeIn-DNS",
      "description": null
    },
    {
      "name": "LogMeIn-Outbound_Email",
      "description": null
    },
    {
      "name": "LogMeIn-SSH",
      "description": null
    },
    {
      "name": "LogMeIn-FTP",
      "description": null
    },
    {
      "name": "LogMeIn-NTP",
      "description": null
    },
    {
      "name": "LogMeIn-Inbound_Email",
      "description": null
    },
    {
      "name": "LogMeIn-LDAP",
      "description": null
    },
    {
      "name": "LogMeIn-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "LogMeIn-RTMP",
      "description": null
    },
    {
      "name": "LogMeIn-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "LogMeIn-GoTo.Suite",
      "description": null
    },
    {
      "name": "Fortinet-Other",
      "description": null
    },
    {
      "name": "Fortinet-Web",
      "description": null
    },
    {
      "name": "Fortinet-ICMP",
      "description": null
    },
    {
      "name": "Fortinet-DNS",
      "description": null
    },
    {
      "name": "Fortinet-Outbound_Email",
      "description": null
    },
    {
      "name": "Fortinet-SSH",
      "description": null
    },
    {
      "name": "Fortinet-FTP",
      "description": null
    },
    {
      "name": "Fortinet-NTP",
      "description": null
    },
    {
      "name": "Fortinet-Inbound_Email",
      "description": null
    },
    {
      "name": "Fortinet-LDAP",
      "description": null
    },
    {
      "name": "Fortinet-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Fortinet-RTMP",
      "description": null
    },
    {
      "name": "Fortinet-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Fortinet-FortiGuard",
      "description": null
    },
    {
      "name": "Fortinet-FortiMail.Cloud",
      "description": null
    },
    {
      "name": "Fortinet-FortiCloud",
      "description": null
    },
    {
      "name": "Kaspersky-Other",
      "description": null
    },
    {
      "name": "Kaspersky-Web",
      "description": null
    },
    {
      "name": "Kaspersky-ICMP",
      "description": null
    },
    {
      "name": "Kaspersky-DNS",
      "description": null
    },
    {
      "name": "Kaspersky-Outbound_Email",
      "description": null
    },
    {
      "name": "Kaspersky-SSH",
      "description": null
    },
    {
      "name": "Kaspersky-FTP",
      "description": null
    },
    {
      "name": "Kaspersky-NTP",
      "description": null
    },
    {
      "name": "Kaspersky-Inbound_Email",
      "description": null
    },
    {
      "name": "Kaspersky-LDAP",
      "description": null
    },
    {
      "name": "Kaspersky-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Kaspersky-RTMP",
      "description": null
    },
    {
      "name": "Kaspersky-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "McAfee-Other",
      "description": null
    },
    {
      "name": "McAfee-Web",
      "description": null
    },
    {
      "name": "McAfee-ICMP",
      "description": null
    },
    {
      "name": "McAfee-DNS",
      "description": null
    },
    {
      "name": "McAfee-Outbound_Email",
      "description": null
    },
    {
      "name": "McAfee-SSH",
      "description": null
    },
    {
      "name": "McAfee-FTP",
      "description": null
    },
    {
      "name": "McAfee-NTP",
      "description": null
    },
    {
      "name": "McAfee-Inbound_Email",
      "description": null
    },
    {
      "name": "McAfee-LDAP",
      "description": null
    },
    {
      "name": "McAfee-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "McAfee-RTMP",
      "description": null
    },
    {
      "name": "McAfee-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Symantec-Other",
      "description": null
    },
    {
      "name": "Symantec-Web",
      "description": null
    },
    {
      "name": "Symantec-ICMP",
      "description": null
    },
    {
      "name": "Symantec-DNS",
      "description": null
    },
    {
      "name": "Symantec-Outbound_Email",
      "description": null
    },
    {
      "name": "Symantec-SSH",
      "description": null
    },
    {
      "name": "Symantec-FTP",
      "description": null
    },
    {
      "name": "Symantec-NTP",
      "description": null
    },
    {
      "name": "Symantec-Inbound_Email",
      "description": null
    },
    {
      "name": "Symantec-LDAP",
      "description": null
    },
    {
      "name": "Symantec-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Symantec-RTMP",
      "description": null
    },
    {
      "name": "Symantec-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Symantec-Symantec.Cloud",
      "description": null
    },
    {
      "name": "VMware-Other",
      "description": null
    },
    {
      "name": "VMware-Web",
      "description": null
    },
    {
      "name": "VMware-ICMP",
      "description": null
    },
    {
      "name": "VMware-DNS",
      "description": null
    },
    {
      "name": "VMware-Outbound_Email",
      "description": null
    },
    {
      "name": "VMware-SSH",
      "description": null
    },
    {
      "name": "VMware-FTP",
      "description": null
    },
    {
      "name": "VMware-NTP",
      "description": null
    },
    {
      "name": "VMware-Inbound_Email",
      "description": null
    },
    {
      "name": "VMware-LDAP",
      "description": null
    },
    {
      "name": "VMware-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "VMware-RTMP",
      "description": null
    },
    {
      "name": "VMware-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "VMware-Workspace.ONE",
      "description": null
    },
    {
      "name": "AOL-Other",
      "description": null
    },
    {
      "name": "AOL-Web",
      "description": null
    },
    {
      "name": "AOL-ICMP",
      "description": null
    },
    {
      "name": "AOL-DNS",
      "description": null
    },
    {
      "name": "AOL-Outbound_Email",
      "description": null
    },
    {
      "name": "AOL-SSH",
      "description": null
    },
    {
      "name": "AOL-FTP",
      "description": null
    },
    {
      "name": "AOL-NTP",
      "description": null
    },
    {
      "name": "AOL-Inbound_Email",
      "description": null
    },
    {
      "name": "AOL-LDAP",
      "description": null
    },
    {
      "name": "AOL-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "AOL-RTMP",
      "description": null
    },
    {
      "name": "AOL-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "RealNetworks-Other",
      "description": null
    },
    {
      "name": "RealNetworks-Web",
      "description": null
    },
    {
      "name": "RealNetworks-ICMP",
      "description": null
    },
    {
      "name": "RealNetworks-DNS",
      "description": null
    },
    {
      "name": "RealNetworks-Outbound_Email",
      "description": null
    },
    {
      "name": "RealNetworks-SSH",
      "description": null
    },
    {
      "name": "RealNetworks-FTP",
      "description": null
    },
    {
      "name": "RealNetworks-NTP",
      "description": null
    },
    {
      "name": "RealNetworks-Inbound_Email",
      "description": null
    },
    {
      "name": "RealNetworks-LDAP",
      "description": null
    },
    {
      "name": "RealNetworks-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "RealNetworks-RTMP",
      "description": null
    },
    {
      "name": "RealNetworks-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Zoho-Other",
      "description": null
    },
    {
      "name": "Zoho-Web",
      "description": null
    },
    {
      "name": "Zoho-ICMP",
      "description": null
    },
    {
      "name": "Zoho-DNS",
      "description": null
    },
    {
      "name": "Zoho-Outbound_Email",
      "description": null
    },
    {
      "name": "Zoho-SSH",
      "description": null
    },
    {
      "name": "Zoho-FTP",
      "description": null
    },
    {
      "name": "Zoho-NTP",
      "description": null
    },
    {
      "name": "Zoho-Inbound_Email",
      "description": null
    },
    {
      "name": "Zoho-LDAP",
      "description": null
    },
    {
      "name": "Zoho-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Zoho-RTMP",
      "description": null
    },
    {
      "name": "Zoho-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Mozilla-Other",
      "description": null
    },
    {
      "name": "Mozilla-Web",
      "description": null
    },
    {
      "name": "Mozilla-ICMP",
      "description": null
    },
    {
      "name": "Mozilla-DNS",
      "description": null
    },
    {
      "name": "Mozilla-Outbound_Email",
      "description": null
    },
    {
      "name": "Mozilla-SSH",
      "description": null
    },
    {
      "name": "Mozilla-FTP",
      "description": null
    },
    {
      "name": "Mozilla-NTP",
      "description": null
    },
    {
      "name": "Mozilla-Inbound_Email",
      "description": null
    },
    {
      "name": "Mozilla-LDAP",
      "description": null
    },
    {
      "name": "Mozilla-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Mozilla-RTMP",
      "description": null
    },
    {
      "name": "Mozilla-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "TeamViewer-Other",
      "description": null
    },
    {
      "name": "TeamViewer-Web",
      "description": null
    },
    {
      "name": "TeamViewer-ICMP",
      "description": null
    },
    {
      "name": "TeamViewer-DNS",
      "description": null
    },
    {
      "name": "TeamViewer-Outbound_Email",
      "description": null
    },
    {
      "name": "TeamViewer-SSH",
      "description": null
    },
    {
      "name": "TeamViewer-FTP",
      "description": null
    },
    {
      "name": "TeamViewer-NTP",
      "description": null
    },
    {
      "name": "TeamViewer-Inbound_Email",
      "description": null
    },
    {
      "name": "TeamViewer-LDAP",
      "description": null
    },
    {
      "name": "TeamViewer-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "TeamViewer-RTMP",
      "description": null
    },
    {
      "name": "TeamViewer-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "TeamViewer-TeamViewer",
      "description": null
    },
    {
      "name": "HP-Other",
      "description": null
    },
    {
      "name": "HP-Web",
      "description": null
    },
    {
      "name": "HP-ICMP",
      "description": null
    },
    {
      "name": "HP-DNS",
      "description": null
    },
    {
      "name": "HP-Outbound_Email",
      "description": null
    },
    {
      "name": "HP-SSH",
      "description": null
    },
    {
      "name": "HP-FTP",
      "description": null
    },
    {
      "name": "HP-NTP",
      "description": null
    },
    {
      "name": "HP-Inbound_Email",
      "description": null
    },
    {
      "name": "HP-LDAP",
      "description": null
    },
    {
      "name": "HP-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "HP-RTMP",
      "description": null
    },
    {
      "name": "HP-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "HP-Aruba",
      "description": null
    },
    {
      "name": "Cisco-Other",
      "description": null
    },
    {
      "name": "Cisco-Web",
      "description": null
    },
    {
      "name": "Cisco-ICMP",
      "description": null
    },
    {
      "name": "Cisco-DNS",
      "description": null
    },
    {
      "name": "Cisco-Outbound_Email",
      "description": null
    },
    {
      "name": "Cisco-SSH",
      "description": null
    },
    {
      "name": "Cisco-FTP",
      "description": null
    },
    {
      "name": "Cisco-NTP",
      "description": null
    },
    {
      "name": "Cisco-Inbound_Email",
      "description": null
    },
    {
      "name": "Cisco-LDAP",
      "description": null
    },
    {
      "name": "Cisco-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Cisco-RTMP",
      "description": null
    },
    {
      "name": "Cisco-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Cisco-Webex",
      "description": null
    },
    {
      "name": "Cisco-Meraki.Cloud",
      "description": null
    },
    {
      "name": "Cisco-Duo.Security",
      "description": null
    },
    {
      "name": "Cisco-AppDynamic",
      "description": null
    },
    {
      "name": "IBM-Other",
      "description": null
    },
    {
      "name": "IBM-Web",
      "description": null
    },
    {
      "name": "IBM-ICMP",
      "description": null
    },
    {
      "name": "IBM-DNS",
      "description": null
    },
    {
      "name": "IBM-Outbound_Email",
      "description": null
    },
    {
      "name": "IBM-SSH",
      "description": null
    },
    {
      "name": "IBM-FTP",
      "description": null
    },
    {
      "name": "IBM-NTP",
      "description": null
    },
    {
      "name": "IBM-Inbound_Email",
      "description": null
    },
    {
      "name": "IBM-LDAP",
      "description": null
    },
    {
      "name": "IBM-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "IBM-RTMP",
      "description": null
    },
    {
      "name": "IBM-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "IBM-IBM.Cloud",
      "description": null
    },
    {
      "name": "Citrix-Other",
      "description": null
    },
    {
      "name": "Citrix-Web",
      "description": null
    },
    {
      "name": "Citrix-ICMP",
      "description": null
    },
    {
      "name": "Citrix-DNS",
      "description": null
    },
    {
      "name": "Citrix-Outbound_Email",
      "description": null
    },
    {
      "name": "Citrix-SSH",
      "description": null
    },
    {
      "name": "Citrix-FTP",
      "description": null
    },
    {
      "name": "Citrix-NTP",
      "description": null
    },
    {
      "name": "Citrix-Inbound_Email",
      "description": null
    },
    {
      "name": "Citrix-LDAP",
      "description": null
    },
    {
      "name": "Citrix-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Citrix-RTMP",
      "description": null
    },
    {
      "name": "Citrix-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Twitter-Other",
      "description": null
    },
    {
      "name": "Twitter-Web",
      "description": null
    },
    {
      "name": "Twitter-ICMP",
      "description": null
    },
    {
      "name": "Twitter-DNS",
      "description": null
    },
    {
      "name": "Twitter-Outbound_Email",
      "description": null
    },
    {
      "name": "Twitter-SSH",
      "description": null
    },
    {
      "name": "Twitter-FTP",
      "description": null
    },
    {
      "name": "Twitter-NTP",
      "description": null
    },
    {
      "name": "Twitter-Inbound_Email",
      "description": null
    },
    {
      "name": "Twitter-LDAP",
      "description": null
    },
    {
      "name": "Twitter-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Twitter-RTMP",
      "description": null
    },
    {
      "name": "Twitter-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Dell-Other",
      "description": null
    },
    {
      "name": "Dell-Web",
      "description": null
    },
    {
      "name": "Dell-ICMP",
      "description": null
    },
    {
      "name": "Dell-DNS",
      "description": null
    },
    {
      "name": "Dell-Outbound_Email",
      "description": null
    },
    {
      "name": "Dell-SSH",
      "description": null
    },
    {
      "name": "Dell-FTP",
      "description": null
    },
    {
      "name": "Dell-NTP",
      "description": null
    },
    {
      "name": "Dell-Inbound_Email",
      "description": null
    },
    {
      "name": "Dell-LDAP",
      "description": null
    },
    {
      "name": "Dell-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Dell-RTMP",
      "description": null
    },
    {
      "name": "Dell-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Vimeo-Other",
      "description": null
    },
    {
      "name": "Vimeo-Web",
      "description": null
    },
    {
      "name": "Vimeo-ICMP",
      "description": null
    },
    {
      "name": "Vimeo-DNS",
      "description": null
    },
    {
      "name": "Vimeo-Outbound_Email",
      "description": null
    },
    {
      "name": "Vimeo-SSH",
      "description": null
    },
    {
      "name": "Vimeo-FTP",
      "description": null
    },
    {
      "name": "Vimeo-NTP",
      "description": null
    },
    {
      "name": "Vimeo-Inbound_Email",
      "description": null
    },
    {
      "name": "Vimeo-LDAP",
      "description": null
    },
    {
      "name": "Vimeo-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Vimeo-RTMP",
      "description": null
    },
    {
      "name": "Vimeo-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Redhat-Other",
      "description": null
    },
    {
      "name": "Redhat-Web",
      "description": null
    },
    {
      "name": "Redhat-ICMP",
      "description": null
    },
    {
      "name": "Redhat-DNS",
      "description": null
    },
    {
      "name": "Redhat-Outbound_Email",
      "description": null
    },
    {
      "name": "Redhat-SSH",
      "description": null
    },
    {
      "name": "Redhat-FTP",
      "description": null
    },
    {
      "name": "Redhat-NTP",
      "description": null
    },
    {
      "name": "Redhat-Inbound_Email",
      "description": null
    },
    {
      "name": "Redhat-LDAP",
      "description": null
    },
    {
      "name": "Redhat-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Redhat-RTMP",
      "description": null
    },
    {
      "name": "Redhat-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "VK-Other",
      "description": null
    },
    {
      "name": "VK-Web",
      "description": null
    },
    {
      "name": "VK-ICMP",
      "description": null
    },
    {
      "name": "VK-DNS",
      "description": null
    },
    {
      "name": "VK-Outbound_Email",
      "description": null
    },
    {
      "name": "VK-SSH",
      "description": null
    },
    {
      "name": "VK-FTP",
      "description": null
    },
    {
      "name": "VK-NTP",
      "description": null
    },
    {
      "name": "VK-Inbound_Email",
      "description": null
    },
    {
      "name": "VK-LDAP",
      "description": null
    },
    {
      "name": "VK-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "VK-RTMP",
      "description": null
    },
    {
      "name": "VK-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "TrendMicro-Other",
      "description": null
    },
    {
      "name": "TrendMicro-Web",
      "description": null
    },
    {
      "name": "TrendMicro-ICMP",
      "description": null
    },
    {
      "name": "TrendMicro-DNS",
      "description": null
    },
    {
      "name": "TrendMicro-Outbound_Email",
      "description": null
    },
    {
      "name": "TrendMicro-SSH",
      "description": null
    },
    {
      "name": "TrendMicro-FTP",
      "description": null
    },
    {
      "name": "TrendMicro-NTP",
      "description": null
    },
    {
      "name": "TrendMicro-Inbound_Email",
      "description": null
    },
    {
      "name": "TrendMicro-LDAP",
      "description": null
    },
    {
      "name": "TrendMicro-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "TrendMicro-RTMP",
      "description": null
    },
    {
      "name": "TrendMicro-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Tencent-Other",
      "description": null
    },
    {
      "name": "Tencent-Web",
      "description": null
    },
    {
      "name": "Tencent-ICMP",
      "description": null
    },
    {
      "name": "Tencent-DNS",
      "description": null
    },
    {
      "name": "Tencent-Outbound_Email",
      "description": null
    },
    {
      "name": "Tencent-SSH",
      "description": null
    },
    {
      "name": "Tencent-FTP",
      "description": null
    },
    {
      "name": "Tencent-NTP",
      "description": null
    },
    {
      "name": "Tencent-Inbound_Email",
      "description": null
    },
    {
      "name": "Tencent-LDAP",
      "description": null
    },
    {
      "name": "Tencent-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Tencent-RTMP",
      "description": null
    },
    {
      "name": "Tencent-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Ask-Other",
      "description": null
    },
    {
      "name": "Ask-Web",
      "description": null
    },
    {
      "name": "Ask-ICMP",
      "description": null
    },
    {
      "name": "Ask-DNS",
      "description": null
    },
    {
      "name": "Ask-Outbound_Email",
      "description": null
    },
    {
      "name": "Ask-SSH",
      "description": null
    },
    {
      "name": "Ask-FTP",
      "description": null
    },
    {
      "name": "Ask-NTP",
      "description": null
    },
    {
      "name": "Ask-Inbound_Email",
      "description": null
    },
    {
      "name": "Ask-LDAP",
      "description": null
    },
    {
      "name": "Ask-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Ask-RTMP",
      "description": null
    },
    {
      "name": "Ask-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "CNN-Other",
      "description": null
    },
    {
      "name": "CNN-Web",
      "description": null
    },
    {
      "name": "CNN-ICMP",
      "description": null
    },
    {
      "name": "CNN-DNS",
      "description": null
    },
    {
      "name": "CNN-Outbound_Email",
      "description": null
    },
    {
      "name": "CNN-SSH",
      "description": null
    },
    {
      "name": "CNN-FTP",
      "description": null
    },
    {
      "name": "CNN-NTP",
      "description": null
    },
    {
      "name": "CNN-Inbound_Email",
      "description": null
    },
    {
      "name": "CNN-LDAP",
      "description": null
    },
    {
      "name": "CNN-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "CNN-RTMP",
      "description": null
    },
    {
      "name": "CNN-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Myspace-Other",
      "description": null
    },
    {
      "name": "Myspace-Web",
      "description": null
    },
    {
      "name": "Myspace-ICMP",
      "description": null
    },
    {
      "name": "Myspace-DNS",
      "description": null
    },
    {
      "name": "Myspace-Outbound_Email",
      "description": null
    },
    {
      "name": "Myspace-SSH",
      "description": null
    },
    {
      "name": "Myspace-FTP",
      "description": null
    },
    {
      "name": "Myspace-NTP",
      "description": null
    },
    {
      "name": "Myspace-Inbound_Email",
      "description": null
    },
    {
      "name": "Myspace-LDAP",
      "description": null
    },
    {
      "name": "Myspace-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Myspace-RTMP",
      "description": null
    },
    {
      "name": "Myspace-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Tor-Relay.Node",
      "description": null
    },
    {
      "name": "Tor-Exit.Node",
      "description": null
    },
    {
      "name": "Baidu-Other",
      "description": null
    },
    {
      "name": "Baidu-Web",
      "description": null
    },
    {
      "name": "Baidu-ICMP",
      "description": null
    },
    {
      "name": "Baidu-DNS",
      "description": null
    },
    {
      "name": "Baidu-Outbound_Email",
      "description": null
    },
    {
      "name": "Baidu-SSH",
      "description": null
    },
    {
      "name": "Baidu-FTP",
      "description": null
    },
    {
      "name": "Baidu-NTP",
      "description": null
    },
    {
      "name": "Baidu-Inbound_Email",
      "description": null
    },
    {
      "name": "Baidu-LDAP",
      "description": null
    },
    {
      "name": "Baidu-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Baidu-RTMP",
      "description": null
    },
    {
      "name": "Baidu-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "ntp.org-Other",
      "description": null
    },
    {
      "name": "ntp.org-Web",
      "description": null
    },
    {
      "name": "ntp.org-ICMP",
      "description": null
    },
    {
      "name": "ntp.org-DNS",
      "description": null
    },
    {
      "name": "ntp.org-Outbound_Email",
      "description": null
    },
    {
      "name": "ntp.org-SSH",
      "description": null
    },
    {
      "name": "ntp.org-FTP",
      "description": null
    },
    {
      "name": "ntp.org-NTP",
      "description": null
    },
    {
      "name": "ntp.org-Inbound_Email",
      "description": null
    },
    {
      "name": "ntp.org-LDAP",
      "description": null
    },
    {
      "name": "ntp.org-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "ntp.org-RTMP",
      "description": null
    },
    {
      "name": "ntp.org-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Proxy-Proxy.Server",
      "description": null
    },
    {
      "name": "Botnet-C&C.Server",
      "description": null
    },
    {
      "name": "Spam-Spamming.Server",
      "description": null
    },
    {
      "name": "Phishing-Phishing.Server",
      "description": null
    },
    {
      "name": "Zendesk-Zendesk.Suite",
      "description": null
    },
    {
      "name": "DocuSign-Other",
      "description": null
    },
    {
      "name": "DocuSign-Web",
      "description": null
    },
    {
      "name": "DocuSign-ICMP",
      "description": null
    },
    {
      "name": "DocuSign-DNS",
      "description": null
    },
    {
      "name": "DocuSign-Outbound_Email",
      "description": null
    },
    {
      "name": "DocuSign-SSH",
      "description": null
    },
    {
      "name": "DocuSign-FTP",
      "description": null
    },
    {
      "name": "DocuSign-NTP",
      "description": null
    },
    {
      "name": "DocuSign-Inbound_Email",
      "description": null
    },
    {
      "name": "DocuSign-LDAP",
      "description": null
    },
    {
      "name": "DocuSign-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "DocuSign-RTMP",
      "description": null
    },
    {
      "name": "DocuSign-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "ServiceNow-Other",
      "description": null
    },
    {
      "name": "ServiceNow-Web",
      "description": null
    },
    {
      "name": "ServiceNow-ICMP",
      "description": null
    },
    {
      "name": "ServiceNow-DNS",
      "description": null
    },
    {
      "name": "ServiceNow-Outbound_Email",
      "description": null
    },
    {
      "name": "ServiceNow-SSH",
      "description": null
    },
    {
      "name": "ServiceNow-FTP",
      "description": null
    },
    {
      "name": "ServiceNow-NTP",
      "description": null
    },
    {
      "name": "ServiceNow-Inbound_Email",
      "description": null
    },
    {
      "name": "ServiceNow-LDAP",
      "description": null
    },
    {
      "name": "ServiceNow-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "ServiceNow-RTMP",
      "description": null
    },
    {
      "name": "ServiceNow-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "GitHub-GitHub",
      "description": null
    },
    {
      "name": "Workday-Other",
      "description": null
    },
    {
      "name": "Workday-Web",
      "description": null
    },
    {
      "name": "Workday-ICMP",
      "description": null
    },
    {
      "name": "Workday-DNS",
      "description": null
    },
    {
      "name": "Workday-Outbound_Email",
      "description": null
    },
    {
      "name": "Workday-SSH",
      "description": null
    },
    {
      "name": "Workday-FTP",
      "description": null
    },
    {
      "name": "Workday-NTP",
      "description": null
    },
    {
      "name": "Workday-Inbound_Email",
      "description": null
    },
    {
      "name": "Workday-LDAP",
      "description": null
    },
    {
      "name": "Workday-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Workday-RTMP",
      "description": null
    },
    {
      "name": "Workday-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "HubSpot-Other",
      "description": null
    },
    {
      "name": "HubSpot-Web",
      "description": null
    },
    {
      "name": "HubSpot-ICMP",
      "description": null
    },
    {
      "name": "HubSpot-DNS",
      "description": null
    },
    {
      "name": "HubSpot-Outbound_Email",
      "description": null
    },
    {
      "name": "HubSpot-SSH",
      "description": null
    },
    {
      "name": "HubSpot-FTP",
      "description": null
    },
    {
      "name": "HubSpot-NTP",
      "description": null
    },
    {
      "name": "HubSpot-Inbound_Email",
      "description": null
    },
    {
      "name": "HubSpot-LDAP",
      "description": null
    },
    {
      "name": "HubSpot-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "HubSpot-RTMP",
      "description": null
    },
    {
      "name": "HubSpot-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Twilio-Other",
      "description": null
    },
    {
      "name": "Twilio-Web",
      "description": null
    },
    {
      "name": "Twilio-ICMP",
      "description": null
    },
    {
      "name": "Twilio-DNS",
      "description": null
    },
    {
      "name": "Twilio-Outbound_Email",
      "description": null
    },
    {
      "name": "Twilio-SSH",
      "description": null
    },
    {
      "name": "Twilio-FTP",
      "description": null
    },
    {
      "name": "Twilio-NTP",
      "description": null
    },
    {
      "name": "Twilio-Inbound_Email",
      "description": null
    },
    {
      "name": "Twilio-LDAP",
      "description": null
    },
    {
      "name": "Twilio-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Twilio-RTMP",
      "description": null
    },
    {
      "name": "Twilio-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Twilio-Elastic.SIP.Trunking",
      "description": null
    },
    {
      "name": "Coupa-Other",
      "description": null
    },
    {
      "name": "Coupa-Web",
      "description": null
    },
    {
      "name": "Coupa-ICMP",
      "description": null
    },
    {
      "name": "Coupa-DNS",
      "description": null
    },
    {
      "name": "Coupa-Outbound_Email",
      "description": null
    },
    {
      "name": "Coupa-SSH",
      "description": null
    },
    {
      "name": "Coupa-FTP",
      "description": null
    },
    {
      "name": "Coupa-NTP",
      "description": null
    },
    {
      "name": "Coupa-Inbound_Email",
      "description": null
    },
    {
      "name": "Coupa-LDAP",
      "description": null
    },
    {
      "name": "Coupa-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Coupa-RTMP",
      "description": null
    },
    {
      "name": "Coupa-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Atlassian-Other",
      "description": null
    },
    {
      "name": "Atlassian-Web",
      "description": null
    },
    {
      "name": "Atlassian-ICMP",
      "description": null
    },
    {
      "name": "Atlassian-DNS",
      "description": null
    },
    {
      "name": "Atlassian-Outbound_Email",
      "description": null
    },
    {
      "name": "Atlassian-SSH",
      "description": null
    },
    {
      "name": "Atlassian-FTP",
      "description": null
    },
    {
      "name": "Atlassian-NTP",
      "description": null
    },
    {
      "name": "Atlassian-Inbound_Email",
      "description": null
    },
    {
      "name": "Atlassian-LDAP",
      "description": null
    },
    {
      "name": "Atlassian-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Atlassian-RTMP",
      "description": null
    },
    {
      "name": "Atlassian-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Xero-Other",
      "description": null
    },
    {
      "name": "Xero-Web",
      "description": null
    },
    {
      "name": "Xero-ICMP",
      "description": null
    },
    {
      "name": "Xero-DNS",
      "description": null
    },
    {
      "name": "Xero-Outbound_Email",
      "description": null
    },
    {
      "name": "Xero-SSH",
      "description": null
    },
    {
      "name": "Xero-FTP",
      "description": null
    },
    {
      "name": "Xero-NTP",
      "description": null
    },
    {
      "name": "Xero-Inbound_Email",
      "description": null
    },
    {
      "name": "Xero-LDAP",
      "description": null
    },
    {
      "name": "Xero-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Xero-RTMP",
      "description": null
    },
    {
      "name": "Xero-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Zuora-Other",
      "description": null
    },
    {
      "name": "Zuora-Web",
      "description": null
    },
    {
      "name": "Zuora-ICMP",
      "description": null
    },
    {
      "name": "Zuora-DNS",
      "description": null
    },
    {
      "name": "Zuora-Outbound_Email",
      "description": null
    },
    {
      "name": "Zuora-SSH",
      "description": null
    },
    {
      "name": "Zuora-FTP",
      "description": null
    },
    {
      "name": "Zuora-NTP",
      "description": null
    },
    {
      "name": "Zuora-Inbound_Email",
      "description": null
    },
    {
      "name": "Zuora-LDAP",
      "description": null
    },
    {
      "name": "Zuora-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Zuora-RTMP",
      "description": null
    },
    {
      "name": "Zuora-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "AdRoll-Other",
      "description": null
    },
    {
      "name": "AdRoll-Web",
      "description": null
    },
    {
      "name": "AdRoll-ICMP",
      "description": null
    },
    {
      "name": "AdRoll-DNS",
      "description": null
    },
    {
      "name": "AdRoll-Outbound_Email",
      "description": null
    },
    {
      "name": "AdRoll-SSH",
      "description": null
    },
    {
      "name": "AdRoll-FTP",
      "description": null
    },
    {
      "name": "AdRoll-NTP",
      "description": null
    },
    {
      "name": "AdRoll-Inbound_Email",
      "description": null
    },
    {
      "name": "AdRoll-LDAP",
      "description": null
    },
    {
      "name": "AdRoll-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "AdRoll-RTMP",
      "description": null
    },
    {
      "name": "AdRoll-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Xactly-Other",
      "description": null
    },
    {
      "name": "Xactly-Web",
      "description": null
    },
    {
      "name": "Xactly-ICMP",
      "description": null
    },
    {
      "name": "Xactly-DNS",
      "description": null
    },
    {
      "name": "Xactly-Outbound_Email",
      "description": null
    },
    {
      "name": "Xactly-SSH",
      "description": null
    },
    {
      "name": "Xactly-FTP",
      "description": null
    },
    {
      "name": "Xactly-NTP",
      "description": null
    },
    {
      "name": "Xactly-Inbound_Email",
      "description": null
    },
    {
      "name": "Xactly-LDAP",
      "description": null
    },
    {
      "name": "Xactly-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Xactly-RTMP",
      "description": null
    },
    {
      "name": "Xactly-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Intuit-Other",
      "description": null
    },
    {
      "name": "Intuit-Web",
      "description": null
    },
    {
      "name": "Intuit-ICMP",
      "description": null
    },
    {
      "name": "Intuit-DNS",
      "description": null
    },
    {
      "name": "Intuit-Outbound_Email",
      "description": null
    },
    {
      "name": "Intuit-SSH",
      "description": null
    },
    {
      "name": "Intuit-FTP",
      "description": null
    },
    {
      "name": "Intuit-NTP",
      "description": null
    },
    {
      "name": "Intuit-Inbound_Email",
      "description": null
    },
    {
      "name": "Intuit-LDAP",
      "description": null
    },
    {
      "name": "Intuit-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Intuit-RTMP",
      "description": null
    },
    {
      "name": "Intuit-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Marketo-Other",
      "description": null
    },
    {
      "name": "Marketo-Web",
      "description": null
    },
    {
      "name": "Marketo-ICMP",
      "description": null
    },
    {
      "name": "Marketo-DNS",
      "description": null
    },
    {
      "name": "Marketo-Outbound_Email",
      "description": null
    },
    {
      "name": "Marketo-SSH",
      "description": null
    },
    {
      "name": "Marketo-FTP",
      "description": null
    },
    {
      "name": "Marketo-NTP",
      "description": null
    },
    {
      "name": "Marketo-Inbound_Email",
      "description": null
    },
    {
      "name": "Marketo-LDAP",
      "description": null
    },
    {
      "name": "Marketo-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Marketo-RTMP",
      "description": null
    },
    {
      "name": "Marketo-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Bill-Other",
      "description": null
    },
    {
      "name": "Bill-Web",
      "description": null
    },
    {
      "name": "Bill-ICMP",
      "description": null
    },
    {
      "name": "Bill-DNS",
      "description": null
    },
    {
      "name": "Bill-Outbound_Email",
      "description": null
    },
    {
      "name": "Bill-SSH",
      "description": null
    },
    {
      "name": "Bill-FTP",
      "description": null
    },
    {
      "name": "Bill-NTP",
      "description": null
    },
    {
      "name": "Bill-Inbound_Email",
      "description": null
    },
    {
      "name": "Bill-LDAP",
      "description": null
    },
    {
      "name": "Bill-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Bill-RTMP",
      "description": null
    },
    {
      "name": "Bill-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Shopify-Other",
      "description": null
    },
    {
      "name": "Shopify-Web",
      "description": null
    },
    {
      "name": "Shopify-ICMP",
      "description": null
    },
    {
      "name": "Shopify-DNS",
      "description": null
    },
    {
      "name": "Shopify-Outbound_Email",
      "description": null
    },
    {
      "name": "Shopify-SSH",
      "description": null
    },
    {
      "name": "Shopify-FTP",
      "description": null
    },
    {
      "name": "Shopify-NTP",
      "description": null
    },
    {
      "name": "Shopify-Inbound_Email",
      "description": null
    },
    {
      "name": "Shopify-LDAP",
      "description": null
    },
    {
      "name": "Shopify-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Shopify-RTMP",
      "description": null
    },
    {
      "name": "Shopify-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Shopify-Shopify",
      "description": null
    },
    {
      "name": "MuleSoft-Other",
      "description": null
    },
    {
      "name": "MuleSoft-Web",
      "description": null
    },
    {
      "name": "MuleSoft-ICMP",
      "description": null
    },
    {
      "name": "MuleSoft-DNS",
      "description": null
    },
    {
      "name": "MuleSoft-Outbound_Email",
      "description": null
    },
    {
      "name": "MuleSoft-SSH",
      "description": null
    },
    {
      "name": "MuleSoft-FTP",
      "description": null
    },
    {
      "name": "MuleSoft-NTP",
      "description": null
    },
    {
      "name": "MuleSoft-Inbound_Email",
      "description": null
    },
    {
      "name": "MuleSoft-LDAP",
      "description": null
    },
    {
      "name": "MuleSoft-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "MuleSoft-RTMP",
      "description": null
    },
    {
      "name": "MuleSoft-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Cornerstone-Other",
      "description": null
    },
    {
      "name": "Cornerstone-Web",
      "description": null
    },
    {
      "name": "Cornerstone-ICMP",
      "description": null
    },
    {
      "name": "Cornerstone-DNS",
      "description": null
    },
    {
      "name": "Cornerstone-Outbound_Email",
      "description": null
    },
    {
      "name": "Cornerstone-SSH",
      "description": null
    },
    {
      "name": "Cornerstone-FTP",
      "description": null
    },
    {
      "name": "Cornerstone-NTP",
      "description": null
    },
    {
      "name": "Cornerstone-Inbound_Email",
      "description": null
    },
    {
      "name": "Cornerstone-LDAP",
      "description": null
    },
    {
      "name": "Cornerstone-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Cornerstone-RTMP",
      "description": null
    },
    {
      "name": "Cornerstone-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Eventbrite-Other",
      "description": null
    },
    {
      "name": "Eventbrite-Web",
      "description": null
    },
    {
      "name": "Eventbrite-ICMP",
      "description": null
    },
    {
      "name": "Eventbrite-DNS",
      "description": null
    },
    {
      "name": "Eventbrite-Outbound_Email",
      "description": null
    },
    {
      "name": "Eventbrite-SSH",
      "description": null
    },
    {
      "name": "Eventbrite-FTP",
      "description": null
    },
    {
      "name": "Eventbrite-NTP",
      "description": null
    },
    {
      "name": "Eventbrite-Inbound_Email",
      "description": null
    },
    {
      "name": "Eventbrite-LDAP",
      "description": null
    },
    {
      "name": "Eventbrite-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Eventbrite-RTMP",
      "description": null
    },
    {
      "name": "Eventbrite-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Paychex-Other",
      "description": null
    },
    {
      "name": "Paychex-Web",
      "description": null
    },
    {
      "name": "Paychex-ICMP",
      "description": null
    },
    {
      "name": "Paychex-DNS",
      "description": null
    },
    {
      "name": "Paychex-Outbound_Email",
      "description": null
    },
    {
      "name": "Paychex-SSH",
      "description": null
    },
    {
      "name": "Paychex-FTP",
      "description": null
    },
    {
      "name": "Paychex-NTP",
      "description": null
    },
    {
      "name": "Paychex-Inbound_Email",
      "description": null
    },
    {
      "name": "Paychex-LDAP",
      "description": null
    },
    {
      "name": "Paychex-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Paychex-RTMP",
      "description": null
    },
    {
      "name": "Paychex-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "NewRelic-Other",
      "description": null
    },
    {
      "name": "NewRelic-Web",
      "description": null
    },
    {
      "name": "NewRelic-ICMP",
      "description": null
    },
    {
      "name": "NewRelic-DNS",
      "description": null
    },
    {
      "name": "NewRelic-Outbound_Email",
      "description": null
    },
    {
      "name": "NewRelic-SSH",
      "description": null
    },
    {
      "name": "NewRelic-FTP",
      "description": null
    },
    {
      "name": "NewRelic-NTP",
      "description": null
    },
    {
      "name": "NewRelic-Inbound_Email",
      "description": null
    },
    {
      "name": "NewRelic-LDAP",
      "description": null
    },
    {
      "name": "NewRelic-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "NewRelic-RTMP",
      "description": null
    },
    {
      "name": "NewRelic-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Splunk-Other",
      "description": null
    },
    {
      "name": "Splunk-Web",
      "description": null
    },
    {
      "name": "Splunk-ICMP",
      "description": null
    },
    {
      "name": "Splunk-DNS",
      "description": null
    },
    {
      "name": "Splunk-Outbound_Email",
      "description": null
    },
    {
      "name": "Splunk-SSH",
      "description": null
    },
    {
      "name": "Splunk-FTP",
      "description": null
    },
    {
      "name": "Splunk-NTP",
      "description": null
    },
    {
      "name": "Splunk-Inbound_Email",
      "description": null
    },
    {
      "name": "Splunk-LDAP",
      "description": null
    },
    {
      "name": "Splunk-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Splunk-RTMP",
      "description": null
    },
    {
      "name": "Splunk-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Domo-Other",
      "description": null
    },
    {
      "name": "Domo-Web",
      "description": null
    },
    {
      "name": "Domo-ICMP",
      "description": null
    },
    {
      "name": "Domo-DNS",
      "description": null
    },
    {
      "name": "Domo-Outbound_Email",
      "description": null
    },
    {
      "name": "Domo-SSH",
      "description": null
    },
    {
      "name": "Domo-FTP",
      "description": null
    },
    {
      "name": "Domo-NTP",
      "description": null
    },
    {
      "name": "Domo-Inbound_Email",
      "description": null
    },
    {
      "name": "Domo-LDAP",
      "description": null
    },
    {
      "name": "Domo-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Domo-RTMP",
      "description": null
    },
    {
      "name": "Domo-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "FreshBooks-Other",
      "description": null
    },
    {
      "name": "FreshBooks-Web",
      "description": null
    },
    {
      "name": "FreshBooks-ICMP",
      "description": null
    },
    {
      "name": "FreshBooks-DNS",
      "description": null
    },
    {
      "name": "FreshBooks-Outbound_Email",
      "description": null
    },
    {
      "name": "FreshBooks-SSH",
      "description": null
    },
    {
      "name": "FreshBooks-FTP",
      "description": null
    },
    {
      "name": "FreshBooks-NTP",
      "description": null
    },
    {
      "name": "FreshBooks-Inbound_Email",
      "description": null
    },
    {
      "name": "FreshBooks-LDAP",
      "description": null
    },
    {
      "name": "FreshBooks-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "FreshBooks-RTMP",
      "description": null
    },
    {
      "name": "FreshBooks-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Tableau-Other",
      "description": null
    },
    {
      "name": "Tableau-Web",
      "description": null
    },
    {
      "name": "Tableau-ICMP",
      "description": null
    },
    {
      "name": "Tableau-DNS",
      "description": null
    },
    {
      "name": "Tableau-Outbound_Email",
      "description": null
    },
    {
      "name": "Tableau-SSH",
      "description": null
    },
    {
      "name": "Tableau-FTP",
      "description": null
    },
    {
      "name": "Tableau-NTP",
      "description": null
    },
    {
      "name": "Tableau-Inbound_Email",
      "description": null
    },
    {
      "name": "Tableau-LDAP",
      "description": null
    },
    {
      "name": "Tableau-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Tableau-RTMP",
      "description": null
    },
    {
      "name": "Tableau-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Druva-Other",
      "description": null
    },
    {
      "name": "Druva-Web",
      "description": null
    },
    {
      "name": "Druva-ICMP",
      "description": null
    },
    {
      "name": "Druva-DNS",
      "description": null
    },
    {
      "name": "Druva-Outbound_Email",
      "description": null
    },
    {
      "name": "Druva-SSH",
      "description": null
    },
    {
      "name": "Druva-FTP",
      "description": null
    },
    {
      "name": "Druva-NTP",
      "description": null
    },
    {
      "name": "Druva-Inbound_Email",
      "description": null
    },
    {
      "name": "Druva-LDAP",
      "description": null
    },
    {
      "name": "Druva-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Druva-RTMP",
      "description": null
    },
    {
      "name": "Druva-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Act-on-Other",
      "description": null
    },
    {
      "name": "Act-on-Web",
      "description": null
    },
    {
      "name": "Act-on-ICMP",
      "description": null
    },
    {
      "name": "Act-on-DNS",
      "description": null
    },
    {
      "name": "Act-on-Outbound_Email",
      "description": null
    },
    {
      "name": "Act-on-SSH",
      "description": null
    },
    {
      "name": "Act-on-FTP",
      "description": null
    },
    {
      "name": "Act-on-NTP",
      "description": null
    },
    {
      "name": "Act-on-Inbound_Email",
      "description": null
    },
    {
      "name": "Act-on-LDAP",
      "description": null
    },
    {
      "name": "Act-on-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Act-on-RTMP",
      "description": null
    },
    {
      "name": "Act-on-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "GoodData-Other",
      "description": null
    },
    {
      "name": "GoodData-Web",
      "description": null
    },
    {
      "name": "GoodData-ICMP",
      "description": null
    },
    {
      "name": "GoodData-DNS",
      "description": null
    },
    {
      "name": "GoodData-Outbound_Email",
      "description": null
    },
    {
      "name": "GoodData-SSH",
      "description": null
    },
    {
      "name": "GoodData-FTP",
      "description": null
    },
    {
      "name": "GoodData-NTP",
      "description": null
    },
    {
      "name": "GoodData-Inbound_Email",
      "description": null
    },
    {
      "name": "GoodData-LDAP",
      "description": null
    },
    {
      "name": "GoodData-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "GoodData-RTMP",
      "description": null
    },
    {
      "name": "GoodData-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "SurveyMonkey-Other",
      "description": null
    },
    {
      "name": "SurveyMonkey-Web",
      "description": null
    },
    {
      "name": "SurveyMonkey-ICMP",
      "description": null
    },
    {
      "name": "SurveyMonkey-DNS",
      "description": null
    },
    {
      "name": "SurveyMonkey-Outbound_Email",
      "description": null
    },
    {
      "name": "SurveyMonkey-SSH",
      "description": null
    },
    {
      "name": "SurveyMonkey-FTP",
      "description": null
    },
    {
      "name": "SurveyMonkey-NTP",
      "description": null
    },
    {
      "name": "SurveyMonkey-Inbound_Email",
      "description": null
    },
    {
      "name": "SurveyMonkey-LDAP",
      "description": null
    },
    {
      "name": "SurveyMonkey-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "SurveyMonkey-RTMP",
      "description": null
    },
    {
      "name": "SurveyMonkey-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Cvent-Other",
      "description": null
    },
    {
      "name": "Cvent-Web",
      "description": null
    },
    {
      "name": "Cvent-ICMP",
      "description": null
    },
    {
      "name": "Cvent-DNS",
      "description": null
    },
    {
      "name": "Cvent-Outbound_Email",
      "description": null
    },
    {
      "name": "Cvent-SSH",
      "description": null
    },
    {
      "name": "Cvent-FTP",
      "description": null
    },
    {
      "name": "Cvent-NTP",
      "description": null
    },
    {
      "name": "Cvent-Inbound_Email",
      "description": null
    },
    {
      "name": "Cvent-LDAP",
      "description": null
    },
    {
      "name": "Cvent-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Cvent-RTMP",
      "description": null
    },
    {
      "name": "Cvent-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Blackbaud-Other",
      "description": null
    },
    {
      "name": "Blackbaud-Web",
      "description": null
    },
    {
      "name": "Blackbaud-ICMP",
      "description": null
    },
    {
      "name": "Blackbaud-DNS",
      "description": null
    },
    {
      "name": "Blackbaud-Outbound_Email",
      "description": null
    },
    {
      "name": "Blackbaud-SSH",
      "description": null
    },
    {
      "name": "Blackbaud-FTP",
      "description": null
    },
    {
      "name": "Blackbaud-NTP",
      "description": null
    },
    {
      "name": "Blackbaud-Inbound_Email",
      "description": null
    },
    {
      "name": "Blackbaud-LDAP",
      "description": null
    },
    {
      "name": "Blackbaud-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Blackbaud-RTMP",
      "description": null
    },
    {
      "name": "Blackbaud-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "InsideSales-Other",
      "description": null
    },
    {
      "name": "InsideSales-Web",
      "description": null
    },
    {
      "name": "InsideSales-ICMP",
      "description": null
    },
    {
      "name": "InsideSales-DNS",
      "description": null
    },
    {
      "name": "InsideSales-Outbound_Email",
      "description": null
    },
    {
      "name": "InsideSales-SSH",
      "description": null
    },
    {
      "name": "InsideSales-FTP",
      "description": null
    },
    {
      "name": "InsideSales-NTP",
      "description": null
    },
    {
      "name": "InsideSales-Inbound_Email",
      "description": null
    },
    {
      "name": "InsideSales-LDAP",
      "description": null
    },
    {
      "name": "InsideSales-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "InsideSales-RTMP",
      "description": null
    },
    {
      "name": "InsideSales-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "ServiceMax-Other",
      "description": null
    },
    {
      "name": "ServiceMax-Web",
      "description": null
    },
    {
      "name": "ServiceMax-ICMP",
      "description": null
    },
    {
      "name": "ServiceMax-DNS",
      "description": null
    },
    {
      "name": "ServiceMax-Outbound_Email",
      "description": null
    },
    {
      "name": "ServiceMax-SSH",
      "description": null
    },
    {
      "name": "ServiceMax-FTP",
      "description": null
    },
    {
      "name": "ServiceMax-NTP",
      "description": null
    },
    {
      "name": "ServiceMax-Inbound_Email",
      "description": null
    },
    {
      "name": "ServiceMax-LDAP",
      "description": null
    },
    {
      "name": "ServiceMax-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "ServiceMax-RTMP",
      "description": null
    },
    {
      "name": "ServiceMax-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Apptio-Other",
      "description": null
    },
    {
      "name": "Apptio-Web",
      "description": null
    },
    {
      "name": "Apptio-ICMP",
      "description": null
    },
    {
      "name": "Apptio-DNS",
      "description": null
    },
    {
      "name": "Apptio-Outbound_Email",
      "description": null
    },
    {
      "name": "Apptio-SSH",
      "description": null
    },
    {
      "name": "Apptio-FTP",
      "description": null
    },
    {
      "name": "Apptio-NTP",
      "description": null
    },
    {
      "name": "Apptio-Inbound_Email",
      "description": null
    },
    {
      "name": "Apptio-LDAP",
      "description": null
    },
    {
      "name": "Apptio-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Apptio-RTMP",
      "description": null
    },
    {
      "name": "Apptio-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Veracode-Other",
      "description": null
    },
    {
      "name": "Veracode-Web",
      "description": null
    },
    {
      "name": "Veracode-ICMP",
      "description": null
    },
    {
      "name": "Veracode-DNS",
      "description": null
    },
    {
      "name": "Veracode-Outbound_Email",
      "description": null
    },
    {
      "name": "Veracode-SSH",
      "description": null
    },
    {
      "name": "Veracode-FTP",
      "description": null
    },
    {
      "name": "Veracode-NTP",
      "description": null
    },
    {
      "name": "Veracode-Inbound_Email",
      "description": null
    },
    {
      "name": "Veracode-LDAP",
      "description": null
    },
    {
      "name": "Veracode-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Veracode-RTMP",
      "description": null
    },
    {
      "name": "Veracode-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Anaplan-Other",
      "description": null
    },
    {
      "name": "Anaplan-Web",
      "description": null
    },
    {
      "name": "Anaplan-ICMP",
      "description": null
    },
    {
      "name": "Anaplan-DNS",
      "description": null
    },
    {
      "name": "Anaplan-Outbound_Email",
      "description": null
    },
    {
      "name": "Anaplan-SSH",
      "description": null
    },
    {
      "name": "Anaplan-FTP",
      "description": null
    },
    {
      "name": "Anaplan-NTP",
      "description": null
    },
    {
      "name": "Anaplan-Inbound_Email",
      "description": null
    },
    {
      "name": "Anaplan-LDAP",
      "description": null
    },
    {
      "name": "Anaplan-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Anaplan-RTMP",
      "description": null
    },
    {
      "name": "Anaplan-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Rapid7-Other",
      "description": null
    },
    {
      "name": "Rapid7-Web",
      "description": null
    },
    {
      "name": "Rapid7-ICMP",
      "description": null
    },
    {
      "name": "Rapid7-DNS",
      "description": null
    },
    {
      "name": "Rapid7-Outbound_Email",
      "description": null
    },
    {
      "name": "Rapid7-SSH",
      "description": null
    },
    {
      "name": "Rapid7-FTP",
      "description": null
    },
    {
      "name": "Rapid7-NTP",
      "description": null
    },
    {
      "name": "Rapid7-Inbound_Email",
      "description": null
    },
    {
      "name": "Rapid7-LDAP",
      "description": null
    },
    {
      "name": "Rapid7-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Rapid7-RTMP",
      "description": null
    },
    {
      "name": "Rapid7-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "AnyDesk-AnyDesk",
      "description": null
    },
    {
      "name": "ESET-Eset.Service",
      "description": null
    },
    {
      "name": "Slack-Other",
      "description": null
    },
    {
      "name": "Slack-Web",
      "description": null
    },
    {
      "name": "Slack-ICMP",
      "description": null
    },
    {
      "name": "Slack-DNS",
      "description": null
    },
    {
      "name": "Slack-Outbound_Email",
      "description": null
    },
    {
      "name": "Slack-SSH",
      "description": null
    },
    {
      "name": "Slack-FTP",
      "description": null
    },
    {
      "name": "Slack-NTP",
      "description": null
    },
    {
      "name": "Slack-Inbound_Email",
      "description": null
    },
    {
      "name": "Slack-LDAP",
      "description": null
    },
    {
      "name": "Slack-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Slack-RTMP",
      "description": null
    },
    {
      "name": "Slack-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Slack-Slack",
      "description": null
    },
    {
      "name": "ADP-Other",
      "description": null
    },
    {
      "name": "ADP-Web",
      "description": null
    },
    {
      "name": "ADP-ICMP",
      "description": null
    },
    {
      "name": "ADP-DNS",
      "description": null
    },
    {
      "name": "ADP-Outbound_Email",
      "description": null
    },
    {
      "name": "ADP-SSH",
      "description": null
    },
    {
      "name": "ADP-FTP",
      "description": null
    },
    {
      "name": "ADP-NTP",
      "description": null
    },
    {
      "name": "ADP-Inbound_Email",
      "description": null
    },
    {
      "name": "ADP-LDAP",
      "description": null
    },
    {
      "name": "ADP-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "ADP-RTMP",
      "description": null
    },
    {
      "name": "ADP-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Blackboard-Other",
      "description": null
    },
    {
      "name": "Blackboard-Web",
      "description": null
    },
    {
      "name": "Blackboard-ICMP",
      "description": null
    },
    {
      "name": "Blackboard-DNS",
      "description": null
    },
    {
      "name": "Blackboard-Outbound_Email",
      "description": null
    },
    {
      "name": "Blackboard-SSH",
      "description": null
    },
    {
      "name": "Blackboard-FTP",
      "description": null
    },
    {
      "name": "Blackboard-NTP",
      "description": null
    },
    {
      "name": "Blackboard-Inbound_Email",
      "description": null
    },
    {
      "name": "Blackboard-LDAP",
      "description": null
    },
    {
      "name": "Blackboard-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Blackboard-RTMP",
      "description": null
    },
    {
      "name": "Blackboard-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "SAP-Other",
      "description": null
    },
    {
      "name": "SAP-Web",
      "description": null
    },
    {
      "name": "SAP-ICMP",
      "description": null
    },
    {
      "name": "SAP-DNS",
      "description": null
    },
    {
      "name": "SAP-Outbound_Email",
      "description": null
    },
    {
      "name": "SAP-SSH",
      "description": null
    },
    {
      "name": "SAP-FTP",
      "description": null
    },
    {
      "name": "SAP-NTP",
      "description": null
    },
    {
      "name": "SAP-Inbound_Email",
      "description": null
    },
    {
      "name": "SAP-LDAP",
      "description": null
    },
    {
      "name": "SAP-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "SAP-RTMP",
      "description": null
    },
    {
      "name": "SAP-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "SAP-HANA",
      "description": null
    },
    {
      "name": "SAP-SuccessFactors",
      "description": null
    },
    {
      "name": "Snap-Snapchat",
      "description": null
    },
    {
      "name": "Zoom.us-Zoom.Meeting",
      "description": null
    },
    {
      "name": "Sophos-Other",
      "description": null
    },
    {
      "name": "Sophos-Web",
      "description": null
    },
    {
      "name": "Sophos-ICMP",
      "description": null
    },
    {
      "name": "Sophos-DNS",
      "description": null
    },
    {
      "name": "Sophos-Outbound_Email",
      "description": null
    },
    {
      "name": "Sophos-SSH",
      "description": null
    },
    {
      "name": "Sophos-FTP",
      "description": null
    },
    {
      "name": "Sophos-NTP",
      "description": null
    },
    {
      "name": "Sophos-Inbound_Email",
      "description": null
    },
    {
      "name": "Sophos-LDAP",
      "description": null
    },
    {
      "name": "Sophos-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Sophos-RTMP",
      "description": null
    },
    {
      "name": "Sophos-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Cloudflare-Other",
      "description": null
    },
    {
      "name": "Cloudflare-Web",
      "description": null
    },
    {
      "name": "Cloudflare-ICMP",
      "description": null
    },
    {
      "name": "Cloudflare-DNS",
      "description": null
    },
    {
      "name": "Cloudflare-Outbound_Email",
      "description": null
    },
    {
      "name": "Cloudflare-SSH",
      "description": null
    },
    {
      "name": "Cloudflare-FTP",
      "description": null
    },
    {
      "name": "Cloudflare-NTP",
      "description": null
    },
    {
      "name": "Cloudflare-Inbound_Email",
      "description": null
    },
    {
      "name": "Cloudflare-LDAP",
      "description": null
    },
    {
      "name": "Cloudflare-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Cloudflare-RTMP",
      "description": null
    },
    {
      "name": "Cloudflare-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Cloudflare-CDN",
      "description": null
    },
    {
      "name": "Pexip-Pexip.Meeting",
      "description": null
    },
    {
      "name": "Zscaler-Other",
      "description": null
    },
    {
      "name": "Zscaler-Web",
      "description": null
    },
    {
      "name": "Zscaler-ICMP",
      "description": null
    },
    {
      "name": "Zscaler-DNS",
      "description": null
    },
    {
      "name": "Zscaler-Outbound_Email",
      "description": null
    },
    {
      "name": "Zscaler-SSH",
      "description": null
    },
    {
      "name": "Zscaler-FTP",
      "description": null
    },
    {
      "name": "Zscaler-NTP",
      "description": null
    },
    {
      "name": "Zscaler-Inbound_Email",
      "description": null
    },
    {
      "name": "Zscaler-LDAP",
      "description": null
    },
    {
      "name": "Zscaler-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Zscaler-RTMP",
      "description": null
    },
    {
      "name": "Zscaler-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Zscaler-Zscaler.Cloud",
      "description": null
    },
    {
      "name": "Yandex-Other",
      "description": null
    },
    {
      "name": "Yandex-Web",
      "description": null
    },
    {
      "name": "Yandex-ICMP",
      "description": null
    },
    {
      "name": "Yandex-DNS",
      "description": null
    },
    {
      "name": "Yandex-Outbound_Email",
      "description": null
    },
    {
      "name": "Yandex-SSH",
      "description": null
    },
    {
      "name": "Yandex-FTP",
      "description": null
    },
    {
      "name": "Yandex-NTP",
      "description": null
    },
    {
      "name": "Yandex-Inbound_Email",
      "description": null
    },
    {
      "name": "Yandex-LDAP",
      "description": null
    },
    {
      "name": "Yandex-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Yandex-RTMP",
      "description": null
    },
    {
      "name": "Yandex-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "mail.ru-Other",
      "description": null
    },
    {
      "name": "mail.ru-Web",
      "description": null
    },
    {
      "name": "mail.ru-ICMP",
      "description": null
    },
    {
      "name": "mail.ru-DNS",
      "description": null
    },
    {
      "name": "mail.ru-Outbound_Email",
      "description": null
    },
    {
      "name": "mail.ru-SSH",
      "description": null
    },
    {
      "name": "mail.ru-FTP",
      "description": null
    },
    {
      "name": "mail.ru-NTP",
      "description": null
    },
    {
      "name": "mail.ru-Inbound_Email",
      "description": null
    },
    {
      "name": "mail.ru-LDAP",
      "description": null
    },
    {
      "name": "mail.ru-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "mail.ru-RTMP",
      "description": null
    },
    {
      "name": "mail.ru-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Alibaba-Other",
      "description": null
    },
    {
      "name": "Alibaba-Web",
      "description": null
    },
    {
      "name": "Alibaba-ICMP",
      "description": null
    },
    {
      "name": "Alibaba-DNS",
      "description": null
    },
    {
      "name": "Alibaba-Outbound_Email",
      "description": null
    },
    {
      "name": "Alibaba-SSH",
      "description": null
    },
    {
      "name": "Alibaba-FTP",
      "description": null
    },
    {
      "name": "Alibaba-NTP",
      "description": null
    },
    {
      "name": "Alibaba-Inbound_Email",
      "description": null
    },
    {
      "name": "Alibaba-LDAP",
      "description": null
    },
    {
      "name": "Alibaba-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Alibaba-RTMP",
      "description": null
    },
    {
      "name": "Alibaba-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Alibaba-Alibaba.Cloud",
      "description": null
    },
    {
      "name": "GoDaddy-Other",
      "description": null
    },
    {
      "name": "GoDaddy-Web",
      "description": null
    },
    {
      "name": "GoDaddy-ICMP",
      "description": null
    },
    {
      "name": "GoDaddy-DNS",
      "description": null
    },
    {
      "name": "GoDaddy-Outbound_Email",
      "description": null
    },
    {
      "name": "GoDaddy-SSH",
      "description": null
    },
    {
      "name": "GoDaddy-FTP",
      "description": null
    },
    {
      "name": "GoDaddy-NTP",
      "description": null
    },
    {
      "name": "GoDaddy-Inbound_Email",
      "description": null
    },
    {
      "name": "GoDaddy-LDAP",
      "description": null
    },
    {
      "name": "GoDaddy-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "GoDaddy-RTMP",
      "description": null
    },
    {
      "name": "GoDaddy-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "GoDaddy-GoDaddy.Email",
      "description": null
    },
    {
      "name": "Webroot-Webroot.SecureAnywhere",
      "description": null
    },
    {
      "name": "Avast-Other",
      "description": null
    },
    {
      "name": "Avast-Web",
      "description": null
    },
    {
      "name": "Avast-ICMP",
      "description": null
    },
    {
      "name": "Avast-DNS",
      "description": null
    },
    {
      "name": "Avast-Outbound_Email",
      "description": null
    },
    {
      "name": "Avast-SSH",
      "description": null
    },
    {
      "name": "Avast-FTP",
      "description": null
    },
    {
      "name": "Avast-NTP",
      "description": null
    },
    {
      "name": "Avast-Inbound_Email",
      "description": null
    },
    {
      "name": "Avast-LDAP",
      "description": null
    },
    {
      "name": "Avast-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Avast-RTMP",
      "description": null
    },
    {
      "name": "Avast-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Avast-Avast.Security",
      "description": null
    },
    {
      "name": "Wetransfer-Other",
      "description": null
    },
    {
      "name": "Wetransfer-Web",
      "description": null
    },
    {
      "name": "Wetransfer-ICMP",
      "description": null
    },
    {
      "name": "Wetransfer-DNS",
      "description": null
    },
    {
      "name": "Wetransfer-Outbound_Email",
      "description": null
    },
    {
      "name": "Wetransfer-SSH",
      "description": null
    },
    {
      "name": "Wetransfer-FTP",
      "description": null
    },
    {
      "name": "Wetransfer-NTP",
      "description": null
    },
    {
      "name": "Wetransfer-Inbound_Email",
      "description": null
    },
    {
      "name": "Wetransfer-LDAP",
      "description": null
    },
    {
      "name": "Wetransfer-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Wetransfer-RTMP",
      "description": null
    },
    {
      "name": "Wetransfer-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Sendgrid-Sendgrid.Email",
      "description": null
    },
    {
      "name": "Ubiquiti-UniFi",
      "description": null
    },
    {
      "name": "Lifesize-Lifesize.Cloud",
      "description": null
    },
    {
      "name": "Okta-Other",
      "description": null
    },
    {
      "name": "Okta-Web",
      "description": null
    },
    {
      "name": "Okta-ICMP",
      "description": null
    },
    {
      "name": "Okta-DNS",
      "description": null
    },
    {
      "name": "Okta-Outbound_Email",
      "description": null
    },
    {
      "name": "Okta-SSH",
      "description": null
    },
    {
      "name": "Okta-FTP",
      "description": null
    },
    {
      "name": "Okta-NTP",
      "description": null
    },
    {
      "name": "Okta-Inbound_Email",
      "description": null
    },
    {
      "name": "Okta-LDAP",
      "description": null
    },
    {
      "name": "Okta-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Okta-RTMP",
      "description": null
    },
    {
      "name": "Okta-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Okta-Okta",
      "description": null
    },
    {
      "name": "Cybozu-Other",
      "description": null
    },
    {
      "name": "Cybozu-Web",
      "description": null
    },
    {
      "name": "Cybozu-ICMP",
      "description": null
    },
    {
      "name": "Cybozu-DNS",
      "description": null
    },
    {
      "name": "Cybozu-Outbound_Email",
      "description": null
    },
    {
      "name": "Cybozu-SSH",
      "description": null
    },
    {
      "name": "Cybozu-FTP",
      "description": null
    },
    {
      "name": "Cybozu-NTP",
      "description": null
    },
    {
      "name": "Cybozu-Inbound_Email",
      "description": null
    },
    {
      "name": "Cybozu-LDAP",
      "description": null
    },
    {
      "name": "Cybozu-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Cybozu-RTMP",
      "description": null
    },
    {
      "name": "Cybozu-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "RealVNC-Other",
      "description": null
    },
    {
      "name": "RealVNC-Web",
      "description": null
    },
    {
      "name": "RealVNC-ICMP",
      "description": null
    },
    {
      "name": "RealVNC-DNS",
      "description": null
    },
    {
      "name": "RealVNC-Outbound_Email",
      "description": null
    },
    {
      "name": "RealVNC-SSH",
      "description": null
    },
    {
      "name": "RealVNC-FTP",
      "description": null
    },
    {
      "name": "RealVNC-NTP",
      "description": null
    },
    {
      "name": "RealVNC-Inbound_Email",
      "description": null
    },
    {
      "name": "RealVNC-LDAP",
      "description": null
    },
    {
      "name": "RealVNC-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "RealVNC-RTMP",
      "description": null
    },
    {
      "name": "RealVNC-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Egnyte-Egnyte",
      "description": null
    },
    {
      "name": "CrowdStrike-CrowdStrike.Falcon.Cloud",
      "description": null
    },
    {
      "name": "Aruba.it-Other",
      "description": null
    },
    {
      "name": "Aruba.it-Web",
      "description": null
    },
    {
      "name": "Aruba.it-ICMP",
      "description": null
    },
    {
      "name": "Aruba.it-DNS",
      "description": null
    },
    {
      "name": "Aruba.it-Outbound_Email",
      "description": null
    },
    {
      "name": "Aruba.it-SSH",
      "description": null
    },
    {
      "name": "Aruba.it-FTP",
      "description": null
    },
    {
      "name": "Aruba.it-NTP",
      "description": null
    },
    {
      "name": "Aruba.it-Inbound_Email",
      "description": null
    },
    {
      "name": "Aruba.it-LDAP",
      "description": null
    },
    {
      "name": "Aruba.it-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Aruba.it-RTMP",
      "description": null
    },
    {
      "name": "Aruba.it-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "ISLOnline-Other",
      "description": null
    },
    {
      "name": "ISLOnline-Web",
      "description": null
    },
    {
      "name": "ISLOnline-ICMP",
      "description": null
    },
    {
      "name": "ISLOnline-DNS",
      "description": null
    },
    {
      "name": "ISLOnline-Outbound_Email",
      "description": null
    },
    {
      "name": "ISLOnline-SSH",
      "description": null
    },
    {
      "name": "ISLOnline-FTP",
      "description": null
    },
    {
      "name": "ISLOnline-NTP",
      "description": null
    },
    {
      "name": "ISLOnline-Inbound_Email",
      "description": null
    },
    {
      "name": "ISLOnline-LDAP",
      "description": null
    },
    {
      "name": "ISLOnline-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "ISLOnline-RTMP",
      "description": null
    },
    {
      "name": "ISLOnline-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Akamai-CDN",
      "description": null
    },
    {
      "name": "Rackspace-CDN",
      "description": null
    },
    {
      "name": "Instart-CDN",
      "description": null
    },
    {
      "name": "Bitdefender-Other",
      "description": null
    },
    {
      "name": "Bitdefender-Web",
      "description": null
    },
    {
      "name": "Bitdefender-ICMP",
      "description": null
    },
    {
      "name": "Bitdefender-DNS",
      "description": null
    },
    {
      "name": "Bitdefender-Outbound_Email",
      "description": null
    },
    {
      "name": "Bitdefender-SSH",
      "description": null
    },
    {
      "name": "Bitdefender-FTP",
      "description": null
    },
    {
      "name": "Bitdefender-NTP",
      "description": null
    },
    {
      "name": "Bitdefender-Inbound_Email",
      "description": null
    },
    {
      "name": "Bitdefender-LDAP",
      "description": null
    },
    {
      "name": "Bitdefender-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Bitdefender-RTMP",
      "description": null
    },
    {
      "name": "Bitdefender-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "UptimeRobot-UptimeRobot.Monitor",
      "description": null
    },
    {
      "name": "Quovadisglobal-Other",
      "description": null
    },
    {
      "name": "Quovadisglobal-Web",
      "description": null
    },
    {
      "name": "Quovadisglobal-ICMP",
      "description": null
    },
    {
      "name": "Quovadisglobal-DNS",
      "description": null
    },
    {
      "name": "Quovadisglobal-Outbound_Email",
      "description": null
    },
    {
      "name": "Quovadisglobal-SSH",
      "description": null
    },
    {
      "name": "Quovadisglobal-FTP",
      "description": null
    },
    {
      "name": "Quovadisglobal-NTP",
      "description": null
    },
    {
      "name": "Quovadisglobal-Inbound_Email",
      "description": null
    },
    {
      "name": "Quovadisglobal-LDAP",
      "description": null
    },
    {
      "name": "Quovadisglobal-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Quovadisglobal-RTMP",
      "description": null
    },
    {
      "name": "Quovadisglobal-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Splashtop-Splashtop",
      "description": null
    },
    {
      "name": "Zoox-Other",
      "description": null
    },
    {
      "name": "Zoox-Web",
      "description": null
    },
    {
      "name": "Zoox-ICMP",
      "description": null
    },
    {
      "name": "Zoox-DNS",
      "description": null
    },
    {
      "name": "Zoox-Outbound_Email",
      "description": null
    },
    {
      "name": "Zoox-SSH",
      "description": null
    },
    {
      "name": "Zoox-FTP",
      "description": null
    },
    {
      "name": "Zoox-NTP",
      "description": null
    },
    {
      "name": "Zoox-Inbound_Email",
      "description": null
    },
    {
      "name": "Zoox-LDAP",
      "description": null
    },
    {
      "name": "Zoox-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Zoox-RTMP",
      "description": null
    },
    {
      "name": "Zoox-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Skyfii-Other",
      "description": null
    },
    {
      "name": "Skyfii-Web",
      "description": null
    },
    {
      "name": "Skyfii-ICMP",
      "description": null
    },
    {
      "name": "Skyfii-DNS",
      "description": null
    },
    {
      "name": "Skyfii-Outbound_Email",
      "description": null
    },
    {
      "name": "Skyfii-SSH",
      "description": null
    },
    {
      "name": "Skyfii-FTP",
      "description": null
    },
    {
      "name": "Skyfii-NTP",
      "description": null
    },
    {
      "name": "Skyfii-Inbound_Email",
      "description": null
    },
    {
      "name": "Skyfii-LDAP",
      "description": null
    },
    {
      "name": "Skyfii-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Skyfii-RTMP",
      "description": null
    },
    {
      "name": "Skyfii-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "CoffeeBean-Other",
      "description": null
    },
    {
      "name": "CoffeeBean-Web",
      "description": null
    },
    {
      "name": "CoffeeBean-ICMP",
      "description": null
    },
    {
      "name": "CoffeeBean-DNS",
      "description": null
    },
    {
      "name": "CoffeeBean-Outbound_Email",
      "description": null
    },
    {
      "name": "CoffeeBean-SSH",
      "description": null
    },
    {
      "name": "CoffeeBean-FTP",
      "description": null
    },
    {
      "name": "CoffeeBean-NTP",
      "description": null
    },
    {
      "name": "CoffeeBean-Inbound_Email",
      "description": null
    },
    {
      "name": "CoffeeBean-LDAP",
      "description": null
    },
    {
      "name": "CoffeeBean-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "CoffeeBean-RTMP",
      "description": null
    },
    {
      "name": "CoffeeBean-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Cloud4Wi-Other",
      "description": null
    },
    {
      "name": "Cloud4Wi-Web",
      "description": null
    },
    {
      "name": "Cloud4Wi-ICMP",
      "description": null
    },
    {
      "name": "Cloud4Wi-DNS",
      "description": null
    },
    {
      "name": "Cloud4Wi-Outbound_Email",
      "description": null
    },
    {
      "name": "Cloud4Wi-SSH",
      "description": null
    },
    {
      "name": "Cloud4Wi-FTP",
      "description": null
    },
    {
      "name": "Cloud4Wi-NTP",
      "description": null
    },
    {
      "name": "Cloud4Wi-Inbound_Email",
      "description": null
    },
    {
      "name": "Cloud4Wi-LDAP",
      "description": null
    },
    {
      "name": "Cloud4Wi-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Cloud4Wi-RTMP",
      "description": null
    },
    {
      "name": "Cloud4Wi-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Panda-Panda.Security",
      "description": null
    },
    {
      "name": "Ewon-Talk2M",
      "description": null
    },
    {
      "name": "Nutanix-Nutanix.Cloud",
      "description": null
    },
    {
      "name": "Backblaze-Other",
      "description": null
    },
    {
      "name": "Backblaze-Web",
      "description": null
    },
    {
      "name": "Backblaze-ICMP",
      "description": null
    },
    {
      "name": "Backblaze-DNS",
      "description": null
    },
    {
      "name": "Backblaze-Outbound_Email",
      "description": null
    },
    {
      "name": "Backblaze-SSH",
      "description": null
    },
    {
      "name": "Backblaze-FTP",
      "description": null
    },
    {
      "name": "Backblaze-NTP",
      "description": null
    },
    {
      "name": "Backblaze-Inbound_Email",
      "description": null
    },
    {
      "name": "Backblaze-LDAP",
      "description": null
    },
    {
      "name": "Backblaze-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Backblaze-RTMP",
      "description": null
    },
    {
      "name": "Backblaze-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Extreme-Extreme.Cloud",
      "description": null
    },
    {
      "name": "XING-Other",
      "description": null
    },
    {
      "name": "XING-Web",
      "description": null
    },
    {
      "name": "XING-ICMP",
      "description": null
    },
    {
      "name": "XING-DNS",
      "description": null
    },
    {
      "name": "XING-Outbound_Email",
      "description": null
    },
    {
      "name": "XING-SSH",
      "description": null
    },
    {
      "name": "XING-FTP",
      "description": null
    },
    {
      "name": "XING-NTP",
      "description": null
    },
    {
      "name": "XING-Inbound_Email",
      "description": null
    },
    {
      "name": "XING-LDAP",
      "description": null
    },
    {
      "name": "XING-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "XING-RTMP",
      "description": null
    },
    {
      "name": "XING-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Genesys-PureCloud",
      "description": null
    },
    {
      "name": "BlackBerry-Cylance",
      "description": null
    },
    {
      "name": "DigiCert-OCSP",
      "description": null
    },
    {
      "name": "Infomaniak-SwissTransfer",
      "description": null
    },
    {
      "name": "Fuze-Fuze",
      "description": null
    },
    {
      "name": "Truecaller-Truecaller",
      "description": null
    },
    {
      "name": "GlobalSign-OCSP",
      "description": null
    },
    {
      "name": "VeriSign-OCSP",
      "description": null
    },
    {
      "name": "Sony-PlayStation.Network",
      "description": null
    },
    {
      "name": "Acronis-Cyber.Cloud",
      "description": null
    },
    {
      "name": "RingCentral-RingCentral",
      "description": null
    },
    {
      "name": "FSecure-FSecure",
      "description": null
    },
    {
      "name": "Kaseya-Kaseya.Cloud",
      "description": null
    },
    {
      "name": "Shodan-Scanner",
      "description": null
    },
    {
      "name": "Censys-Scanner",
      "description": null
    },
    {
      "name": "Valve-Steam",
      "description": null
    },
    {
      "name": "YouSeeU-Bongo",
      "description": null
    },
    {
      "name": "Cato-Cato.Cloud",
      "description": null
    },
    {
      "name": "SolarWinds-SpamExperts",
      "description": null
    },
    {
      "name": "SolarWinds-Pingdom.Probe",
      "description": null
    },
    {
      "name": "8X8-8X8.Cloud",
      "description": null
    },
    {
      "name": "Zattoo-Zattoo.TV",
      "description": null
    },
    {
      "name": "Datto-Datto.RMM",
      "description": null
    },
    {
      "name": "Barracuda-Barracuda.Cloud",
      "description": null
    },
    {
      "name": "Naver-Line",
      "description": null
    },
    {
      "name": "Disney-Disney+",
      "description": null
    },
    {
      "name": "DNS-DoH_DoT",
      "description": null
    },
    {
      "name": "Quad9-Quad9.Standard.DNS",
      "description": null
    },
    {
      "name": "Stretchoid-Scanner",
      "description": null
    },
    {
      "name": "Poly-RealConnect.Service",
      "description": null
    },
    {
      "name": "Telegram-Telegram",
      "description": null
    },
    {
      "name": "Spotify-Spotify",
      "description": null
    },
    {
      "name": "NextDNS-NextDNS",
      "description": null
    },
    {
      "name": "Fastly-CDN",
      "description": null
    },
    {
      "name": "Neustar-UltraDNS.Probes",
      "description": null
    },
    {
      "name": "Microsoft-Intune",
      "description": null
    },
    {
      "name": "Microsoft-Office365.Published.Optimize",
      "description": null
    },
    {
      "name": "Microsoft-Office365.Published.Allow",
      "description": null
    },
    {
      "name": "Microsoft-Office365.Published.USGOV",
      "description": null
    },
    {
      "name": "Microsoft-Azure.Monitor",
      "description": null
    },
    {
      "name": "Microsoft-Azure.SQL",
      "description": null
    },
    {
      "name": "Microsoft-Azure.AD",
      "description": null
    },
    {
      "name": "Microsoft-Azure.Data.Factory",
      "description": null
    },
    {
      "name": "Microsoft-Azure.Virtual.Desktop",
      "description": null
    },
    {
      "name": "Microsoft-Azure.Power.BI",
      "description": null
    },
    {
      "name": "Amazon-Twitch",
      "description": null
    },
    {
      "name": "Amazon-AWS.GovCloud.US",
      "description": null
    },
    {
      "name": "Amazon-AWS.EBS",
      "description": null
    },
    {
      "name": "Amazon-AWS.Cloud9",
      "description": null
    },
    {
      "name": "Amazon-AWS.DynamoDB",
      "description": null
    },
    {
      "name": "Amazon-AWS.Route53",
      "description": null
    },
    {
      "name": "Amazon-AWS.S3",
      "description": null
    },
    {
      "name": "Amazon-AWS.Kinesis.Video.Streams",
      "description": null
    },
    {
      "name": "Amazon-AWS.Global.Accelerator",
      "description": null
    },
    {
      "name": "Amazon-AWS.EC2",
      "description": null
    },
    {
      "name": "Amazon-AWS.API.Gateway",
      "description": null
    },
    {
      "name": "Amazon-AWS.Chime.Voice.Connector",
      "description": null
    },
    {
      "name": "Amazon-AWS.Connect",
      "description": null
    },
    {
      "name": "Amazon-AWS.CloudFront",
      "description": null
    },
    {
      "name": "Amazon-AWS.CodeBuild",
      "description": null
    },
    {
      "name": "Amazon-AWS.Chime.Meetings",
      "description": null
    },
    {
      "name": "Amazon-AWS.AppFlow",
      "description": null
    },
    {
      "name": "Amazon-Amazon.SES",
      "description": null
    },
    {
      "name": "Adobe-Adobe.Sign",
      "description": null
    },
    {
      "name": "Fortinet-FortiVoice.Cloud",
      "description": null
    },
    {
      "name": "Fortinet-FortiGuard.Secure.DNS",
      "description": null
    },
    {
      "name": "Fortinet-FortiEDR",
      "description": null
    },
    {
      "name": "Zoho-Site24x7.Monitor",
      "description": null
    },
    {
      "name": "Cisco-Webex.FedRAMP",
      "description": null
    },
    {
      "name": "Cisco-Secure.Endpoint",
      "description": null
    },
    {
      "name": "Atlassian-Atlassian.Cloud",
      "description": null
    },
    {
      "name": "Atlassian-Atlassian.Notification",
      "description": null
    },
    {
      "name": "Akamai-Linode.Cloud",
      "description": null
    },
    {
      "name": "SolarWinds-SolarWinds.RMM",
      "description": null
    },
    {
      "name": "DNS-Root.Name.Servers",
      "description": null
    },
    {
      "name": "Malicious-Malicious.Server",
      "description": null
    },
    {
      "name": "NIST-ITS",
      "description": null
    },
    {
      "name": "Jamf-Jamf.Cloud",
      "description": null
    },
    {
      "name": "Alcatel.Lucent-Rainbow",
      "description": null
    },
    {
      "name": "Forcepoint-Forcepoint.Cloud",
      "description": null
    },
    {
      "name": "Datadog-Datadog",
      "description": null
    },
    {
      "name": "Mimecast-Mimecast",
      "description": null
    },
    {
      "name": "MediaFire-Other",
      "description": null
    },
    {
      "name": "MediaFire-Web",
      "description": null
    },
    {
      "name": "MediaFire-ICMP",
      "description": null
    },
    {
      "name": "MediaFire-DNS",
      "description": null
    },
    {
      "name": "MediaFire-Outbound_Email",
      "description": null
    },
    {
      "name": "MediaFire-SSH",
      "description": null
    },
    {
      "name": "MediaFire-FTP",
      "description": null
    },
    {
      "name": "MediaFire-NTP",
      "description": null
    },
    {
      "name": "MediaFire-Inbound_Email",
      "description": null
    },
    {
      "name": "MediaFire-LDAP",
      "description": null
    },
    {
      "name": "MediaFire-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "MediaFire-RTMP",
      "description": null
    },
    {
      "name": "MediaFire-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Pandora-Pandora",
      "description": null
    },
    {
      "name": "SiriusXM-SiriusXM",
      "description": null
    },
    {
      "name": "Hopin-Hopin",
      "description": null
    },
    {
      "name": "RedShield-RedShield.Cloud",
      "description": null
    },
    {
      "name": "InterneTTL-Scanner",
      "description": null
    },
    {
      "name": "VadeSecure-VadeSecure.Cloud",
      "description": null
    },
    {
      "name": "Netskope-Netskope.Cloud",
      "description": null
    },
    {
      "name": "ClickMeeting-ClickMeeting",
      "description": null
    },
    {
      "name": "Tenable-Tenable.io.Cloud.Scanner",
      "description": null
    },
    {
      "name": "Vidyo-VidyoCloud",
      "description": null
    },
    {
      "name": "OpenNIC-OpenNIC.DNS",
      "description": null
    },
    {
      "name": "Sectigo-Sectigo",
      "description": null
    },
    {
      "name": "DigitalOcean-DigitalOcean.Platform",
      "description": null
    },
    {
      "name": "Pitney.Bowes-Pitney.Bowes.Data.Center",
      "description": null
    },
    {
      "name": "VPN-Anonymous.VPN",
      "description": null
    },
    {
      "name": "Blockchain-Crypto.Mining.Pool",
      "description": null
    },
    {
      "name": "FactSet-FactSet",
      "description": null
    },
    {
      "name": "Bloomberg-Bloomberg",
      "description": null
    },
    {
      "name": "Five9-Five9",
      "description": null
    },
    {
      "name": "Gigas-Gigas.Cloud",
      "description": null
    },
    {
      "name": "Imperva-Imperva.Cloud.WAF",
      "description": null
    },
    {
      "name": "HorizonIQ-HorizonIQ",
      "description": null
    },
    {
      "name": "Azion-Azion.Platform",
      "description": null
    },
    {
      "name": "Hurricane.Electric-Hurricane.Electric.Internet.Services",
      "description": null
    },
    {
      "name": "NodePing-NodePing.Probe",
      "description": null
    },
    {
      "name": "Frontline-Frontline",
      "description": null
    },
    {
      "name": "Tally-Tally.ERP",
      "description": null
    },
    {
      "name": "Hosting-Bulletproof.Hosting",
      "description": null
    },
    {
      "name": "Okko-Okko.TV",
      "description": null
    },
    {
      "name": "Voximplant-Voximplant.Platform",
      "description": null
    },
    {
      "name": "OVHcloud-OVHcloud",
      "description": null
    },
    {
      "name": "SentinelOne-SentinelOne.Cloud",
      "description": null
    },
    {
      "name": "Kakao-Kakao.Services",
      "description": null
    },
    {
      "name": "Stripe-Stripe",
      "description": null
    },
    {
      "name": "NetScout-Scanner",
      "description": null
    },
    {
      "name": "Recyber-Scanner",
      "description": null
    },
    {
      "name": "Cyber.Casa-Scanner",
      "description": null
    },
    {
      "name": "GTHost-Dedicated.Instant.Servers",
      "description": null
    },
    {
      "name": "ivi-ivi.Streaming",
      "description": null
    },
    {
      "name": "BinaryEdge-Scanner",
      "description": null
    },
    {
      "name": "Fintech-MarketMap.Terminal",
      "description": null
    },
    {
      "name": "xMatters-xMatters.Platform",
      "description": null
    },
    {
      "name": "Blizzard-Battle.Net",
      "description": null
    },
    {
      "name": "Axon-Evidence",
      "description": null
    },
    {
      "name": "CDN77-CDN",
      "description": null
    },
    {
      "name": "GCore.Labs-CDN",
      "description": null
    },
    {
      "name": "Matrix42-FastViewer",
      "description": null
    },
    {
      "name": "Bunny.net-CDN",
      "description": null
    },
    {
      "name": "StackPath-CDN",
      "description": null
    },
    {
      "name": "Edgio-CDN",
      "description": null
    },
    {
      "name": "CacheFly-CDN",
      "description": null
    },
    {
      "name": "Bluejeans-Bluejeans.Meeting",
      "description": null
    },
    {
      "name": "Microsoft-Azure.Connectors",
      "description": null
    },
    {
      "name": "Microsoft-Teams.Published.Worldwide.Optimize",
      "description": null
    },
    {
      "name": "Microsoft-Teams.Published.Worldwide.Allow",
      "description": null
    },
    {
      "name": "Microsoft-Azure.Front.Door",
      "description": null
    },
    {
      "name": "Microsoft-Azure.Service.Bus",
      "description": null
    },
    {
      "name": "Microsoft-Azure.Microsoft.Defender",
      "description": null
    },
    {
      "name": "Microsoft-Azure.Resource.Manager",
      "description": null
    },
    {
      "name": "Microsoft-Azure.Arc.Infrastructure",
      "description": null
    },
    {
      "name": "Microsoft-Azure.Storage",
      "description": null
    },
    {
      "name": "Microsoft-Azure.ATP",
      "description": null
    },
    {
      "name": "Microsoft-Azure.Traffic.Manager",
      "description": null
    },
    {
      "name": "Microsoft-Azure.Windows.Admin.Center",
      "description": null
    },
    {
      "name": "Microsoft-Azure.KeyVault",
      "description": null
    },
    {
      "name": "Microsoft-Azure.Databricks",
      "description": null
    },
    {
      "name": "Microsoft-Azure.Event.Hub",
      "description": null
    },
    {
      "name": "Microsoft-Azure.Power.Platform",
      "description": null
    },
    {
      "name": "Microsoft-Azure.Front.Door.MicrosoftSecurity",
      "description": null
    },
    {
      "name": "Microsoft-Azure.OneDsCollector",
      "description": null
    },
    {
      "name": "Salesforce-Hyperforce",
      "description": null
    },
    {
      "name": "Fortinet-FortiClient.EMS",
      "description": null
    },
    {
      "name": "Fortinet-FortiWeb.Cloud",
      "description": null
    },
    {
      "name": "Fortinet-FortiSASE",
      "description": null
    },
    {
      "name": "Fortinet-FortiGuard.SOCaaS",
      "description": null
    },
    {
      "name": "Fortinet-FortiDLP.Cloud",
      "description": null
    },
    {
      "name": "Fortinet-FortiMonitor",
      "description": null
    },
    {
      "name": "Fortinet-FortiSandbox",
      "description": null
    },
    {
      "name": "Fortinet-FortiSandbox.Cloud",
      "description": null
    },
    {
      "name": "Tencent-VooV.Meeting",
      "description": null
    },
    {
      "name": "NewRelic-Synthetic.Monitor",
      "description": null
    },
    {
      "name": "Rapid7-Scanner",
      "description": null
    },
    {
      "name": "SAP-SAP.Ariba",
      "description": null
    },
    {
      "name": "Alibaba-DingTalk",
      "description": null
    },
    {
      "name": "ISLOnline-ISLOnline",
      "description": null
    },
    {
      "name": "Datto-Datto.BCDR",
      "description": null
    },
    {
      "name": "DNS-ARPA.Name.Servers",
      "description": null
    },
    {
      "name": "DNS-Generic.TLD.Name.Servers",
      "description": null
    },
    {
      "name": "OVHcloud-OVH.Telecom",
      "description": null
    },
    {
      "name": "Paylocity-Paylocity",
      "description": null
    },
    {
      "name": "Qualys-Qualys.Cloud.Platform",
      "description": null
    },
    {
      "name": "Dailymotion-Other",
      "description": null
    },
    {
      "name": "Dailymotion-Web",
      "description": null
    },
    {
      "name": "Dailymotion-ICMP",
      "description": null
    },
    {
      "name": "Dailymotion-DNS",
      "description": null
    },
    {
      "name": "Dailymotion-Outbound_Email",
      "description": null
    },
    {
      "name": "Dailymotion-SSH",
      "description": null
    },
    {
      "name": "Dailymotion-FTP",
      "description": null
    },
    {
      "name": "Dailymotion-NTP",
      "description": null
    },
    {
      "name": "Dailymotion-Inbound_Email",
      "description": null
    },
    {
      "name": "Dailymotion-LDAP",
      "description": null
    },
    {
      "name": "Dailymotion-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Dailymotion-RTMP",
      "description": null
    },
    {
      "name": "Dailymotion-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "LaunchDarkly-LaunchDarkly.Platform",
      "description": null
    },
    {
      "name": "Medianova-CDN",
      "description": null
    },
    {
      "name": "NetDocuments-NetDocuments.Platform",
      "description": null
    },
    {
      "name": "Vonage-Vonage.Contact.Center",
      "description": null
    },
    {
      "name": "Vonage-Vonage.Video.API",
      "description": null
    },
    {
      "name": "Veritas-Enterprise.Vault.Cloud",
      "description": null
    },
    {
      "name": "UK.NCSC-Scanner",
      "description": null
    },
    {
      "name": "Restream-Restream.Platform",
      "description": null
    },
    {
      "name": "ArcticWolf-ArcticWolf.Cloud",
      "description": null
    },
    {
      "name": "CounterPath-Bria",
      "description": null
    },
    {
      "name": "CriminalIP-Scanner",
      "description": null
    },
    {
      "name": "IPFS-IPFS.Gateway",
      "description": null
    },
    {
      "name": "Internet.Census.Group-Scanner",
      "description": null
    },
    {
      "name": "Performive-Performive.Cloud",
      "description": null
    },
    {
      "name": "OneLogin-OneLogin",
      "description": null
    },
    {
      "name": "Shadowserver-Scanner",
      "description": null
    },
    {
      "name": "Turkcell-Suit.Conference",
      "description": null
    },
    {
      "name": "LeakIX-Scanner",
      "description": null
    },
    {
      "name": "Infoblox-BloxOne",
      "description": null
    },
    {
      "name": "Nice-CXone",
      "description": null
    },
    {
      "name": "Hetzner-Hetzner.Hosting.Service",
      "description": null
    },
    {
      "name": "ThreatLocker-ThreatLocker",
      "description": null
    },
    {
      "name": "ZPE-ZPE.Cloud",
      "description": null
    },
    {
      "name": "ColoCrossing-ColoCrossing.Hosting.Service",
      "description": null
    },
    {
      "name": "Sinch-Mailgun",
      "description": null
    },
    {
      "name": "SpaceX-Starlink",
      "description": null
    },
    {
      "name": "Ingenuity-Ingenuity.Cloud.Service",
      "description": null
    },
    {
      "name": "Skyhigh.Security-Secure.Web.Gateway",
      "description": null
    },
    {
      "name": "THE.Hosting-THE.Hosting.Hosting.Service",
      "description": null
    },
    {
      "name": "StatusCake-StatusCake.Monitor",
      "description": null
    },
    {
      "name": "NAP-NAPLAN",
      "description": null
    },
    {
      "name": "Elastic-Elastic.Cloud",
      "description": null
    },
    {
      "name": "NFON-NFON",
      "description": null
    },
    {
      "name": "SERVERD-SERVERD.Hosting.Service",
      "description": null
    },
    {
      "name": "MEGA-MEGA.Cloud",
      "description": null
    },
    {
      "name": "Hadrian-Scanner",
      "description": null
    },
    {
      "name": "Dotcom.Monitor-Dotcom.Monitor",
      "description": null
    },
    {
      "name": "Ahrefs-AhrefsBot",
      "description": null
    },
    {
      "name": "Semrush-SemrushBot",
      "description": null
    },
    {
      "name": "Zero.Networks-Zero.Networks",
      "description": null
    },
    {
      "name": "Vultr-Vultr.Cloud",
      "description": null
    },
    {
      "name": "EGI-EGI.Hosting.Service",
      "description": null
    },
    {
      "name": "ONYPHE-Scanner",
      "description": null
    },
    {
      "name": "Proofpoint-Proofpoint",
      "description": null
    },
    {
      "name": "Lookout-Lookout.Cloud",
      "description": null
    },
    {
      "name": "Heimdal-Heimdal.Security",
      "description": null
    },
    {
      "name": "Yealink-Yealink.Meeting",
      "description": null
    },
    {
      "name": "Secomea-Secomea",
      "description": null
    },
    {
      "name": "CallTower-CT.Cloud",
      "description": null
    },
    {
      "name": "OpenAI-OpenAI.Bot",
      "description": null
    },
    {
      "name": "OpenAI-GPT.Actions",
      "description": null
    },
    {
      "name": "Alpemix-Alpemix",
      "description": null
    },
    {
      "name": "M247-M247.Hosting.Service",
      "description": null
    },
    {
      "name": "Quintex-Quintex.Hosting.Service",
      "description": null
    },
    {
      "name": "Aeza-Aeza.Hosting.Service",
      "description": null
    },
    {
      "name": "Amanah-Amanah.Hosting.Service",
      "description": null
    },
    {
      "name": "ByteDance-Lark",
      "description": null
    },
    {
      "name": "KnowBe4-KnowBe4",
      "description": null
    },
    {
      "name": "Keeper-Keeper.Security",
      "description": null
    },
    {
      "name": "NinjaOne-NinjaOne",
      "description": null
    },
    {
      "name": "Modat-Scanner",
      "description": null
    },
    {
      "name": "Make-Make.Platform",
      "description": null
    },
    {
      "name": "Cloudzy-Cloudzy.Hosting.Service",
      "description": null
    },
    {
      "name": "Nokia-Deepfield.Genome.Crawler",
      "description": null
    },
    {
      "name": "Neat-Neat.Cloud",
      "description": null
    },
    {
      "name": "Brightree-Brightree",
      "description": null
    },
    {
      "name": "PagerDuty-PagerDuty",
      "description": null
    },
    {
      "name": "JFrog-JFrog",
      "description": null
    },
    {
      "name": "Tailscale-Tailscale",
      "description": null
    },
    {
      "name": "Gamma-Horizon",
      "description": null
    },
    {
      "name": "Automox-Automox",
      "description": null
    },
    {
      "name": "Pulseway-Pulseway.RMM",
      "description": null
    },
    {
      "name": "3xK-3xK.Hosting.Service",
      "description": null
    },
    {
      "name": "ASEM-UBIQUITY",
      "description": null
    },
    {
      "name": "Dialpad-Dialpad",
      "description": null
    },
    {
      "name": "iboss-iboss.Cloud",
      "description": null
    },
    {
      "name": "Redstor-Redstor",
      "description": null
    },
    {
      "name": "Anthropic-Claude",
      "description": null
    },
    {
      "name": "NETLOCK-NETLOCK",
      "description": null
    },
    {
      "name": "Aircall-Aircall",
      "description": null
    },
    {
      "name": "Mendix-Mendix.Cloud",
      "description": null
    },
    {
      "name": "Palo.Alto.Networks-Cortex.Xpanse.Scanner",
      "description": null
    },
    {
      "name": "Microsoft-Azure.Sentinel",
      "description": null
    },
    {
      "name": "Tor-Tor.Node",
      "description": null
    },
    {
      "name": "Zendesk-Other",
      "description": null
    },
    {
      "name": "Zendesk-Web",
      "description": null
    },
    {
      "name": "Zendesk-ICMP",
      "description": null
    },
    {
      "name": "Zendesk-DNS",
      "description": null
    },
    {
      "name": "Zendesk-Outbound_Email",
      "description": null
    },
    {
      "name": "Zendesk-SSH",
      "description": null
    },
    {
      "name": "Zendesk-FTP",
      "description": null
    },
    {
      "name": "Zendesk-NTP",
      "description": null
    },
    {
      "name": "Zendesk-Inbound_Email",
      "description": null
    },
    {
      "name": "Zendesk-LDAP",
      "description": null
    },
    {
      "name": "Zendesk-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Zendesk-RTMP",
      "description": null
    },
    {
      "name": "Zendesk-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Pingdom-Other",
      "description": null
    },
    {
      "name": "Pingdom-Web",
      "description": null
    },
    {
      "name": "Pingdom-ICMP",
      "description": null
    },
    {
      "name": "Pingdom-DNS",
      "description": null
    },
    {
      "name": "Pingdom-Outbound_Email",
      "description": null
    },
    {
      "name": "Pingdom-SSH",
      "description": null
    },
    {
      "name": "Pingdom-FTP",
      "description": null
    },
    {
      "name": "Pingdom-NTP",
      "description": null
    },
    {
      "name": "Pingdom-Inbound_Email",
      "description": null
    },
    {
      "name": "Pingdom-LDAP",
      "description": null
    },
    {
      "name": "Pingdom-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "Pingdom-RTMP",
      "description": null
    },
    {
      "name": "Pingdom-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "UptimeRobot-Other",
      "description": null
    },
    {
      "name": "UptimeRobot-Web",
      "description": null
    },
    {
      "name": "UptimeRobot-ICMP",
      "description": null
    },
    {
      "name": "UptimeRobot-DNS",
      "description": null
    },
    {
      "name": "UptimeRobot-Outbound_Email",
      "description": null
    },
    {
      "name": "UptimeRobot-SSH",
      "description": null
    },
    {
      "name": "UptimeRobot-FTP",
      "description": null
    },
    {
      "name": "UptimeRobot-NTP",
      "description": null
    },
    {
      "name": "UptimeRobot-Inbound_Email",
      "description": null
    },
    {
      "name": "UptimeRobot-LDAP",
      "description": null
    },
    {
      "name": "UptimeRobot-NetBIOS.Session.Service",
      "description": null
    },
    {
      "name": "UptimeRobot-RTMP",
      "description": null
    },
    {
      "name": "UptimeRobot-NetBIOS.Name.Service",
      "description": null
    },
    {
      "name": "Microsoft-Azure.IoT.Hub",
      "description": null
    }
  ],
  "audit_entries": [
    {
      "id": "EMS_ALL_UNKNOWN_CLIENTS",
      "category": "Address",
      "message": "Dynamic/EMS Tag 'EMS_ALL_UNKNOWN_CLIENTS' automatically converted to Target Dynamic Address Group (DAG) with filter 'EMS_ALL_UNKNOWN_CLIENTS'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "EMS_ALL_UNMANAGEABLE_CLIENTS",
      "category": "Address",
      "message": "Dynamic/EMS Tag 'EMS_ALL_UNMANAGEABLE_CLIENTS' automatically converted to Target Dynamic Address Group (DAG) with filter 'EMS_ALL_UNMANAGEABLE_CLIENTS'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "FCTEMS_ALL_FORTICLOUD_SERVERS",
      "category": "Address",
      "message": "Dynamic/EMS Tag 'FCTEMS_ALL_FORTICLOUD_SERVERS' automatically converted to Target Dynamic Address Group (DAG) with filter 'FCTEMS_ALL_FORTICLOUD_SERVERS'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "EMS1_ZTNA_all_registered_clients",
      "category": "Address",
      "message": "Dynamic/EMS Tag 'EMS1_ZTNA_all_registered_clients' automatically converted to Target Dynamic Address Group (DAG) with filter 'EMS1_ZTNA_all_registered_clients'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "MAC_EMS1_ZTNA_all_registered_clients",
      "category": "Address",
      "message": "Dynamic/EMS Tag 'MAC_EMS1_ZTNA_all_registered_clients' automatically converted to Target Dynamic Address Group (DAG) with filter 'MAC_EMS1_ZTNA_all_registered_clients'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "EMS1_ZTNA_Deleum_ADUser",
      "category": "Address",
      "message": "Dynamic/EMS Tag 'EMS1_ZTNA_Deleum_ADUser' automatically converted to Target Dynamic Address Group (DAG) with filter 'EMS1_ZTNA_Deleum_ADUser'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "MAC_EMS1_ZTNA_Deleum_ADUser",
      "category": "Address",
      "message": "Dynamic/EMS Tag 'MAC_EMS1_ZTNA_Deleum_ADUser' automatically converted to Target Dynamic Address Group (DAG) with filter 'MAC_EMS1_ZTNA_Deleum_ADUser'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "EMS1_ZTNA_Deleum_AV",
      "category": "Address",
      "message": "Dynamic/EMS Tag 'EMS1_ZTNA_Deleum_AV' automatically converted to Target Dynamic Address Group (DAG) with filter 'EMS1_ZTNA_Deleum_AV'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "MAC_EMS1_ZTNA_Deleum_AV",
      "category": "Address",
      "message": "Dynamic/EMS Tag 'MAC_EMS1_ZTNA_Deleum_AV' automatically converted to Target Dynamic Address Group (DAG) with filter 'MAC_EMS1_ZTNA_Deleum_AV'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "EMS1_ZTNA_Deleum_CriticalVul",
      "category": "Address",
      "message": "Dynamic/EMS Tag 'EMS1_ZTNA_Deleum_CriticalVul' automatically converted to Target Dynamic Address Group (DAG) with filter 'EMS1_ZTNA_Deleum_CriticalVul'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "MAC_EMS1_ZTNA_Deleum_CriticalVul",
      "category": "Address",
      "message": "Dynamic/EMS Tag 'MAC_EMS1_ZTNA_Deleum_CriticalVul' automatically converted to Target Dynamic Address Group (DAG) with filter 'MAC_EMS1_ZTNA_Deleum_CriticalVul'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "EMS1_ZTNA_Not_Log_Domain_Name",
      "category": "Address",
      "message": "Dynamic/EMS Tag 'EMS1_ZTNA_Not_Log_Domain_Name' automatically converted to Target Dynamic Address Group (DAG) with filter 'EMS1_ZTNA_Not_Log_Domain_Name'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "EMS1_ZTNA_Outdated_Windows",
      "category": "Address",
      "message": "Dynamic/EMS Tag 'EMS1_ZTNA_Outdated_Windows' automatically converted to Target Dynamic Address Group (DAG) with filter 'EMS1_ZTNA_Outdated_Windows'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "MAC_EMS1_ZTNA_Outdated_Windows",
      "category": "Address",
      "message": "Dynamic/EMS Tag 'MAC_EMS1_ZTNA_Outdated_Windows' automatically converted to Target Dynamic Address Group (DAG) with filter 'MAC_EMS1_ZTNA_Outdated_Windows'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "EMS1_ZTNA_Deleum_OSVersion",
      "category": "Address",
      "message": "Dynamic/EMS Tag 'EMS1_ZTNA_Deleum_OSVersion' automatically converted to Target Dynamic Address Group (DAG) with filter 'EMS1_ZTNA_Deleum_OSVersion'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "MAC_EMS1_ZTNA_Deleum_OSVersion",
      "category": "Address",
      "message": "Dynamic/EMS Tag 'MAC_EMS1_ZTNA_Deleum_OSVersion' automatically converted to Target Dynamic Address Group (DAG) with filter 'MAC_EMS1_ZTNA_Deleum_OSVersion'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "EMS1_ZTNA_Not_Deleum",
      "category": "Address",
      "message": "Dynamic/EMS Tag 'EMS1_ZTNA_Not_Deleum' automatically converted to Target Dynamic Address Group (DAG) with filter 'EMS1_ZTNA_Not_Deleum'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "MAC_EMS1_ZTNA_Not_Deleum",
      "category": "Address",
      "message": "Dynamic/EMS Tag 'MAC_EMS1_ZTNA_Not_Deleum' automatically converted to Target Dynamic Address Group (DAG) with filter 'MAC_EMS1_ZTNA_Not_Deleum'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "EMS1_ZTNA_Crit_Vul",
      "category": "Address",
      "message": "Dynamic/EMS Tag 'EMS1_ZTNA_Crit_Vul' automatically converted to Target Dynamic Address Group (DAG) with filter 'EMS1_ZTNA_Crit_Vul'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "MAC_EMS1_ZTNA_Crit_Vul",
      "category": "Address",
      "message": "Dynamic/EMS Tag 'MAC_EMS1_ZTNA_Crit_Vul' automatically converted to Target Dynamic Address Group (DAG) with filter 'MAC_EMS1_ZTNA_Crit_Vul'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "google-play",
      "category": "Address",
      "message": "Wildcard FQDN '*play.google.com' normalized to PAN-OS format '*.play.google.com'. Note: Apex domain matching behavior may differ. Review for semantics.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "update.microsoft.com",
      "category": "Address",
      "message": "Wildcard FQDN '*update.microsoft.com' normalized to PAN-OS format '*.update.microsoft.com'. Note: Apex domain matching behavior may differ. Review for semantics.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "swscan.apple.com",
      "category": "Address",
      "message": "Wildcard FQDN '*swscan.apple.com' normalized to PAN-OS format '*.swscan.apple.com'. Note: Apex domain matching behavior may differ. Review for semantics.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "autoupdate.opera.com",
      "category": "Address",
      "message": "Wildcard FQDN '*autoupdate.opera.com' normalized to PAN-OS format '*.autoupdate.opera.com'. Note: Apex domain matching behavior may differ. Review for semantics.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "google-drive",
      "category": "Address",
      "message": "Wildcard FQDN '*drive.google.com' normalized to PAN-OS format '*.drive.google.com'. Note: Apex domain matching behavior may differ. Review for semantics.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "itunes",
      "category": "Address",
      "message": "Wildcard FQDN '*itunes.apple.com' normalized to PAN-OS format '*.itunes.apple.com'. Note: Apex domain matching behavior may differ. Review for semantics.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "3",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "252",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "253",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "258",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "263",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "255",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "259",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "264",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "257",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "260",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "256",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "254",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "261",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "9",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'Migrated_Profiles'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "285",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "298",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "288",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "302",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "286",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "295",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "292",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "303",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "269",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "282",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "297",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "291",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "305",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "281",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "284",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "299",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "289",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "301",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "287",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "296",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "293",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "304",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "274",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "280",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "128",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "23",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "127",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "186",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_WF_deleum_webfilter_APP_deleum_application_control'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "137",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_APP_deleum_application_control'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "72",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_WF_deleum_webfilter_APP_deleum_application_control'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "33",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "249",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_WF_wifi__deleum_webfilter_APP_deleum_application_control_fo'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "39",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_WF_wifi__deleum_webfilter_APP_deleum_application_control'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "147",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "148",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "152",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "150",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "154",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "160",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "174",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "155",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "157",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "156",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_WF_deleum_webfilter_APP_deleum_application_control'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "172",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "161",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "180",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "162",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "188",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "272",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "276",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "190",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "178",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "164",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "171",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "216",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "224",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "226",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "225",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "227",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "205",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "230",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "231",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "176",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "242",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "203",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "245",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "131",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "241",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "240",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "195",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "196",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "246",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "167",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "236",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "169",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "133",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "165",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "184",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "182",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default_WF_deleum_webfilter_APP_deleum_application_cont'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "82",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "211",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "168",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "210",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "134",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "112",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "238",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "212",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "232",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "244",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "239",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "233",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "135",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "25",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_AV_default_IPS_high_security_WF_deleum_webfilter_APP_deleum'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "136",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "26",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "21",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_AV_default_IPS_high_security_WF_deleum_webfilter_APP_deleum'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "22",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "138",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "119",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "34",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "18",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "124",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "149",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security_APP_deleum_application_control'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "181",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "36",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security_APP_deleum_application_control'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "61",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "283",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "294",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "290",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'Migrated_Profiles'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "300",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'Migrated_Profiles'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "62",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "78",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "123",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "76",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "79",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "198",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "197",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "106",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "146",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "243",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "143",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "217",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "132",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "116",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "237",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "218",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_high_security'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "219",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_IPS_default'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "266",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_AV_default_IPS_high_security_WF_deleum_webfilter_APP_deleum'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "312",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_WF_deleum_webfilter_APP_deleum_application_control'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "311",
      "category": "Policy",
      "message": "UTM profiles mapped to Security Profile Group 'SPG_AV_default_IPS_high_security_WF_deleum_webfilter_APP_deleum'.",
      "confidence": "full",
      "original_config": null
    },
    {
      "id": "toMiriWH",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "to_CKJ_unifi",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "to_DOSSB_Miri",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "toDOSSB_KSB",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "toIT_fromHQ",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "toCKJ_secondary",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "to_TKY",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "toTKY_secondary",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "toKSB_secondary",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "MiriWHsecondary",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "Miri_secondary",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "toKK_secondary",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "to_KK",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "toLabuan",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "toLabuan_second",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "toIT_secondary",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "toMiri_DTS",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "MiriDTS_second",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "toBintulu1",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "toBintulu2",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "Bintulu1_second",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "Bintulu2_second",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    },
    {
      "id": "FortiClient",
      "category": "VPN",
      "message": "IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
      "confidence": "partial",
      "original_config": null
    }
  ]
}
```

</details>
