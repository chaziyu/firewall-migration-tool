# ==============================================================================
# Palo Alto Networks PAN-OS Terraform Configuration
# Generated automatically from FortiGate configuration (deleumHQ)
# Provider: PaloAltoNetworks/panos (~> 1.11)
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. Address Objects & Custom URL Categories
# ------------------------------------------------------------------------------

resource "panos_address_object" "addr_Biometric-192_168_10_0_24" {
  vsys        = var.panos_vsys
  name        = "Biometric-192.168.10.0_24"
  value       = "192.168.10.0/24"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_DPSB_CKJ_192_168_14_0_24" {
  vsys        = var.panos_vsys
  name        = "DPSB_CKJ_192.168.14.0_24"
  value       = "192.168.14.0/24"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_Miri_DTS_192_168_6_0_24" {
  vsys        = var.panos_vsys
  name        = "Miri_DTS_192.168.6.0_24"
  value       = "192.168.6.0/24"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_DPSB_Miri-192_168_9_0_24" {
  vsys        = var.panos_vsys
  name        = "DPSB_Miri-192.168.9.0_24"
  value       = "192.168.9.0/24"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_DPSB_TK_new_192_168_7_0_24" {
  vsys        = var.panos_vsys
  name        = "DPSB_TK_new_192.168.7.0_24"
  value       = "192.168.7.0/24"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_DR-192_168_43_0_24" {
  vsys        = var.panos_vsys
  name        = "DR-192.168.43.0_24"
  value       = "192.168.43.0/24"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_Bintulu2-192_168_3_0_24" {
  vsys        = var.panos_vsys
  name        = "Bintulu2-192.168.3.0_24"
  value       = "192.168.3.0/24"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_HQ_Wifi_User-10_10_10_0_23" {
  vsys        = var.panos_vsys
  name        = "HQ_Wifi_User-10.10.10.0_23"
  value       = "10.10.10.0/23"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_ICT_HQ_192_168_111_0_24" {
  vsys        = var.panos_vsys
  name        = "ICT_HQ_192.168.111.0_24"
  value       = "192.168.111.0/24"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_DOSSB_KSB-192_168_4_0_24" {
  vsys        = var.panos_vsys
  name        = "DOSSB_KSB-192.168.4.0_24"
  value       = "192.168.4.0/24"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_DOSSB_KK-192_168_13_0_24" {
  vsys        = var.panos_vsys
  name        = "DOSSB_KK-192.168.13.0_24"
  value       = "192.168.13.0/24"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_DOSSB_Labuan-192_168_2_0_24" {
  vsys        = var.panos_vsys
  name        = "DOSSB_Labuan-192.168.2.0_24"
  value       = "192.168.2.0/24"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_DOSSB_Labuan_Leased_Line-10_10_2_0_24" {
  vsys        = var.panos_vsys
  name        = "DOSSB_Labuan_Leased_Line-10.10.2.0_24"
  value       = "10.10.2.0/24"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_DOSSB_Miri-192_168_5_0_24" {
  vsys        = var.panos_vsys
  name        = "DOSSB_Miri-192.168.5.0_24"
  value       = "192.168.5.0/24"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_Miri_WS-192_168_8_0_24" {
  vsys        = var.panos_vsys
  name        = "Miri_WS-192.168.8.0_24"
  value       = "192.168.8.0/24"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_SSL_VPN_HQ" {
  vsys        = var.panos_vsys
  name        = "SSL_VPN_HQ"
  value       = "10.10.100.0/24"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_Server-192_168_42_0_24" {
  vsys        = var.panos_vsys
  name        = "Server-192.168.42.0_24"
  value       = "192.168.42.0/24"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_Trust-192_168_0_0_23" {
  vsys        = var.panos_vsys
  name        = "Trust-192.168.0.0_23"
  value       = "192.168.0.0/23"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_SSL_VPN_HQ_new" {
  vsys        = var.panos_vsys
  name        = "SSL_VPN_HQ_new"
  value       = "10.10.100.0/24"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_FAZ200F_192_168_30_2" {
  vsys        = var.panos_vsys
  name        = "FAZ200F_192.168.30.2"
  value       = "192.168.30.2/32"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_DOSSB_Labuan_wifi_10_10_22_0_24" {
  vsys        = var.panos_vsys
  name        = "DOSSB_Labuan_wifi_10.10.22.0_24"
  value       = "10.10.22.0/24"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_trust_fixed_IP" {
  vsys        = var.panos_vsys
  name        = "trust_fixed_IP"
  value       = "192.168.0.1-192.168.0.100"
  type        = "ip-range"
}

resource "panos_address_object" "addr_DBATT_192_168_10_7" {
  vsys        = var.panos_vsys
  name        = "DBATT_192.168.10.7"
  value       = "192.168.10.7/32"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_pulse_new_172_16_0_0_24" {
  vsys        = var.panos_vsys
  name        = "pulse_new_172.16.0.0_24"
  value       = "172.16.0.0/24"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_trust_dhcp" {
  vsys        = var.panos_vsys
  name        = "trust_dhcp"
  value       = "192.168.0.101-192.168.1.250"
  type        = "ip-range"
}

# SKIPPED Address 'toDOSSB_KSB_local_subnet_1' due to parse error: 1 validation error for IRAddress
  Value error, Address toDOSSB_KSB_local_subnet_1 of type AddressType.NETWORK must have 'subnet' defined. [type=value_error, input_value={'name': 'toDOSSB_KSB_loc...t': False, 'subnet': ''}, input_type=dict]
    For further information visit https://errors.pydantic.dev/2.13/v/value_error
# Raw value: 

# SKIPPED Address 'toDOSSB_KSB_remote_subnet_1' due to parse error: 1 validation error for IRAddress
  Value error, Address toDOSSB_KSB_remote_subnet_1 of type AddressType.NETWORK must have 'subnet' defined. [type=value_error, input_value={'name': 'toDOSSB_KSB_rem...t': False, 'subnet': ''}, input_type=dict]
    For further information visit https://errors.pydantic.dev/2.13/v/value_error
# Raw value: 

resource "panos_address_object" "addr_s2b_standardchartered_com" {
  vsys        = var.panos_vsys
  name        = "s2b.standardchartered.com"
  value       = "s2b.standardchartered.com"
  type        = "fqdn"
}

resource "panos_address_object" "addr_mrates_maybank_com_my" {
  vsys        = var.panos_vsys
  name        = "mrates.maybank.com.my"
  value       = "mrates.maybank.com.my"
  type        = "fqdn"
}

resource "panos_address_object" "addr_hsbcnet_com" {
  vsys        = var.panos_vsys
  name        = "hsbcnet.com"
  value       = "hsbcnet.com"
  type        = "fqdn"
}

resource "panos_address_object" "addr_server_192_168_42_17" {
  vsys        = var.panos_vsys
  name        = "server_192.168.42.17"
  value       = "192.168.42.17/32"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_server_192_168_42_18" {
  vsys        = var.panos_vsys
  name        = "server_192.168.42.18"
  value       = "192.168.42.18/32"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_server_192_168_42_19" {
  vsys        = var.panos_vsys
  name        = "server_192.168.42.19"
  value       = "192.168.42.19/32"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_croudstrike1" {
  vsys        = var.panos_vsys
  name        = "croudstrike1"
  value       = "ts01-gyr-maverick.cloudsink.net"
  type        = "fqdn"
}

resource "panos_address_object" "addr_croudstrike2" {
  vsys        = var.panos_vsys
  name        = "croudstrike2"
  value       = "lfodown01-gyr-maverick.cloudsink.net"
  type        = "fqdn"
}

resource "panos_address_object" "addr_server_192_168_42_12" {
  vsys        = var.panos_vsys
  name        = "server_192.168.42.12"
  value       = "192.168.42.12/32"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_server_192_168_42_9" {
  vsys        = var.panos_vsys
  name        = "server_192.168.42.9"
  value       = "192.168.42.17/32"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_Bintulu1_192_168_11_0_24" {
  vsys        = var.panos_vsys
  name        = "Bintulu1_192.168.11.0_24"
  value       = "192.168.11.0/24"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_miniOrange_52_55_147_107" {
  vsys        = var.panos_vsys
  name        = "miniOrange_52.55.147.107"
  value       = "52.55.147.107/32"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_miniOrange_52_86_38_163" {
  vsys        = var.panos_vsys
  name        = "miniOrange_52.86.38.163"
  value       = "52.86.38.163/32"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_miniOrange_54_165_245_227" {
  vsys        = var.panos_vsys
  name        = "miniOrange_54.165.245.227"
  value       = "54.165.245.227/32"
  type        = "ip-netmask"
}

resource "panos_address_object" "addr_CCTVnvr_192_168_10_8" {
  vsys        = var.panos_vsys
  name        = "CCTVnvr_192.168.10.8"
  value       = "192.168.10.8/32"
  type        = "ip-netmask"
}

# ------------------------------------------------------------------------------
# 2. Address Groups
# ------------------------------------------------------------------------------

resource "panos_address_group" "grp_Branches_LAN" {
  vsys           = var.panos_vsys
  name           = "Branches_LAN"
  static_entries = [
    panos_address_object.addr_DOSSB_KK-192_168_13_0_24.name,
    panos_address_object.addr_DOSSB_Labuan-192_168_2_0_24.name,
    panos_address_object.addr_DOSSB_Miri-192_168_5_0_24.name,
    panos_address_object.addr_DPSB_Miri-192_168_9_0_24.name,
    panos_address_object.addr_DPSB_TK_new_192_168_7_0_24.name,
    panos_address_object.addr_Miri_WS-192_168_8_0_24.name
  ]
  depends_on = [
    panos_address_object.addr_DOSSB_KK-192_168_13_0_24,
    panos_address_object.addr_DOSSB_Labuan-192_168_2_0_24,
    panos_address_object.addr_DOSSB_Miri-192_168_5_0_24,
    panos_address_object.addr_DPSB_Miri-192_168_9_0_24,
    panos_address_object.addr_DPSB_TK_new_192_168_7_0_24,
    panos_address_object.addr_Miri_WS-192_168_8_0_24
  ]
}

resource "panos_address_group" "grp_banking" {
  vsys           = var.panos_vsys
  name           = "banking"
  static_entries = [
    panos_address_object.addr_s2b_standardchartered_com.name,
    panos_address_object.addr_hsbcnet_com.name,
    panos_address_object.addr_mrates_maybank_com_my.name
  ]
  depends_on = [
    panos_address_object.addr_s2b_standardchartered_com,
    panos_address_object.addr_hsbcnet_com,
    panos_address_object.addr_mrates_maybank_com_my
  ]
}

resource "panos_address_group" "grp_server_no_internet" {
  vsys           = var.panos_vsys
  name           = "server_no_internet"
  static_entries = [
    panos_address_object.addr_server_192_168_42_17.name,
    panos_address_object.addr_server_192_168_42_19.name,
    panos_address_object.addr_server_192_168_42_18.name,
    panos_address_object.addr_server_192_168_42_9.name,
    panos_address_object.addr_server_192_168_42_12.name
  ]
  depends_on = [
    panos_address_object.addr_server_192_168_42_17,
    panos_address_object.addr_server_192_168_42_19,
    panos_address_object.addr_server_192_168_42_18,
    panos_address_object.addr_server_192_168_42_9,
    panos_address_object.addr_server_192_168_42_12
  ]
}

resource "panos_address_group" "grp_miniOrange_Cloud" {
  vsys           = var.panos_vsys
  name           = "miniOrange_Cloud"
  static_entries = [
    panos_address_object.addr_miniOrange_52_55_147_107.name,
    panos_address_object.addr_miniOrange_52_86_38_163.name,
    panos_address_object.addr_miniOrange_54_165_245_227.name
  ]
  depends_on = [
    panos_address_object.addr_miniOrange_52_55_147_107,
    panos_address_object.addr_miniOrange_52_86_38_163,
    panos_address_object.addr_miniOrange_54_165_245_227
  ]
}

# ------------------------------------------------------------------------------
# 3. Service Objects
# ------------------------------------------------------------------------------

resource "panos_service_object" "svc_ALL" {
  vsys             = var.panos_vsys
  name             = "ALL"
  protocol         = "tcp"
  destination_port = "1-65535"
}

resource "panos_service_object" "svc_DNS" {
  vsys             = var.panos_vsys
  name             = "DNS"
  protocol         = "tcp"
  destination_port = "53"
}

resource "panos_service_object" "svc_DNS_udp" {
  vsys             = var.panos_vsys
  name             = "DNS_UDP"
  protocol         = "udp"
  destination_port = "53"
}

resource "panos_service_object" "svc_HTTP" {
  vsys             = var.panos_vsys
  name             = "HTTP"
  protocol         = "tcp"
  destination_port = "80"
}

resource "panos_service_object" "svc_HTTPS" {
  vsys             = var.panos_vsys
  name             = "HTTPS"
  protocol         = "tcp"
  destination_port = "443"
}

resource "panos_service_object" "svc_TRACEROUTE" {
  vsys             = var.panos_vsys
  name             = "TRACEROUTE"
  protocol         = "udp"
  destination_port = "33434-33535"
}

resource "panos_service_object" "svc_port_8081" {
  vsys             = var.panos_vsys
  name             = "port_8081"
  protocol         = "tcp"
  destination_port = "8081"
}

# ------------------------------------------------------------------------------
# 4. Service Groups
# ------------------------------------------------------------------------------

resource "panos_service_group" "sgrp_Web_Access" {
  vsys        = var.panos_vsys
  name        = "Web Access"
  services    = [
    panos_service_object.svc_DNS.name,
    panos_service_object.svc_HTTP.name,
    panos_service_object.svc_HTTPS.name
  ]
  depends_on = [
    panos_service_object.svc_DNS,
    panos_service_object.svc_HTTP,
    panos_service_object.svc_HTTPS
  ]
}

# ------------------------------------------------------------------------------
# 5. Security Zones
# ------------------------------------------------------------------------------

resource "panos_zone" "zone_untrust" {
  vsys        = var.panos_vsys
  name        = "untrust"
  mode        = "layer3"
  interfaces  = ["ha", "port1", "port3", "port7", "port12", "port13", "port14", "port15", "port16", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "port17", "port18", "port19", "port20", "modem", "naf.root", "l2t.root", "ssl.root", "toMiriWH", "to_CKJ_unifi", "to_DOSSB_Miri", "toDOSSB_KSB", "toIT_fromHQ", "toCKJ_secondary", "to_TKY", "toTKY_secondary", "toKSB_secondary", "MiriWHsecondary", "Miri_secondary", "toKK_secondary", "to_KK", "toLabuan", "toLabuan_second", "toIT_secondary", "maxis", "toMiri_DTS", "MiriDTS_second", "toBintulu1", "toBintulu2", "Bintulu1_second", "Bintulu2_second", "FortiClient"]
}

resource "panos_zone" "zone_trust" {
  vsys        = var.panos_vsys
  name        = "trust"
  mode        = "layer3"
  interfaces  = ["mgmt", "port5", "port6", "port8", "port9", "port11", "HQ_Vlan20", "HQ_Vlan70"]
}

resource "panos_zone" "zone_virtual-wan-link" {
  vsys        = var.panos_vsys
  name        = "virtual-wan-link"
  mode        = "layer3"
  interfaces  = ["port2", "port4", "unifi_port1", "unifi2_Vlan", "unifi3"]
}

resource "panos_zone" "zone_dmz" {
  vsys        = var.panos_vsys
  name        = "dmz"
  mode        = "layer3"
  interfaces  = ["port10"]
}

# ------------------------------------------------------------------------------
# 6. Static Routes
# ------------------------------------------------------------------------------

resource "panos_static_route_ipv4" "route_route_2" {
  name           = "route_2"
  destination    = "192.168.2.0/24"
  interface      = "HQ_Vlan20"
  nexthop        = "10.10.2.254"
  nexthop_type   = "ip-address"
  metric         = 5
}

resource "panos_static_route_ipv4" "route_route_4" {
  name           = "route_4"
  destination    = "0.0.0.0/0"
  nexthop_type   = "none"
  metric         = 1
}

resource "panos_static_route_ipv4" "route_route_6" {
  name           = "route_6"
  destination    = "192.168.7.0/24"
  interface      = "HQ_Vlan70"
  nexthop        = "10.10.7.254"
  nexthop_type   = "ip-address"
  metric         = 7
}

resource "panos_static_route_ipv4" "route_route_9" {
  name           = "route_9"
  destination    = "10.10.77.0/24"
  interface      = "HQ_Vlan70"
  nexthop        = "10.10.7.254"
  nexthop_type   = "ip-address"
  metric         = 7
}

resource "panos_static_route_ipv4" "route_route_23" {
  name           = "route_23"
  destination    = "192.168.8.0/24"
  interface      = "toMiriWH"
  nexthop_type   = "none"
  metric         = 5
}

resource "panos_static_route_ipv4" "route_route_26" {
  name           = "route_26"
  destination    = "192.168.43.0/24"
  interface      = "toIT_fromHQ"
  nexthop_type   = "none"
  metric         = 4
}

resource "panos_static_route_ipv4" "route_route_29" {
  name           = "route_29"
  destination    = "192.168.14.0/24"
  interface      = "to_CKJ_unifi"
  nexthop_type   = "none"
  metric         = 6
  description    = "VPN: to_CKJ_unifi (Created by VPN wizard)"
}

resource "panos_static_route_ipv4" "route_route_30" {
  name           = "route_30"
  destination    = "0.0.0.0/0"
  nexthop_type   = "none"
  metric         = 254
  description    = "VPN: to_CKJ_unifi (Created by VPN wizard)"
}

resource "panos_static_route_ipv4" "route_route_31" {
  name           = "route_31"
  destination    = "10.10.22.0/24"
  interface      = "HQ_Vlan20"
  nexthop        = "10.10.2.254"
  nexthop_type   = "ip-address"
  metric         = 5
}

resource "panos_static_route_ipv4" "route_route_32" {
  name           = "route_32"
  destination    = "192.168.5.0/24"
  interface      = "to_DOSSB_Miri"
  nexthop_type   = "none"
  metric         = 6
  description    = "VPN: to_DOSSB_Miri (Created by VPN wizard)"
}

resource "panos_static_route_ipv4" "route_route_33" {
  name           = "route_33"
  destination    = "0.0.0.0/0"
  nexthop_type   = "none"
  metric         = 254
  description    = "VPN: to_DOSSB_Miri (Created by VPN wizard)"
}

resource "panos_static_route_ipv4" "route_route_22" {
  name           = "route_22"
  destination    = "0.0.0.0/0"
  interface      = "port4"
  nexthop        = "103.27.106.129"
  nexthop_type   = "ip-address"
  metric         = 10
}

resource "panos_static_route_ipv4" "route_route_27" {
  name           = "route_27"
  destination    = "0.0.0.0/0"
  interface      = "toDOSSB_KSB"
  nexthop_type   = "none"
  metric         = 6
  description    = "VPN: toDOSSB_KSB (Created by VPN wizard)"
}

resource "panos_static_route_ipv4" "route_route_34" {
  name           = "route_34"
  destination    = "0.0.0.0/0"
  nexthop_type   = "none"
  metric         = 254
  description    = "VPN: toDOSSB_KSB (Created by VPN wizard)"
}

resource "panos_static_route_ipv4" "route_route_35" {
  name           = "route_35"
  destination    = "192.168.4.0/24"
  interface      = "toDOSSB_KSB"
  nexthop_type   = "none"
  metric         = 6
}

resource "panos_static_route_ipv4" "route_route_36" {
  name           = "route_36"
  destination    = "192.168.111.0/24"
  interface      = "toIT_fromHQ"
  nexthop_type   = "none"
  metric         = 4
}

resource "panos_static_route_ipv4" "route_route_37" {
  name           = "route_37"
  destination    = "192.168.14.0/24"
  interface      = "toCKJ_secondary"
  nexthop_type   = "none"
  metric         = 4
}

resource "panos_static_route_ipv4" "route_route_38" {
  name           = "route_38"
  destination    = "172.16.0.0/16"
  interface      = "port2"
  nexthop        = "172.16.1.1"
  nexthop_type   = "ip-address"
  metric         = 6
}

resource "panos_static_route_ipv4" "route_route_40" {
  name           = "route_40"
  destination    = "192.168.13.0/24"
  interface      = "to_KK"
  nexthop_type   = "none"
  metric         = 6
}

resource "panos_static_route_ipv4" "route_route_41" {
  name           = "route_41"
  destination    = "192.168.111.0/24"
  interface      = "port2"
  nexthop        = "172.16.1.1"
  nexthop_type   = "ip-address"
  metric         = 5
}

resource "panos_static_route_ipv4" "route_route_25" {
  name           = "route_25"
  destination    = "192.168.7.0/24"
  interface      = "to_TKY"
  nexthop_type   = "none"
  metric         = 6
}

resource "panos_static_route_ipv4" "route_route_28" {
  name           = "route_28"
  destination    = "192.168.7.0/24"
  interface      = "toTKY_secondary"
  nexthop_type   = "none"
  metric         = 4
}

resource "panos_static_route_ipv4" "route_route_24" {
  name           = "route_24"
  destination    = "192.168.4.0/24"
  interface      = "toKSB_secondary"
  nexthop_type   = "none"
  metric         = 4
}

resource "panos_static_route_ipv4" "route_route_39" {
  name           = "route_39"
  destination    = "192.168.8.0/24"
  interface      = "MiriWHsecondary"
  nexthop_type   = "none"
  metric         = 4
}

resource "panos_static_route_ipv4" "route_route_42" {
  name           = "route_42"
  destination    = "192.168.5.0/24"
  interface      = "Miri_secondary"
  nexthop_type   = "none"
  metric         = 4
}

resource "panos_static_route_ipv4" "route_route_43" {
  name           = "route_43"
  destination    = "192.168.13.0/24"
  interface      = "toKK_secondary"
  nexthop_type   = "none"
  metric         = 4
}

resource "panos_static_route_ipv4" "route_route_44" {
  name           = "route_44"
  destination    = "192.168.2.0/24"
  interface      = "toLabuan"
  nexthop_type   = "none"
  metric         = 6
}

resource "panos_static_route_ipv4" "route_route_45" {
  name           = "route_45"
  destination    = "192.168.2.0/24"
  interface      = "toLabuan_second"
  nexthop_type   = "none"
  metric         = 4
}

resource "panos_static_route_ipv4" "route_route_46" {
  name           = "route_46"
  destination    = "10.10.22.0/24"
  interface      = "toLabuan"
  nexthop_type   = "none"
  metric         = 6
}

resource "panos_static_route_ipv4" "route_route_47" {
  name           = "route_47"
  destination    = "10.10.22.0/24"
  interface      = "toLabuan_second"
  nexthop_type   = "none"
  metric         = 4
}

resource "panos_static_route_ipv4" "route_route_48" {
  name           = "route_48"
  destination    = "192.168.111.0/24"
  interface      = "toIT_secondary"
  nexthop_type   = "none"
  metric         = 6
}

resource "panos_static_route_ipv4" "route_route_49" {
  name           = "route_49"
  destination    = "0.0.0.0/0"
  interface      = "unifi2_Vlan"
  nexthop_type   = "none"
  metric         = 10
}

resource "panos_static_route_ipv4" "route_route_50" {
  name           = "route_50"
  destination    = "0.0.0.0/0"
  interface      = "unifi3"
  nexthop_type   = "none"
  metric         = 10
}

resource "panos_static_route_ipv4" "route_route_51" {
  name           = "route_51"
  destination    = "192.168.6.0/24"
  interface      = "toMiri_DTS"
  nexthop_type   = "none"
  metric         = 6
}

resource "panos_static_route_ipv4" "route_route_52" {
  name           = "route_52"
  destination    = "192.168.6.0/24"
  interface      = "MiriDTS_second"
  nexthop_type   = "none"
  metric         = 4
}

resource "panos_static_route_ipv4" "route_route_53" {
  name           = "route_53"
  destination    = "192.168.11.0/24"
  interface      = "toBintulu1"
  nexthop_type   = "none"
  metric         = 6
}

resource "panos_static_route_ipv4" "route_route_54" {
  name           = "route_54"
  destination    = "192.168.3.0/24"
  interface      = "toBintulu2"
  nexthop_type   = "none"
  metric         = 6
}

resource "panos_static_route_ipv4" "route_route_55" {
  name           = "route_55"
  destination    = "192.168.11.0/24"
  interface      = "Bintulu1_second"
  nexthop_type   = "none"
  metric         = 4
}

resource "panos_static_route_ipv4" "route_route_56" {
  name           = "route_56"
  destination    = "192.168.3.0/24"
  interface      = "Bintulu2_second"
  nexthop_type   = "none"
  metric         = 4
}

# ------------------------------------------------------------------------------
# 7. NAT Rules (panos_nat_rule_group)
# ------------------------------------------------------------------------------

resource "panos_nat_rule_group" "nat_rules" {
  vsys = var.panos_vsys

    rule {
      name                  = "unifi_60.53.219.65"
      source_zones          = ["any"]
      destination_zone      = "any"
      source_addresses      = ["any"]
      destination_addresses = ["any"]
      service               = "any"
      dynamic_ip_and_port {
        type = "translated-address"
        translated_address {
          translated_addresses = ["60.53.219.65"]
        }
      }
    }
  depends_on = [
    panos_zone.zone_untrust,
    panos_zone.zone_trust,
    panos_zone.zone_virtual-wan-link,
    panos_zone.zone_dmz
  ]
}

# ------------------------------------------------------------------------------
# 8. Security Policies (panos_security_rule_group)
# ------------------------------------------------------------------------------

resource "panos_security_rule_group" "security_rules" {
  vsys = var.panos_vsys

    rule {
      name                  = "unnamed"
      source_zones          = ["trust"]
      source_addresses      = ["DOSSB_Labuan_Leased_Line-10.10.2.0_24", "DOSSB_Labuan-192.168.2.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "252"
      source_zones          = ["untrust"]
      source_addresses      = ["DOSSB_Labuan-192.168.2.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "253"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_Labuan-192.168.2.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "258"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_Labuan-192.168.2.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "263"
      source_zones          = ["untrust"]
      source_addresses      = ["DOSSB_Labuan-192.168.2.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = " (Reverse of 258)"
    }

    rule {
      name                  = "255"
      source_zones          = ["trust"]
      source_addresses      = ["pulse_new_172.16.0.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_Labuan-192.168.2.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "259"
      source_zones          = ["trust"]
      source_addresses      = ["pulse_new_172.16.0.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_Labuan-192.168.2.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "264"
      source_zones          = ["untrust"]
      source_addresses      = ["DOSSB_Labuan-192.168.2.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["pulse_new_172.16.0.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = " (Reverse of 259)"
    }

    rule {
      name                  = "257"
      source_zones          = ["trust"]
      source_addresses      = ["Trust-192.168.0.0_23"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_Labuan-192.168.2.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "260"
      source_zones          = ["trust"]
      source_addresses      = ["Trust-192.168.0.0_23"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_Labuan-192.168.2.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "256"
      source_zones          = ["untrust"]
      source_addresses      = ["DOSSB_Labuan-192.168.2.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["pulse_new_172.16.0.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = " (Reverse of 255)"
    }

    rule {
      name                  = "254"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_Labuan-192.168.2.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "261"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_Labuan-192.168.2.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "9"
      source_zones          = ["trust"]
      source_addresses      = ["DOSSB_Labuan_Leased_Line-10.10.2.0_24", "DOSSB_Labuan-192.168.2.0_24", "DOSSB_Labuan_wifi_10.10.22.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["any"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["Migrated_Profiles"]
    }

    rule {
      name                  = "85"
      source_zones          = ["trust"]
      source_addresses      = ["FAZ200F_192.168.30.2"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Miri_WS-192.168.8.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
    }

    rule {
      name                  = "206"
      source_zones          = ["trust"]
      source_addresses      = ["FAZ200F_192.168.30.2"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Miri_WS-192.168.8.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      description           = "Clone of 85"
    }

    rule {
      name                  = "153"
      source_zones          = ["trust"]
      source_addresses      = ["FAZ200F_192.168.30.2"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KSB-192.168.4.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      description           = "Clone of 85"
    }

    rule {
      name                  = "163"
      source_zones          = ["untrust"]
      source_addresses      = ["DOSSB_KSB-192.168.4.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Reverse of 153"
    }

    rule {
      name                  = "170"
      source_zones          = ["trust"]
      source_addresses      = ["FAZ200F_192.168.30.2"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_CKJ_192.168.14.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      description           = "Clone of 87"
    }

    rule {
      name                  = "179"
      source_zones          = ["trust"]
      source_addresses      = ["FAZ200F_192.168.30.2"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KSB-192.168.4.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      description           = "Clone of 170"
    }

    rule {
      name                  = "204"
      source_zones          = ["untrust"]
      source_addresses      = ["DOSSB_KSB-192.168.4.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      description           = "Reverse of 179"
    }

    rule {
      name                  = "111"
      source_zones          = ["trust"]
      source_addresses      = ["FAZ200F_192.168.30.2"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_CKJ_192.168.14.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
    }

    rule {
      name                  = "187"
      source_zones          = ["trust"]
      source_addresses      = ["FAZ200F_192.168.30.2"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_TK_new_192.168.7.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      description           = "Clone of 111"
    }

    rule {
      name                  = "268"
      source_zones          = ["trust"]
      source_addresses      = ["FAZ200F_192.168.30.2"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Miri_DTS_192.168.6.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      description           = "Clone of 111 (Copy of 187) (Copy of )"
    }

    rule {
      name                  = "285"
      source_zones          = ["trust"]
      source_addresses      = ["FAZ200F_192.168.30.2"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Bintulu1_192.168.11.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "298"
      source_zones          = ["trust"]
      source_addresses      = ["FAZ200F_192.168.30.2"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Bintulu1_192.168.11.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "288"
      source_zones          = ["trust"]
      source_addresses      = ["FAZ200F_192.168.30.2"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Bintulu2-192.168.3.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = " (Copy of 285) (Copy of )"
    }

    rule {
      name                  = "302"
      source_zones          = ["trust"]
      source_addresses      = ["FAZ200F_192.168.30.2"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Bintulu2-192.168.3.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "286"
      source_zones          = ["untrust"]
      source_addresses      = ["Bintulu1_192.168.11.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = " (Reverse of 285)"
    }

    rule {
      name                  = "295"
      source_zones          = ["untrust"]
      source_addresses      = ["Bintulu1_192.168.11.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "292"
      source_zones          = ["untrust"]
      source_addresses      = ["Bintulu2-192.168.3.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "303"
      source_zones          = ["untrust"]
      source_addresses      = ["Bintulu2-192.168.3.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = " (Copy of 292) (Copy of )"
    }

    rule {
      name                  = "275"
      source_zones          = ["trust"]
      source_addresses      = ["FAZ200F_192.168.30.2"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Miri_DTS_192.168.6.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
    }

    rule {
      name                  = "273"
      source_zones          = ["untrust"]
      source_addresses      = ["Miri_DTS_192.168.6.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      description           = "Clone of 111 (Copy of 187) (Copy of ) (Reverse of 268)"
    }

    rule {
      name                  = "279"
      source_zones          = ["untrust"]
      source_addresses      = ["Miri_DTS_192.168.6.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
    }

    rule {
      name                  = "269"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Miri_DTS_192.168.6.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
    }

    rule {
      name                  = "282"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Bintulu1_192.168.11.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = " (Copy of 269) (Copy of )"
    }

    rule {
      name                  = "297"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Bintulu1_192.168.11.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = " "
    }

    rule {
      name                  = "291"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Bintulu2-192.168.3.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
    }

    rule {
      name                  = "305"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Bintulu2-192.168.3.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
    }

    rule {
      name                  = "281"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Miri_DTS_192.168.6.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = " (Copy of 269) (Copy of )"
    }

    rule {
      name                  = "270"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Miri_DTS_192.168.6.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
    }

    rule {
      name                  = "284"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Bintulu1_192.168.11.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "299"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Bintulu1_192.168.11.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "289"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Bintulu2-192.168.3.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "301"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Bintulu2-192.168.3.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "287"
      source_zones          = ["untrust"]
      source_addresses      = ["Bintulu1_192.168.11.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = " (Reverse of 284)"
    }

    rule {
      name                  = "296"
      source_zones          = ["untrust"]
      source_addresses      = ["Bintulu1_192.168.11.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "293"
      source_zones          = ["untrust"]
      source_addresses      = ["Bintulu2-192.168.3.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = " "
    }

    rule {
      name                  = "304"
      source_zones          = ["untrust"]
      source_addresses      = ["Bintulu2-192.168.3.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "  (Copy of 293) (Copy of )"
    }

    rule {
      name                  = "277"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Miri_DTS_192.168.6.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
    }

    rule {
      name                  = "274"
      source_zones          = ["untrust"]
      source_addresses      = ["Miri_DTS_192.168.6.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = " (Reverse of 270)"
    }

    rule {
      name                  = "280"
      source_zones          = ["untrust"]
      source_addresses      = ["Miri_DTS_192.168.6.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
    }

    rule {
      name                  = "199"
      source_zones          = ["untrust"]
      source_addresses      = ["DPSB_TK_new_192.168.7.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      description           = "Reverse of 187"
    }

    rule {
      name                  = "189"
      source_zones          = ["trust"]
      source_addresses      = ["FAZ200F_192.168.30.2"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_TK_new_192.168.7.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      description           = "Clone of 187"
    }

    rule {
      name                  = "221"
      source_zones          = ["trust"]
      source_addresses      = ["FAZ200F_192.168.30.2"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KK-192.168.13.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      description           = "Clone of 189"
    }

    rule {
      name                  = "250"
      source_zones          = ["trust"]
      source_addresses      = ["FAZ200F_192.168.30.2"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_Labuan-192.168.2.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
    }

    rule {
      name                  = "262"
      source_zones          = ["trust"]
      source_addresses      = ["FAZ200F_192.168.30.2"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_Labuan-192.168.2.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
    }

    rule {
      name                  = "265"
      source_zones          = ["untrust"]
      source_addresses      = ["DOSSB_Labuan-192.168.2.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      description           = " (Reverse of 262)"
    }

    rule {
      name                  = "251"
      source_zones          = ["untrust"]
      source_addresses      = ["DOSSB_Labuan-192.168.2.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      description           = " (Reverse of 250)"
    }

    rule {
      name                  = "223"
      source_zones          = ["untrust"]
      source_addresses      = ["DOSSB_KK-192.168.13.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      description           = "Reverse of 221"
    }

    rule {
      name                  = "220"
      source_zones          = ["trust"]
      source_addresses      = ["FAZ200F_192.168.30.2"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KK-192.168.13.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      description           = "Clone of 189"
    }

    rule {
      name                  = "222"
      source_zones          = ["untrust"]
      source_addresses      = ["DOSSB_KK-192.168.13.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      description           = "Reverse of 220"
    }

    rule {
      name                  = "200"
      source_zones          = ["untrust"]
      source_addresses      = ["DPSB_TK_new_192.168.7.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
      description           = "Reverse of 189"
    }

    rule {
      name                  = "95"
      source_zones          = ["trust"]
      source_addresses      = ["FAZ200F_192.168.30.2"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["DOSSB_Labuan-192.168.2.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = false
    }

    rule {
      name                  = "96"
      source_zones          = ["trust"]
      source_addresses      = ["DOSSB_Labuan-192.168.2.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Reverse of 95"
    }

    rule {
      name                  = "177"
      source_zones          = ["untrust"]
      source_addresses      = ["DPSB_CKJ_192.168.14.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 88"
    }

    rule {
      name                  = "117"
      source_zones          = ["untrust"]
      source_addresses      = ["DOSSB_Miri-192.168.5.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 88"
    }

    rule {
      name                  = "215"
      source_zones          = ["untrust"]
      source_addresses      = ["DOSSB_Miri-192.168.5.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 117"
    }

    rule {
      name                  = "107"
      source_zones          = ["untrust"]
      source_addresses      = ["DPSB_CKJ_192.168.14.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
    }

    rule {
      name                  = "86"
      source_zones          = ["untrust"]
      source_addresses      = ["Miri_WS-192.168.8.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Reverse of 85"
    }

    rule {
      name                  = "209"
      source_zones          = ["untrust"]
      source_addresses      = ["Miri_WS-192.168.8.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 86"
    }

    rule {
      name                  = "4"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["DOSSB_Labuan_Leased_Line-10.10.2.0_24", "DOSSB_Labuan-192.168.2.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Reverse of ,"
    }

    rule {
      name                  = "17"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Branches_LAN"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
    }

    rule {
      name                  = "128"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 23"
    }

    rule {
      name                  = "23"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio"]
      description           = "Reverse of 22"
    }

    rule {
      name                  = "127"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Branches_LAN"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 32"
    }

    rule {
      name                  = "186"
      source_zones          = ["trust"]
      source_addresses      = ["Trust-192.168.0.0_23"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["banking"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_WF_deleum_webfilter_APP_deleum_application_control"]
      description           = " (Copy of 32) (Copy of )"
    }

    rule {
      name                  = "32"
      source_zones          = ["trust"]
      source_addresses      = ["Trust-192.168.0.0_23"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["banking"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
    }

    rule {
      name                  = "to_MicrosoftTeams"
      source_zones          = ["trust"]
      source_addresses      = ["Trust-192.168.0.0_23"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["any"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 137"
    }

    rule {
      name                  = "137"
      source_zones          = ["trust"]
      source_addresses      = ["trust_fixed_IP"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["any"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_APP_deleum_application_control"]
      description           = "Clone of FSSO policy"
    }

    rule {
      name                  = "FSSO policy"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["any"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_WF_deleum_webfilter_APP_deleum_application_control"]
    }

    rule {
      name                  = "33"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["any"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio"]
    }

    rule {
      name                  = "to_MicrosoftTeams_from_wifi"
      source_zones          = ["trust"]
      source_addresses      = ["HQ_Wifi_User-10.10.10.0_23"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["any"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of to_MicrosoftTeams"
    }

    rule {
      name                  = "quic allowed"
      source_zones          = ["trust"]
      source_addresses      = ["any"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["any"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_WF_wifi__deleum_webfilter_APP_deleum_application_control_fo"]
    }

    rule {
      name                  = "39"
      source_zones          = ["trust"]
      source_addresses      = ["HQ_Wifi_User-10.10.10.0_23"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["any"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_WF_wifi__deleum_webfilter_APP_deleum_application_control"]
    }

    rule {
      name                  = "147"
      source_zones          = ["trust"]
      source_addresses      = ["pulse_new_172.16.0.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio"]
    }

    rule {
      name                  = "151"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["pulse_new_172.16.0.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Reverse of 147"
    }

    rule {
      name                  = "148"
      source_zones          = ["trust"]
      source_addresses      = ["pulse_new_172.16.0.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["Trust-192.168.0.0_23"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 147"
    }

    rule {
      name                  = "152"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["pulse_new_172.16.0.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 126"
    }

    rule {
      name                  = "150"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["pulse_new_172.16.0.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = "Reverse of 148"
    }

    rule {
      name                  = "154"
      source_zones          = ["trust"]
      source_addresses      = ["pulse_new_172.16.0.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["DBATT_192.168.10.7"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 144"
    }

    rule {
      name                  = "160"
      source_zones          = ["trust"]
      source_addresses      = ["pulse_new_172.16.0.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["DOSSB_Labuan-192.168.2.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 142"
    }

    rule {
      name                  = "174"
      source_zones          = ["trust"]
      source_addresses      = ["DOSSB_Labuan-192.168.2.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["pulse_new_172.16.0.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_default"]
      description           = "Reverse of 160"
    }

    rule {
      name                  = "155"
      source_zones          = ["trust"]
      source_addresses      = ["pulse_new_172.16.0.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Branches_LAN"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 45"
    }

    rule {
      name                  = "157"
      source_zones          = ["untrust"]
      source_addresses      = ["Branches_LAN"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["pulse_new_172.16.0.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_default"]
      description           = "Reverse of 155"
    }

    rule {
      name                  = "156"
      source_zones          = ["trust"]
      source_addresses      = ["pulse_new_172.16.0.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["any"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_WF_deleum_webfilter_APP_deleum_application_control"]
      description           = "Clone of 46"
    }

    rule {
      name                  = "172"
      source_zones          = ["trust"]
      source_addresses      = ["pulse_new_172.16.0.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_CKJ_192.168.14.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 161"
    }

    rule {
      name                  = "161"
      source_zones          = ["trust"]
      source_addresses      = ["pulse_new_172.16.0.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KSB-192.168.4.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 172"
    }

    rule {
      name                  = "180"
      source_zones          = ["untrust"]
      source_addresses      = ["DPSB_CKJ_192.168.14.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["pulse_new_172.16.0.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 179"
    }

    rule {
      name                  = "162"
      source_zones          = ["trust"]
      source_addresses      = ["pulse_new_172.16.0.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_CKJ_192.168.14.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 109"
    }

    rule {
      name                  = "188"
      source_zones          = ["trust"]
      source_addresses      = ["pulse_new_172.16.0.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_TK_new_192.168.7.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 162"
    }

    rule {
      name                  = "272"
      source_zones          = ["trust"]
      source_addresses      = ["pulse_new_172.16.0.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Miri_DTS_192.168.6.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "276"
      source_zones          = ["trust"]
      source_addresses      = ["pulse_new_172.16.0.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Miri_DTS_192.168.6.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "190"
      source_zones          = ["trust"]
      source_addresses      = ["pulse_new_172.16.0.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_TK_new_192.168.7.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 188"
    }

    rule {
      name                  = "178"
      source_zones          = ["untrust"]
      source_addresses      = ["DPSB_CKJ_192.168.14.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["pulse_new_172.16.0.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Reverse of 162"
    }

    rule {
      name                  = "164"
      source_zones          = ["trust"]
      source_addresses      = ["pulse_new_172.16.0.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_Miri-192.168.5.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 143"
    }

    rule {
      name                  = "171"
      source_zones          = ["untrust"]
      source_addresses      = ["DOSSB_Miri-192.168.5.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["pulse_new_172.16.0.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Reverse of 164"
    }

    rule {
      name                  = "216"
      source_zones          = ["untrust"]
      source_addresses      = ["DOSSB_Miri-192.168.5.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["pulse_new_172.16.0.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 171"
    }

    rule {
      name                  = "224"
      source_zones          = ["untrust"]
      source_addresses      = ["DOSSB_KK-192.168.13.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["pulse_new_172.16.0.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 216"
    }

    rule {
      name                  = "226"
      source_zones          = ["trust"]
      source_addresses      = ["pulse_new_172.16.0.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KK-192.168.13.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Reverse of 224"
    }

    rule {
      name                  = "225"
      source_zones          = ["untrust"]
      source_addresses      = ["DOSSB_KK-192.168.13.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["pulse_new_172.16.0.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 224"
    }

    rule {
      name                  = "227"
      source_zones          = ["trust"]
      source_addresses      = ["pulse_new_172.16.0.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KK-192.168.13.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Reverse of 225"
    }

    rule {
      name                  = "173"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_CKJ_192.168.14.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 51"
    }

    rule {
      name                  = "201"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KSB-192.168.4.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 173"
    }

    rule {
      name                  = "205"
      source_zones          = ["untrust"]
      source_addresses      = ["DOSSB_KSB-192.168.4.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio"]
      description           = "Reverse of 201"
    }

    rule {
      name                  = "230"
      source_zones          = ["untrust"]
      source_addresses      = ["DOSSB_KK-192.168.13.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 205"
    }

    rule {
      name                  = "231"
      source_zones          = ["untrust"]
      source_addresses      = ["DOSSB_KK-192.168.13.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 230"
    }

    rule {
      name                  = "176"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_CKJ_192.168.14.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 129"
    }

    rule {
      name                  = "242"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_CKJ_192.168.14.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 129 (Copy of 176)"
    }

    rule {
      name                  = "203"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KSB-192.168.4.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 176"
    }

    rule {
      name                  = "245"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KSB-192.168.4.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 176 (Copy of 203)"
    }

    rule {
      name                  = "131"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_CKJ_192.168.14.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 110"
    }

    rule {
      name                  = "241"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_CKJ_192.168.14.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 110 (Copy of 131)"
    }

    rule {
      name                  = "240"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_TK_new_192.168.7.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 131 (Copy of 195)"
    }

    rule {
      name                  = "195"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_TK_new_192.168.7.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 131"
    }

    rule {
      name                  = "196"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_TK_new_192.168.7.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 195"
    }

    rule {
      name                  = "246"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_TK_new_192.168.7.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 195 (Copy of 196)"
    }

    rule {
      name                  = "167"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ_new"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["ICT_HQ_192.168.111.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 131"
    }

    rule {
      name                  = "236"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ_new"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["ICT_HQ_192.168.111.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
    }

    rule {
      name                  = "169"
      source_zones          = ["untrust"]
      source_addresses      = ["ICT_HQ_192.168.111.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["Trust-192.168.0.0_23"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = "Reverse of 167"
    }

    rule {
      name                  = "133"
      source_zones          = ["untrust"]
      source_addresses      = ["ICT_HQ_192.168.111.0_24", "DR-192.168.43.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 169"
    }

    rule {
      name                  = "247"
      source_zones          = ["untrust"]
      source_addresses      = ["ICT_HQ_192.168.111.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 169 (Copy of 133)"
    }

    rule {
      name                  = "248"
      source_zones          = ["trust"]
      source_addresses      = ["FAZ200F_192.168.30.2"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["ICT_HQ_192.168.111.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 169 (Copy of 133) (Copy of 247) (Reverse of 247)"
    }

    rule {
      name                  = "165"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DR-192.168.43.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = "Reverse of 133"
    }

    rule {
      name                  = "184"
      source_zones          = ["trust"]
      source_addresses      = ["Trust-192.168.0.0_23"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DR-192.168.43.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 165"
    }

    rule {
      name                  = "182"
      source_zones          = ["untrust"]
      source_addresses      = ["DPSB_CKJ_192.168.14.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default_WF_deleum_webfilter_APP_deleum_application_cont"]
      description           = "Clone of 52"
    }

    rule {
      name                  = "82"
      source_zones          = ["untrust"]
      source_addresses      = ["Miri_WS-192.168.8.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "211"
      source_zones          = ["untrust"]
      source_addresses      = ["Miri_WS-192.168.8.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 82"
    }

    rule {
      name                  = "168"
      source_zones          = ["untrust"]
      source_addresses      = ["Miri_WS-192.168.8.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["pulse_new_172.16.0.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "210"
      source_zones          = ["untrust"]
      source_addresses      = ["Miri_WS-192.168.8.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["pulse_new_172.16.0.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 168"
    }

    rule {
      name                  = "83"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Miri_WS-192.168.8.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Reverse of 82"
    }

    rule {
      name                  = "207"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Miri_WS-192.168.8.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 83"
    }

    rule {
      name                  = "134"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Miri_WS-192.168.8.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 112"
    }

    rule {
      name                  = "112"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Miri_WS-192.168.8.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = true
      group                 = ["SPG_IPS_high_security"]
    }

    rule {
      name                  = "238"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Miri_WS-192.168.8.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 112 (Copy of 212)"
    }

    rule {
      name                  = "212"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Miri_WS-192.168.8.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = true
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 112"
    }

    rule {
      name                  = "232"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KK-192.168.13.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 212"
    }

    rule {
      name                  = "244"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KK-192.168.13.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = true
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 212 (Copy of 232)"
    }

    rule {
      name                  = "239"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KK-192.168.13.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 232 (Copy of 233)"
    }

    rule {
      name                  = "233"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KK-192.168.13.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = true
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 232"
    }

    rule {
      name                  = "20"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["Biometric-192.168.10.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
    }

    rule {
      name                  = "135"
      source_zones          = ["trust"]
      source_addresses      = ["Biometric-192.168.10.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 25"
    }

    rule {
      name                  = "25"
      source_zones          = ["trust"]
      source_addresses      = ["Biometric-192.168.10.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_AV_default_IPS_high_security_WF_deleum_webfilter_APP_deleum"]
      description           = "Reverse of 20"
    }

    rule {
      name                  = "136"
      source_zones          = ["trust"]
      source_addresses      = ["Biometric-192.168.10.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["Trust-192.168.0.0_23"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 26"
    }

    rule {
      name                  = "26"
      source_zones          = ["trust"]
      source_addresses      = ["Biometric-192.168.10.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["Trust-192.168.0.0_23"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "21"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["HQ_Wifi_User-10.10.10.0_23"]
      applications          = ["any"]
      services              = ["PING", "TRACEROUTE"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_AV_default_IPS_high_security_WF_deleum_webfilter_APP_deleum"]
    }

    rule {
      name                  = "22"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["Trust-192.168.0.0_23"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "138"
      source_zones          = ["trust"]
      source_addresses      = ["trust_fixed_IP"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 23"
    }

    rule {
      name                  = "119"
      source_zones          = ["trust"]
      source_addresses      = ["Trust-192.168.0.0_23"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["Biometric-192.168.10.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 34"
    }

    rule {
      name                  = "34"
      source_zones          = ["trust"]
      source_addresses      = ["Trust-192.168.0.0_23"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["Biometric-192.168.10.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio"]
    }

    rule {
      name                  = "267"
      source_zones          = ["dmz"]
      source_addresses      = ["server_no_internet"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["croudstrike1", "croudstrike2"]
      applications          = ["any"]
      services              = ["HTTPS"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = " (Copy of 185) (Copy of )"
    }

    rule {
      name                  = "185"
      source_zones          = ["dmz"]
      source_addresses      = ["server_no_internet"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["any"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "deny"
      log_end               = true
      disabled              = true
    }

    rule {
      name                  = "18"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["any"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_high_security"]
    }

    rule {
      name                  = "124"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["DOSSB_Labuan_Leased_Line-10.10.2.0_24", "DOSSB_Labuan-192.168.2.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 27"
    }

    rule {
      name                  = "149"
      source_zones          = ["untrust"]
      source_addresses      = ["any"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["any"]
      applications          = ["any"]
      services              = ["HTTPS"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_high_security_APP_deleum_application_control"]
      description           = "Clone of 37"
    }

    rule {
      name                  = "MiniOrange_LDAPgw"
      source_zones          = ["untrust"]
      source_addresses      = ["miniOrange_Cloud"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["any"]
      applications          = ["any"]
      services              = ["HTTPS", "port_8081"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "36"
      source_zones          = ["untrust"]
      source_addresses      = ["any"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["any"]
      applications          = ["any"]
      services              = ["Web Access"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_high_security_APP_deleum_application_control"]
    }

    rule {
      name                  = "61"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "64"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["DOSSB_Labuan_Leased_Line-10.10.2.0_24", "DOSSB_Labuan-192.168.2.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
    }

    rule {
      name                  = "175"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_CKJ_192.168.14.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 69"
    }

    rule {
      name                  = "234"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KK-192.168.13.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 175"
    }

    rule {
      name                  = "235"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KK-192.168.13.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 234"
    }

    rule {
      name                  = "202"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KSB-192.168.4.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 175"
    }

    rule {
      name                  = "108"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_CKJ_192.168.14.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
    }

    rule {
      name                  = "193"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_TK_new_192.168.7.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 108"
    }

    rule {
      name                  = "271"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Miri_DTS_192.168.6.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
    }

    rule {
      name                  = "283"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Bintulu1_192.168.11.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "294"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Bintulu1_192.168.11.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "290"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Bintulu2-192.168.3.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["Migrated_Profiles"]
    }

    rule {
      name                  = "300"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Bintulu2-192.168.3.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["Migrated_Profiles"]
      description           = " (Copy of 290) (Copy of )"
    }

    rule {
      name                  = "278"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Miri_DTS_192.168.6.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
    }

    rule {
      name                  = "194"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_TK_new_192.168.7.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 193"
    }

    rule {
      name                  = "118"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_Miri-192.168.5.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 70"
    }

    rule {
      name                  = "214"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_Miri-192.168.5.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 118"
    }

    rule {
      name                  = "84"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Miri_WS-192.168.8.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
    }

    rule {
      name                  = "208"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["Miri_WS-192.168.8.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 84"
    }

    rule {
      name                  = "62"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["Trust-192.168.0.0_23"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "145"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["pulse_new_172.16.0.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 62"
    }

    rule {
      name                  = "144"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KSB-192.168.4.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 74"
    }

    rule {
      name                  = "63"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["any"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
    }

    rule {
      name                  = "75"
      source_zones          = ["untrust"]
      source_addresses      = ["SSL_VPN_HQ"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
    }

    rule {
      name                  = "78"
      source_zones          = ["trust"]
      source_addresses      = ["HQ_Wifi_User-10.10.10.0_23"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_high_security"]
    }

    rule {
      name                  = "123"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 76"
    }

    rule {
      name                  = "76"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "77"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["trust"]
      destination_addresses = ["FAZ200F_192.168.30.2"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
    }

    rule {
      name                  = "79"
      source_zones          = ["trust"]
      source_addresses      = ["FAZ200F_192.168.30.2"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["any"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_IPS_high_security_WF_deleum_webfilter_APP_deleum_applicatio"]
    }

    rule {
      name                  = "vpn_to_CKJ_unifi_local"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_CKJ_192.168.14.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "VPN: to_CKJ_unifi (Created by VPN wizard)"
    }

    rule {
      name                  = "191"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_TK_new_192.168.7.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of vpn_to_CKJ_unifi_local"
    }

    rule {
      name                  = "198"
      source_zones          = ["untrust"]
      source_addresses      = ["DPSB_TK_new_192.168.7.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Reverse of 191"
    }

    rule {
      name                  = "192"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DPSB_TK_new_192.168.7.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 191"
    }

    rule {
      name                  = "197"
      source_zones          = ["untrust"]
      source_addresses      = ["DPSB_TK_new_192.168.7.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Reverse of 192"
    }

    rule {
      name                  = "vpn_to_CKJ_unifi_remote"
      source_zones          = ["untrust"]
      source_addresses      = ["DPSB_CKJ_192.168.14.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "VPN: to_CKJ_unifi (Created by VPN wizard)"
    }

    rule {
      name                  = "141"
      source_zones          = ["untrust"]
      source_addresses      = ["DOSSB_KSB-192.168.4.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of vpn_to_CKJ_unifi_remote"
    }

    rule {
      name                  = "142"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KSB-192.168.4.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Reverse of 141"
    }

    rule {
      name                  = "146"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KSB-192.168.4.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 142"
    }

    rule {
      name                  = "243"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KSB-192.168.4.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 142 (Copy of 146)"
    }

    rule {
      name                  = "143"
      source_zones          = ["trust"]
      source_addresses      = ["pulse_new_172.16.0.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KSB-192.168.4.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
      description           = "Clone of 142"
    }

    rule {
      name                  = "vpn_to_DOSSB_Miri_local"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_Miri-192.168.5.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "VPN: to_DOSSB_Miri (Created by VPN wizard)"
    }

    rule {
      name                  = "213"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_Miri-192.168.5.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of vpn_to_DOSSB_Miri_local"
    }

    rule {
      name                  = "228"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KK-192.168.13.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 213"
    }

    rule {
      name                  = "229"
      source_zones          = ["dmz"]
      source_addresses      = ["Server-192.168.42.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_KK-192.168.13.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Clone of 228"
    }

    rule {
      name                  = "115"
      source_zones          = ["untrust"]
      source_addresses      = ["DOSSB_Miri-192.168.5.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      description           = "Reverse of vpn_to_DOSSB_Miri_local"
    }

    rule {
      name                  = "217"
      source_zones          = ["untrust"]
      source_addresses      = ["DOSSB_Miri-192.168.5.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["Server-192.168.42.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 115"
    }

    rule {
      name                  = "132"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_Miri-192.168.5.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 116"
    }

    rule {
      name                  = "116"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_Miri-192.168.5.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = true
      group                 = ["SPG_IPS_high_security"]
    }

    rule {
      name                  = "237"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_Miri-192.168.5.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 116 (Copy of 218)"
    }

    rule {
      name                  = "218"
      source_zones          = ["trust"]
      source_addresses      = ["trust_dhcp"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_Miri-192.168.5.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = false
      disabled              = true
      group                 = ["SPG_IPS_high_security"]
      description           = "Clone of 116"
    }

    rule {
      name                  = "vpn_toDOSSB_KSB_remote"
      source_zones          = ["untrust"]
      source_addresses      = ["any"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["any"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      description           = "VPN: toDOSSB_KSB (Created by VPN wizard)"
    }

    rule {
      name                  = "219"
      source_zones          = ["trust"]
      source_addresses      = ["pulse_new_172.16.0.0_24"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["DOSSB_Miri-192.168.5.0_24"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = false
      group                 = ["SPG_IPS_default"]
    }

    rule {
      name                  = "266"
      source_zones          = ["trust"]
      source_addresses      = ["DBATT_192.168.10.7", "CCTVnvr_192.168.10.8"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["any"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_AV_default_IPS_high_security_WF_deleum_webfilter_APP_deleum"]
    }

    rule {
      name                  = "FortiClient_IPSEC_Internet"
      source_zones          = ["untrust"]
      source_addresses      = ["any"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["untrust"]
      destination_addresses = ["any"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_WF_deleum_webfilter_APP_deleum_application_control"]
      description           = "VPN: Test_IPSEC_2 (Created by VPN wizard) (Copy of vpn_Test_IPSEC_2_remote_1) (Copy of )"
    }

    rule {
      name                  = "FortiClient_IPSEC_Deny"
      source_zones          = ["untrust"]
      source_addresses      = ["any"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["any"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "deny"
      log_end               = false
      disabled              = true
      description           = " (Copy of FortiClient_IPSEC) (Copy of )"
    }

    rule {
      name                  = "FortiClient_IPSEC"
      source_zones          = ["untrust"]
      source_addresses      = ["any"]
      source_users          = ["any"]
      hip_profiles          = ["any"]
      destination_zones     = ["dmz"]
      destination_addresses = ["any"]
      applications          = ["any"]
      services              = ["any"]
      categories            = ["any"]
      action                = "allow"
      log_end               = true
      disabled              = true
      group                 = ["SPG_AV_default_IPS_high_security_WF_deleum_webfilter_APP_deleum"]
    }
  depends_on = [
    panos_zone.zone_untrust,
    panos_zone.zone_trust,
    panos_zone.zone_virtual-wan-link,
    panos_zone.zone_dmz,
    panos_address_object.addr_Biometric-192_168_10_0_24,
    panos_address_object.addr_DPSB_CKJ_192_168_14_0_24,
    panos_address_object.addr_Miri_DTS_192_168_6_0_24,
    panos_address_object.addr_DPSB_Miri-192_168_9_0_24,
    panos_address_object.addr_DPSB_TK_new_192_168_7_0_24,
    panos_address_object.addr_DR-192_168_43_0_24,
    panos_address_object.addr_Bintulu2-192_168_3_0_24,
    panos_address_object.addr_HQ_Wifi_User-10_10_10_0_23,
    panos_address_object.addr_ICT_HQ_192_168_111_0_24,
    panos_address_object.addr_DOSSB_KSB-192_168_4_0_24,
    panos_address_object.addr_DOSSB_KK-192_168_13_0_24,
    panos_address_object.addr_DOSSB_Labuan-192_168_2_0_24,
    panos_address_object.addr_DOSSB_Labuan_Leased_Line-10_10_2_0_24,
    panos_address_object.addr_DOSSB_Miri-192_168_5_0_24,
    panos_address_object.addr_Miri_WS-192_168_8_0_24,
    panos_address_object.addr_SSL_VPN_HQ,
    panos_address_object.addr_Server-192_168_42_0_24,
    panos_address_object.addr_Trust-192_168_0_0_23,
    panos_address_object.addr_SSL_VPN_HQ_new,
    panos_address_object.addr_FAZ200F_192_168_30_2,
    panos_address_object.addr_DOSSB_Labuan_wifi_10_10_22_0_24,
    panos_address_object.addr_trust_fixed_IP,
    panos_address_object.addr_DBATT_192_168_10_7,
    panos_address_object.addr_pulse_new_172_16_0_0_24,
    panos_address_object.addr_trust_dhcp,
    panos_address_object.addr_s2b_standardchartered_com,
    panos_address_object.addr_mrates_maybank_com_my,
    panos_address_object.addr_hsbcnet_com,
    panos_address_object.addr_server_192_168_42_17,
    panos_address_object.addr_server_192_168_42_18,
    panos_address_object.addr_server_192_168_42_19,
    panos_address_object.addr_croudstrike1,
    panos_address_object.addr_croudstrike2,
    panos_address_object.addr_server_192_168_42_12,
    panos_address_object.addr_server_192_168_42_9,
    panos_address_object.addr_Bintulu1_192_168_11_0_24,
    panos_address_object.addr_miniOrange_52_55_147_107,
    panos_address_object.addr_miniOrange_52_86_38_163,
    panos_address_object.addr_miniOrange_54_165_245_227,
    panos_address_object.addr_CCTVnvr_192_168_10_8,
    panos_address_group.grp_Branches_LAN,
    panos_address_group.grp_banking,
    panos_address_group.grp_server_no_internet,
    panos_address_group.grp_miniOrange_Cloud,
    panos_service_object.svc_ALL,
    panos_service_object.svc_DNS,
    panos_service_object.svc_DNS_udp,
    panos_service_object.svc_HTTP,
    panos_service_object.svc_HTTPS,
    panos_service_object.svc_TRACEROUTE,
    panos_service_object.svc_port_8081,
    panos_service_group.sgrp_Web_Access
  ]
}
