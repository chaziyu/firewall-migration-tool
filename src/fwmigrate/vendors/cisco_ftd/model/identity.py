"""Vendor-native cisco_ftd identity models."""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from .base import CiscoFTDReference, CiscoFTDSourceRecord


class CiscoFTDGroupPolicy(CiscoFTDSourceRecord):
    vpn_access: Optional[Any] = None
    protocols: Optional[Any] = None
    connection_settings: Optional[Dict[str, Any]] = None
    dns_servers: Optional[List[Any]] = None
    wins_servers: Optional[List[Any]] = None
    domain_name: Optional[str] = None
    realm: Optional[CiscoFTDReference] = None
    aaa_server_group: Optional[CiscoFTDReference] = None
    address_pools: Optional[List[CiscoFTDReference]] = None
    split_tunnel: Optional[List[CiscoFTDReference]] = None
    split_tunnel_policy: Optional[Any] = None
    split_tunnel_networks: Optional[List[CiscoFTDReference]] = None
    split_dns: Optional[Any] = None
    split_tunnel_acl: Optional[CiscoFTDReference] = None
    secure_client: Optional[List[CiscoFTDReference]] = None
    session_settings: Optional[Dict[str, Any]] = None
    simultaneous_logins: Optional[int] = None


class CiscoFTDFMCUserRole(CiscoFTDSourceRecord):
    description: Optional[str] = None
    predefined: Optional[bool] = None
    custom: Optional[bool] = None
    menu_permissions: Optional[Any] = None
    system_permissions: Optional[Any] = None
    role_escalation: Optional[Any] = None
    other_permissions: Optional[Any] = None


class CiscoFTDFMCUser(CiscoFTDSourceRecord):
    username: Optional[str] = None
    enabled: Optional[bool] = None
    authentication_type: Optional[str] = None
    authentication_source: Optional[CiscoFTDReference] = None
    roles: Optional[List[CiscoFTDReference]] = None
    external_identity: Optional[Any] = None


class CiscoFTDDHCPServer(CiscoFTDSourceRecord):
    interface: Optional[CiscoFTDReference] = None


class CiscoFTDDHCPRelaySettings(CiscoFTDSourceRecord):
    relay_agents: Optional[List[Any]] = None
    relay_servers: Optional[List[Any]] = None
    ipv4_timeout_seconds: Optional[Any] = None
    ipv6_timeout_seconds: Optional[Any] = None
    trust_all_information: Optional[bool] = None


class CiscoFTDRealm(CiscoFTDSourceRecord):
    realm_type: Optional[str] = None
    enabled: Optional[bool] = None
    description: Optional[str] = None
    directory_configurations: Optional[List[Any]] = None
    base_dn: Optional[str] = None
    group_dn: Optional[str] = None
    group_attribute: Optional[str] = None
    ad_primary_domain: Optional[str] = None
    included_users: Optional[List[str]] = None
    excluded_users: Optional[List[str]] = None
    included_groups: Optional[List[str]] = None
    excluded_groups: Optional[List[str]] = None
    identity_provider: Optional[str] = None
    idp_settings: Optional[Dict[str, Any]] = None
    synchronization_settings: Optional[Dict[str, Any]] = None


class CiscoFTDRealmUserGroup(CiscoFTDSourceRecord):
    realm: Optional[CiscoFTDReference] = None
    external_id: Optional[str] = None
    distinguished_name: Optional[str] = None
    synchronized: Optional[bool] = None
    resolved: Optional[bool] = None
    for_policy: Optional[bool] = None
    last_synced: Optional[Any] = None


class CiscoFTDRealmUser(CiscoFTDSourceRecord):
    realm: Optional[CiscoFTDReference] = None
    username: Optional[str] = None
    external_id: Optional[str] = None
    distinguished_name: Optional[str] = None
    synchronized: Optional[bool] = None
    resolved: Optional[bool] = None
    for_policy: Optional[bool] = None
    last_synced: Optional[Any] = None
    groups: Optional[List[CiscoFTDReference]] = None


class CiscoFTDLocalRealmUser(CiscoFTDSourceRecord):
    username: Optional[str] = None
    realm: Optional[CiscoFTDReference] = None
    enabled: Optional[bool] = None
    groups: Optional[List[CiscoFTDReference]] = None
    password_configured: Optional[bool] = None
