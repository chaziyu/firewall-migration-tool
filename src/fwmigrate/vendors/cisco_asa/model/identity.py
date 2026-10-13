from __future__ import annotations
from typing import List, Optional
from pydantic import Field
from .base import CiscoSourceRecord


class CiscoAAARecord(CiscoSourceRecord):
    protocol: Optional[str] = None
    address: Optional[str] = None
    has_secret: Optional[bool] = None


class CiscoAAAServerGroup(CiscoSourceRecord):
    protocol: Optional[str] = None
    hosts: List[str] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)


class CiscoAAAServerHost(CiscoSourceRecord):
    group_name: str
    host: Optional[str] = None
    interface: Optional[str] = None
    protocol: Optional[str] = None
    authentication_port: Optional[int] = None
    accounting_port: Optional[int] = None
    timeout: Optional[int] = None
    retries: Optional[int] = None
    key_present: bool = False
    password_present: bool = False
    server_secret_present: bool = False
    ldap_base_dn: Optional[str] = None
    ldap_scope: Optional[str] = None
    ldap_naming_attribute: Optional[str] = None
    ldap_login_dn: Optional[str] = None
    ldap_over_ssl: Optional[bool] = None
    radius_common_password_present: bool = False
    review_reasons: List[str] = Field(default_factory=list)


class CiscoLocalUser(CiscoSourceRecord):
    username: str
    privilege: Optional[int] = None
    authentication_type: Optional[str] = None
    password_present: bool = False
    secret_present: bool = False
    encrypted: bool = False
    nopassword: bool = False
    raw_line: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)


class CiscoAAAAuthenticationRule(CiscoSourceRecord):
    service: Optional[str] = None
    management_protocol: Optional[str] = None
    target: Optional[str] = None
    server_group: Optional[str] = None
    fallback_local: bool = False
    interface: Optional[str] = None
    options: List[str] = Field(default_factory=list)
    acl_reference: Optional[str] = None
    user_identity: Optional[str] = None
    raw_line: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)


class CiscoAAAAuthorizationRule(CiscoSourceRecord):
    service: Optional[str] = None
    management_protocol: Optional[str] = None
    target: Optional[str] = None
    server_group: Optional[str] = None
    fallback_local: bool = False
    interface: Optional[str] = None
    options: List[str] = Field(default_factory=list)
    acl_reference: Optional[str] = None
    user_identity: Optional[str] = None
    raw_line: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)


class CiscoAAAAccountingRule(CiscoSourceRecord):
    service: Optional[str] = None
    management_protocol: Optional[str] = None
    target: Optional[str] = None
    server_group: Optional[str] = None
    fallback_local: bool = False
    interface: Optional[str] = None
    options: List[str] = Field(default_factory=list)
    acl_reference: Optional[str] = None
    user_identity: Optional[str] = None
    raw_line: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)


class CiscoCommandPrivilege(CiscoSourceRecord):
    privilege_level: int
    command_form: str
    command: str
    cli_mode: Optional[str] = None
    raw_line: str
    source_order: int = 0
