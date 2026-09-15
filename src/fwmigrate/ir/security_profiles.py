# Canonical IR security_profiles domain models

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, model_validator


class IRSecurityProfileRule(BaseModel):
    name: Optional[str] = None
    applications: List[str] = Field(default_factory=list)
    file_types: List[str] = Field(default_factory=list)
    direction: Optional[str] = None
    action: Optional[str] = None
    vendor_ids: List[str] = Field(default_factory=list)
    severities: List[str] = Field(default_factory=list)
    cves: List[str] = Field(default_factory=list)
    threat_name: Optional[str] = None
    host: Optional[str] = None
    category: Optional[str] = None
    packet_capture: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRSecurityProfileCredentialEnforcement(BaseModel):
    mode: Optional[str] = None
    log_severity: Optional[str] = None
    block_categories: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRSecurityProfileDefinition(BaseModel):
    name: str
    source_context: Optional[str] = None
    family: str
    source_family: str
    description: Optional[str] = None
    rules: List[IRSecurityProfileRule] = Field(default_factory=list)
    allow_categories: List[str] = Field(default_factory=list)
    alert_categories: List[str] = Field(default_factory=list)
    block_categories: List[str] = Field(default_factory=list)
    continue_categories: List[str] = Field(default_factory=list)
    override_categories: List[str] = Field(default_factory=list)
    credential_enforcement: Optional[IRSecurityProfileCredentialEnforcement] = None
    log_http_hdr_xff: Optional[bool] = None
    log_http_hdr_user_agent: Optional[bool] = None
    support_level: str = "TYPED_EXTRACT_ONLY"
    migration_status: str = "EXTRACT_ONLY"
    review_reasons: List[str] = Field(default_factory=list)
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRCertificate(BaseModel):
    name: str
    certificate_type: str

    source_uid: Optional[str] = None
    source_context: Optional[str] = None
    kind: str = "UNKNOWN"
    status: str = "unknown"
    fingerprint_algorithm: Optional[str] = None
    usage_references: List[Dict[str, Any]] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)

    source_range: Optional[str] = None
    source_origin: Optional[str] = None
    public_certificate_pem: Optional[str] = None

    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    public_key_algorithm: Optional[str] = None
    public_key_size: Optional[int] = None
    signature_algorithm: Optional[str] = None
    sha256_fingerprint: Optional[str] = None
    ca_reference: Optional[str] = None
    usage: Optional[str] = None
    is_self_signed: Optional[bool] = None
    is_ca: Optional[bool] = None

    has_certificate: bool = False
    has_private_key: bool = False
    private_key_encrypted: bool = False
    has_password: bool = False

    description: Optional[str] = None
    source_last_updated: Optional[datetime] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    parse_error: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRSSHKey(BaseModel):
    name: str
    key_type: str
    public_key: Optional[str] = None
    source_origin: Optional[str] = None
    has_private_key: bool = False
    has_password: bool = False
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRIdentityServerEndpoint(BaseModel):
    name: Optional[str] = None
    address: Optional[str] = None
    port: Optional[int] = None
    has_secret: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
class IRUserLDAP(BaseModel):
    name: str
    server: Optional[str] = None
    cnid: Optional[str] = None
    dn: Optional[str] = None
    source_type: Optional[str] = None
    username: Optional[str] = None
    has_password: bool = False
    secondary_server: Optional[str] = None
    tertiary_server: Optional[str] = None
    port: Optional[int] = None
    secure: Optional[str] = None
    ca_cert: Optional[str] = None
    server_identity_check: Optional[str] = None
    source_ip: Optional[str] = None
    interface_select_method: Optional[str] = None
    interface: Optional[str] = None
    group_filter: Optional[str] = None
    group_search_base: Optional[str] = None
    obtain_user_info: Optional[str] = None
    password_expiry_warning: Optional[str] = None
    password_renewal: Optional[str] = None
    account_key_cert_field: Optional[str] = None
    account_key_filter: Optional[str] = None
    account_key_processing: Optional[str] = None
    antiphish: Optional[str] = None
    client_cert: Optional[str] = None
    client_cert_auth: Optional[str] = None
    group_member_check: Optional[str] = None
    group_object_filter: Optional[str] = None
    member_attr: Optional[str] = None
    password_attr: Optional[str] = None
    search_type: List[str] = Field(default_factory=list)
    source_port: Optional[int] = None
    ssl_min_proto_version: Optional[str] = None
    ca_certificate_resolved: Optional[bool] = None
    client_certificate_resolved: Optional[bool] = None
    unresolved_certificate_references: List[str] = Field(default_factory=list)
    server_entries: List[IRIdentityServerEndpoint] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRUserRADIUSAccountingServer(BaseModel):
    id: str
    status: Optional[str] = None
    server: Optional[str] = None
    port: Optional[int] = None
    source_ip: Optional[str] = None
    interface_select_method: Optional[str] = None
    interface: Optional[str] = None
    has_secret: bool = False
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRUserRADIUS(BaseModel):
    name: str
    source_context: str = "root"
    server: Optional[str] = None
    secondary_server: Optional[str] = None
    tertiary_server: Optional[str] = None
    auth_type: Optional[str] = None
    port: Optional[int] = None
    acct_interim_interval: Optional[int] = None
    nas_ip: Optional[str] = None
    source_ip: Optional[str] = None
    has_secret: bool = False
    accounting_servers: List[IRUserRADIUSAccountingServer] = Field(default_factory=list)
    server_entries: List[IRIdentityServerEndpoint] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRFSSOEndpoint(BaseModel):
    index: int
    server: Optional[str] = None
    port: Optional[int] = None
    has_password: bool = False
class IRFSSOProvider(BaseModel):
    name: str
    endpoints: List[IRFSSOEndpoint] = Field(default_factory=list)
    server: Optional[str] = None
    has_password: bool = False
    server2: Optional[str] = None
    server3: Optional[str] = None
    server4: Optional[str] = None
    server5: Optional[str] = None
    port: Optional[int] = None
    port2: Optional[int] = None
    port3: Optional[int] = None
    port4: Optional[int] = None
    port5: Optional[int] = None
    interface_select_method: Optional[str] = None
    interface: Optional[str] = None
    ldap_poll: Optional[str] = None
    ldap_poll_filter: Optional[str] = None
    ldap_poll_interval: Optional[int] = None
    group_poll_interval: Optional[int] = None
    ldap_server: Optional[str] = None
    logon_timeout: Optional[int] = None
    source_ip: Optional[str] = None
    source_ip6: Optional[str] = None
    ssl: Optional[str] = None
    ssl_server_host_ip_check: Optional[str] = None
    ssl_trusted_cert: Optional[str] = None
    sni: Optional[str] = None
    source_type: Optional[str] = None
    user_info_server: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRUserTACACS(BaseModel):
    name: str
    source_context: str = "root"
    server: Optional[str] = None
    secondary_server: Optional[str] = None
    tertiary_server: Optional[str] = None
    port: Optional[int] = None
    authentication_type: Optional[str] = None
    authorization: Optional[str] = None
    source_ip: Optional[str] = None
    interface_select_method: Optional[str] = None
    interface: Optional[str] = None
    status_ttl: Optional[int] = None
    has_secret: bool = False
    server_entries: List[IRIdentityServerEndpoint] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRFSSOADGroup(BaseModel):
    name: str
    provider_name: Optional[str] = None
    provider_resolved: bool = False
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRUserSAML(BaseModel):
    name: str
    entity_id: Optional[str] = None
    single_sign_on_url: Optional[str] = None
    single_logout_url: Optional[str] = None
    idp_entity_id: Optional[str] = None
    idp_single_sign_on_url: Optional[str] = None
    idp_single_logout_url: Optional[str] = None
    idp_cert: Optional[str] = None
    idp_certificate_resolved: Optional[bool] = None
    cert_certificate_resolved: Optional[bool] = None
    unresolved_certificate_references: List[str] = Field(default_factory=list)
    user_name: Optional[str] = None
    group_name: Optional[str] = None
    digest_method: Optional[str] = None
    cert: Optional[str] = None
    clock_tolerance: Optional[int] = None
    adfs_claim: Optional[str] = None
    limit_relaystate: Optional[str] = None
    reauth: Optional[str] = None
    user_claim_type: Optional[str] = None
    group_claim_type: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRLocalUser(BaseModel):
    name: str
    id: Optional[int] = None
    uid: Optional[int] = None
    gid: Optional[int] = None
    homedir: Optional[str] = None
    shell: Optional[str] = None
    realname: Optional[str] = None
    lock_out: Optional[str] = None
    force_password_change: Optional[str] = None
    status: Optional[str] = None
    source_type: Optional[str] = None
    has_password: bool = False
    source_passwd_time: Optional[str] = None
    two_factor: Optional[str] = None
    two_factor_authentication: Optional[str] = None
    two_factor_notification: Optional[str] = None
    fortitoken: Optional[str] = None
    email_to: Optional[str] = None
    sms_server: Optional[str] = None
    sms_custom_server: Optional[str] = None
    sms_phone: Optional[str] = None
    ldap_server: Optional[str] = None
    radius_server: Optional[str] = None
    auth_concurrent_override: Optional[str] = None
    auth_concurrent_value: Optional[int] = None
    authtimeout: Optional[int] = None
    passwd_policy: Optional[str] = None
    workstation: Optional[str] = None
    username_sensitivity: Optional[str] = None
    tacacs_server: Optional[str] = None
    ppk_identity: Optional[str] = None
    has_ppk_secret: bool = False
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRUserGroupMatch(BaseModel):
    source_id: int
    server_name: Optional[str] = None
    group_name: Optional[str] = None
class IRUserGroupGuest(BaseModel):
    id: int
    name: Optional[str] = None
    user_id: Optional[str] = None
    company: Optional[str] = None
    email: Optional[str] = None
    expiration: Optional[str] = None
    mobile_phone: Optional[str] = None
    sponsor: Optional[str] = None
    has_password: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRIdentityDependency(BaseModel):
    reference: str
    dependency_type: str
    resolved: bool
    target_name: Optional[str] = None
    source_context: Optional[str] = None
class IRUserGroup(BaseModel):
    name: str
    group_type: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    matches: List[IRUserGroupMatch] = Field(default_factory=list)
    auth_concurrent_override: Optional[str] = None
    auth_concurrent_value: Optional[int] = None
    authtimeout: Optional[int] = None
    company: Optional[str] = None
    email: Optional[str] = None
    expire: Optional[int] = None
    expire_type: Optional[str] = None
    http_digest_realm: Optional[str] = None
    id: Optional[int] = None
    max_accounts: Optional[int] = None
    mobile_phone: Optional[str] = None
    multiple_guest_add: Optional[str] = None
    password: Optional[str] = None
    sms_custom_server: Optional[str] = None
    sms_server: Optional[str] = None
    sponsor: Optional[str] = None
    sso_attribute_value: Optional[str] = None
    user_id: Optional[str] = None
    user_name: Optional[str] = None
    guests: List[IRUserGroupGuest] = Field(default_factory=list)
    resolved_members: List[str] = Field(default_factory=list)
    unresolved_members: List[str] = Field(default_factory=list)
    member_dependencies: List[IRIdentityDependency] = Field(default_factory=list)
    unresolved_match_servers: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRAdministrator(BaseModel):
    name: str
    source_context: Optional[str] = None
    access_profile: Optional[str] = None
    vdoms: List[str] = Field(default_factory=list)
    trusthost1: Optional[str] = None
    trusthost2: Optional[str] = None
    trusted_hosts_ipv4: List[str] = Field(default_factory=list)
    trusted_hosts_ipv6: List[str] = Field(default_factory=list)
    two_factor: Optional[str] = None
    token_reference: Optional[str] = None
    fortitoken_resolved: Optional[bool] = None
    access_profile_resolved: Optional[bool] = None
    unresolved_references: List[str] = Field(default_factory=list)
    email_to: Optional[str] = None
    remote_auth: Optional[str] = None
    remote_group: Optional[str] = None
    guest_user_groups: List[str] = Field(default_factory=list)
    schedule: Optional[str] = None
    peer_auth: Optional[str] = None
    peer_group: Optional[str] = None
    ssh_certificate: Optional[str] = None
    ssh_public_keys: List[str] = Field(default_factory=list)
    credential_configured: bool = False
    authentication_profile: Optional[str] = None
    authentication_sequence: Optional[str] = None
    authentication_profile_resolved: Optional[bool] = None
    authentication_sequence_resolved: Optional[bool] = None
    permitted_ips: List[str] = Field(default_factory=list)
    invalid_permitted_ips: List[str] = Field(default_factory=list)
    certificate_authentication_required: Optional[bool] = None
    certificate_profile: Optional[str] = None
    certificate_profile_resolved: Optional[bool] = None
    disabled: Optional[bool] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRAdminProfilePermissionBlock(BaseModel):
    name: str
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRAdminProfile(BaseModel):
    name: str
    permission_blocks: List[IRAdminProfilePermissionBlock] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRFortiToken(BaseModel):
    serial: str
    status: Optional[str] = None
    assigned_user: Optional[str] = None
    description: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRSSLVPNHostCheckItem(BaseModel):
    source_id: int
    action: Optional[str] = None
    md5s: List[str] = Field(default_factory=list)
    target: Optional[str] = None
    check_type: Optional[str] = None
    version: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRSSLVPNHostCheck(BaseModel):
    name: str
    check_type: Optional[str] = None
    source_type: Optional[str] = None
    os_type: Optional[str] = None
    guid: Optional[str] = None
    version: Optional[str] = None
    check_items: List[IRSSLVPNHostCheckItem] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRFSSOPollingADGroup(BaseModel):
    name: str
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRFSSOPolling(BaseModel):
    name: str
    source_context: str = "root"
    status: Optional[str] = None
    server: Optional[str] = None
    default_domain: Optional[str] = None
    port: Optional[int] = None
    user: Optional[str] = None
    has_password: bool = False
    ldap_server: Optional[str] = None
    logon_history: Optional[int] = None
    polling_frequency: Optional[int] = None
    smbv1: Optional[str] = None
    smb_ntlmv1_auth: Optional[str] = None
    ad_groups: List[IRFSSOPollingADGroup] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRSSLVPNPortalSplitDNS(BaseModel):
    id: Optional[int] = None
    domains: Optional[str] = None
    dns_server1: Optional[str] = None
    dns_server2: Optional[str] = None
    ipv6_dns_server1: Optional[str] = None
    ipv6_dns_server2: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRSSLVPNPortalBookmarkFormData(BaseModel):
    name: str
    value_configured: bool = False
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRSSLVPNPortalBookmark(BaseModel):
    name: str
    form_data: List[IRSSLVPNPortalBookmarkFormData] = Field(default_factory=list)
    has_logon_password: bool = False
    has_sso_password: bool = False
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRSSLVPNPortalBookmarkGroup(BaseModel):
    name: str
    bookmarks: List[IRSSLVPNPortalBookmark] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRSSLVPNPortalLandingPageFormData(IRSSLVPNPortalBookmarkFormData):
    pass
class IRSSLVPNPortalLandingPage(BaseModel):
    name: str
    form_data: List[IRSSLVPNPortalLandingPageFormData] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRSSLVPNPortalMACAddressRule(BaseModel):
    id: Optional[int] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRSSLVPNPortalOSCheck(IRSSLVPNPortalMACAddressRule):
    pass
class IRSSLVPNPortal(BaseModel):
    name: str
    tunnel_mode: Optional[str] = None
    ipv6_tunnel_mode: Optional[str] = None
    ip_pools: List[str] = Field(default_factory=list)
    ipv6_pools: List[str] = Field(default_factory=list)
    split_tunneling: Optional[str] = None
    limit_user_logins: Optional[str] = None
    forticlient_download: Optional[str] = None
    host_check: Optional[str] = None
    host_check_policies: List[str] = Field(default_factory=list)
    host_check_interval: Optional[int] = None
    unresolved_host_check_policies: List[str] = Field(default_factory=list)
    allow_user_access: List[str] = Field(default_factory=list)
    auto_connect: Optional[str] = None
    exclusive_routing: Optional[str] = None
    ip_mode: Optional[str] = None
    service_restriction: Optional[str] = None
    split_tunneling_routing_addresses: List[str] = Field(default_factory=list)
    split_tunneling_routing_negate: Optional[str] = None
    client_src_range: Optional[str] = None
    clipboard: Optional[str] = None
    custom_lang: Optional[str] = None
    customize_forticlient_download_url: Optional[str] = None
    default_protocol: Optional[str] = None
    default_window_height: Optional[int] = None
    default_window_width: Optional[int] = None
    dhcp_ip_overlap: Optional[str] = None
    dhcp_ra_giaddr: Optional[str] = None
    dhcp6_ra_linkaddr: Optional[str] = None
    display_bookmark: Optional[str] = None
    display_connection_tools: Optional[str] = None
    display_history: Optional[str] = None
    display_status: Optional[str] = None
    dns_server1: Optional[str] = None
    dns_server2: Optional[str] = None
    dns_suffix: Optional[str] = None
    focus_bookmark: Optional[str] = None
    forticlient_download_method: Optional[str] = None
    heading: Optional[str] = None
    hide_sso_credential: Optional[str] = None
    ipv6_dns_server1: Optional[str] = None
    ipv6_dns_server2: Optional[str] = None
    ipv6_exclusive_routing: Optional[str] = None
    ipv6_service_restriction: Optional[str] = None
    ipv6_split_tunneling: Optional[str] = None
    ipv6_split_tunneling_routing_addresses: List[str] = Field(default_factory=list)
    ipv6_split_tunneling_routing_negate: Optional[str] = None
    ipv6_wins_server1: Optional[str] = None
    ipv6_wins_server2: Optional[str] = None
    keep_alive: Optional[str] = None
    landing_page_mode: Optional[str] = None
    mac_addr_action: Optional[str] = None
    mac_addr_check: Optional[str] = None
    macos_forticlient_download_url: Optional[str] = None
    os_check: Optional[str] = None
    prefer_ipv6_dns: Optional[str] = None
    redir_url: Optional[str] = None
    rewrite_ip_uri_ui: Optional[str] = None
    save_password: Optional[str] = None
    skip_check_for_browser: Optional[str] = None
    skip_check_for_unsupported_os: Optional[str] = None
    smb_max_version: Optional[str] = None
    smb_min_version: Optional[str] = None
    smb_ntlmv1_auth: Optional[str] = None
    smbv1: Optional[str] = None
    theme: Optional[str] = None
    use_sdwan: Optional[str] = None
    user_bookmark: Optional[str] = None
    user_group_bookmark: Optional[str] = None
    web_mode: Optional[str] = None
    windows_forticlient_download_url: Optional[str] = None
    wins_server1: Optional[str] = None
    wins_server2: Optional[str] = None
    source_fields: Dict[str, Any] = Field(default_factory=dict)
    bookmark_groups: List[IRSSLVPNPortalBookmarkGroup] = Field(default_factory=list)
    landing_pages: List[IRSSLVPNPortalLandingPage] = Field(default_factory=list)
    mac_address_check_rules: List[IRSSLVPNPortalMACAddressRule] = Field(default_factory=list)
    os_check_list: List[IRSSLVPNPortalOSCheck] = Field(default_factory=list)
    split_dns: List[IRSSLVPNPortalSplitDNS] = Field(default_factory=list)
    host_checks: List[IRSSLVPNHostCheck] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRSSLVPNAuthenticationRule(BaseModel):
    source_id: int
    auth: Optional[str] = None
    cipher: Optional[str] = None
    client_cert: Optional[str] = None
    realm: Optional[str] = None
    source_addresses: List[str] = Field(default_factory=list)
    source_address_negate: Optional[str] = None
    source_addresses6: List[str] = Field(default_factory=list)
    source_address6_negate: Optional[str] = None
    source_interfaces: List[str] = Field(default_factory=list)
    user_peer: Optional[str] = None
    users: List[str] = Field(default_factory=list)
    groups: List[str] = Field(default_factory=list)
    unresolved_groups: List[str] = Field(default_factory=list)
    portal: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRSSLVPNSettings(BaseModel):
    status: Optional[str] = None
    ssl_min_proto_ver: Optional[str] = None
    banned_cipher: List[str] = Field(default_factory=list)
    server_certificate: Optional[str] = None
    server_certificate_configured: bool = False
    ssl_max_proto_ver: Optional[str] = None
    algorithm: Optional[str] = None
    client_signature_algorithms: List[str] = Field(default_factory=list)
    require_client_certificate: Optional[str] = None
    dtls_tunnel: Optional[str] = None
    login_attempt_limit: Optional[int] = None
    login_block_time: Optional[int] = None
    auth_timeout: Optional[int] = None
    idle_timeout: Optional[int] = None
    port: Optional[int] = None
    dns_server1: Optional[str] = None
    dns_server2: Optional[str] = None
    wins_server1: Optional[str] = None
    wins_server2: Optional[str] = None
    source_interfaces: List[str] = Field(default_factory=list)
    source_addresses: List[str] = Field(default_factory=list)
    source_addresses6: List[str] = Field(default_factory=list)
    tunnel_ip_pools: List[str] = Field(default_factory=list)
    auth_session_check_source_ip: Optional[str] = None
    auto_tunnel_static_route: Optional[str] = None
    browser_language_detection: Optional[str] = None
    check_referer: Optional[str] = None
    ciphersuite: List[str] = Field(default_factory=list)
    deflate_compression_level: Optional[int] = None
    deflate_min_data_size: Optional[int] = None
    dns_suffix: Optional[str] = None
    dtls_heartbeat_fail_count: Optional[int] = None
    dtls_heartbeat_idle_timeout: Optional[int] = None
    dtls_heartbeat_interval: Optional[int] = None
    dtls_hello_timeout: Optional[int] = None
    dtls_max_proto_ver: Optional[str] = None
    dtls_min_proto_ver: Optional[str] = None
    dual_stack_mode: Optional[str] = None
    encode_2f_sequence: Optional[str] = None
    encrypt_and_store_password: Optional[str] = None
    force_two_factor_auth: Optional[str] = None
    header_x_forwarded_for: Optional[str] = None
    hsts_include_subdomains: Optional[str] = None
    http_compression: Optional[str] = None
    http_only_cookie: Optional[str] = None
    http_request_body_timeout: Optional[int] = None
    http_request_header_timeout: Optional[int] = None
    https_redirect: Optional[str] = None
    ipv6_dns_server1: Optional[str] = None
    ipv6_dns_server2: Optional[str] = None
    ipv6_wins_server1: Optional[str] = None
    ipv6_wins_server2: Optional[str] = None
    login_timeout: Optional[int] = None
    port_precedence: Optional[str] = None
    saml_redirect_port: Optional[int] = None
    server_hostname: Optional[str] = None
    source_address_negate: Optional[str] = None
    source_address6: List[str] = Field(default_factory=list)
    source_address6_negate: Optional[str] = None
    ssl_client_renegotiation: Optional[str] = None
    ssl_insert_empty_fragment: Optional[str] = None
    transform_backward_slashes: Optional[str] = None
    tunnel_addr_assigned_method: Optional[str] = None
    tunnel_connect_without_reauth: Optional[str] = None
    tunnel_ipv6_pools: List[str] = Field(default_factory=list)
    tunnel_user_session_timeout: Optional[int] = None
    unsafe_legacy_renegotiation: Optional[str] = None
    url_obscuration: Optional[str] = None
    user_peer: Optional[str] = None
    x_content_type_options: Optional[str] = None
    ztna_trusted_client: Optional[str] = None
    source_fields: Dict[str, Any] = Field(default_factory=dict)
    default_portal: Optional[str] = None
    authentication_rules: List[IRSSLVPNAuthenticationRule] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRDoSAnomaly(BaseModel):
    name: str
    status: Optional[str] = None
    log: Optional[str] = None
    action: Optional[str] = None
    quarantine: Optional[str] = None
    quarantine_expiry: Optional[str] = None
    quarantine_log: Optional[str] = None
    threshold: Optional[int] = None
    threshold_default: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRDoSPolicy(BaseModel):
    source_id: int
    name: Optional[str] = None
    source_context: Optional[str] = None
    address_family: str = "ipv4"
    status: Optional[str] = None
    interface: Optional[str] = None
    source_addresses: List[str] = Field(default_factory=list)
    destination_addresses: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    anomalies: List[IRDoSAnomaly] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRFirewallSniffer(BaseModel):
    source_id: int
    source_uuid: Optional[str] = None
    logtraffic: Optional[str] = None
    ipv6: Optional[str] = None
    non_ip: Optional[str] = None
    application_list_status: Optional[str] = None
    application_list: Optional[str] = None
    ips_sensor_status: Optional[str] = None
    ips_sensor: Optional[str] = None
    av_profile_status: Optional[str] = None
    av_profile: Optional[str] = None
    webfilter_profile_status: Optional[str] = None
    webfilter_profile: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRAuthenticationProfile(BaseModel):
    name: str
    method: Optional[str] = None
    identity_source: Optional[str] = None
    server_refs: List[str] = Field(default_factory=list)
    realm: Optional[str] = None
    domain: Optional[str] = None
    user_database: Optional[str] = None
    certificate_profile: Optional[str] = None
    mfa_provider: Optional[str] = None
    timeout: Optional[int] = None
    resolved_user_databases: List[str] = Field(default_factory=list)
    unresolved_user_databases: List[str] = Field(default_factory=list)
    user_database_dependencies: List[IRIdentityDependency] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRAuthenticationSequence(BaseModel):
    name: str
    source_context: Optional[str] = None
    authentication_profiles: List[str] = Field(default_factory=list)
    profiles: List[str] = Field(default_factory=list)
    order: List[str] = Field(default_factory=list)
    continue_on_failure: bool = False
    stop_on_failure: bool = True
    resolved_authentication_profiles: List[str] = Field(default_factory=list)
    unresolved_authentication_profiles: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def normalize_profile_aliases(self):
        if self.profiles:
            self.authentication_profiles = list(self.profiles)
        else:
            self.profiles = list(self.authentication_profiles)
        if not self.order:
            self.order = list(self.profiles)
        return self
class IRSSLTLSServiceProfile(BaseModel):
    name: str
    source_context: Optional[str] = None
    certificate: Optional[str] = None
    certificate_resolved: Optional[bool] = None
    # May hold an unexpected PAN-OS source reference retained for audit compatibility.
    certificate_profile: Optional[str] = None
    certificate_profile_resolved: Optional[bool] = None
    minimum_tls_version: Optional[str] = None
    maximum_tls_version: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRAuthenticationPolicy(BaseModel):
    name: str
    source: List[str] = Field(default_factory=list)
    destination: List[str] = Field(default_factory=list)
    interfaces: List[str] = Field(default_factory=list)
    zones: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    users: List[str] = Field(default_factory=list)
    schedule: Optional[str] = None
    authentication_profile: Optional[str] = None
    authentication_sequence: Optional[str] = None
    action: Optional[str] = None
    source_interfaces: List[str] = Field(default_factory=list)
    source_addresses: List[str] = Field(default_factory=list)
    active_auth_method: Optional[str] = None
    active_auth_method_resolved: Optional[bool] = None
    unresolved_auth_methods: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


IRAuthenticationScheme = IRAuthenticationProfile
IRAuthenticationRule = IRAuthenticationPolicy
class IRUserAuthenticationSettings(BaseModel):
    auth_certificate: Optional[str] = None
    auth_certificate_resolved: Optional[bool] = None
    auth_ca_certificate: Optional[str] = None
    auth_ca_certificate_resolved: Optional[bool] = None
    auth_timeout: Optional[int] = None
    auth_lockout_threshold: Optional[int] = None
    auth_lockout_duration: Optional[int] = None
    ssl_min_proto_version: Optional[str] = None
    management_authentication_profile: Optional[str] = None
    management_authentication_profile_resolved: Optional[bool] = None
    unresolved_management_authentication_profile: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRUserQuarantineSettings(BaseModel):
    firewall_groups: List[str] = Field(default_factory=list)
    resolved_firewall_groups: List[str] = Field(default_factory=list)
    unresolved_firewall_groups: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRGlobalProtectClientAuthentication(BaseModel):
    name: str
    os: Optional[str] = None
    authentication_profile: Optional[str] = None
    authentication_profile_resolved: Optional[bool] = None
    resolved_authentication_profile: Optional[str] = None
    authentication_message: Optional[str] = None
    username_label: Optional[str] = None
    password_label: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRGlobalProtectGatewayPriorityRule(BaseModel):
    name: str
    priority: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRGlobalProtectExternalGateway(BaseModel):
    name: str
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    manual: Optional[bool] = None
    priority_rules: List[IRGlobalProtectGatewayPriorityRule] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRGlobalProtectAppSetting(BaseModel):
    name: str
    values: List[str] = Field(default_factory=list)
    source_order: int
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRGlobalProtectPortalClientConfig(BaseModel):
    name: str
    source_users: List[str] = Field(default_factory=list)
    operating_systems: List[str] = Field(default_factory=list)
    external_gateways: List[IRGlobalProtectExternalGateway] = Field(default_factory=list)
    external_gateway_cutoff_time: Optional[str] = None
    authentication_override_generate_cookie: Optional[bool] = None
    max_agent_user_overrides: Optional[int] = None
    agent_user_override_timeout: Optional[int] = None
    hip_collect_data: Optional[bool] = None
    hip_max_wait_time: Optional[int] = None
    app_settings: List[IRGlobalProtectAppSetting] = Field(default_factory=list)
    save_user_credentials: Optional[Union[int, str]] = None
    portal_2fa: Optional[bool] = None
    manual_only_gateway_2fa: Optional[bool] = None
    internal_gateway_2fa: Optional[bool] = None
    auto_discovery_external_gateway_2fa: Optional[bool] = None
    mdm_enrollment_port: Optional[int] = None
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRGlobalProtectPortalRootCA(BaseModel):
    certificate: str
    certificate_resolved: Optional[bool] = None
    resolved_certificate: Optional[str] = None
    install_in_cert_store: Optional[bool] = None
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRGlobalProtectPortal(BaseModel):
    name: str
    source_context: Optional[str] = None
    local_interface: Optional[str] = None
    local_interface_resolved: Optional[bool] = None
    resolved_local_interface: Optional[str] = None
    local_ipv4: Optional[str] = None
    local_ipv6: Optional[str] = None
    local_address_resolved: Optional[bool] = None
    resolved_local_address: Optional[str] = None
    ssl_tls_service_profile: Optional[str] = None
    ssl_tls_service_profile_resolved: Optional[bool] = None
    resolved_ssl_tls_service_profile: Optional[str] = None
    custom_login_page: Optional[str] = None
    custom_home_page: Optional[str] = None
    client_authentication: List[IRGlobalProtectClientAuthentication] = Field(default_factory=list)
    client_configs: List[IRGlobalProtectPortalClientConfig] = Field(default_factory=list)
    root_ca_certificates: List[IRGlobalProtectPortalRootCA] = Field(default_factory=list)
    has_agent_user_override_key: bool = False
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRGlobalProtectGatewayRole(BaseModel):
    name: str
    login_lifetime_days: Optional[int] = None
    inactivity_logout_hours: Optional[int] = None
    disconnect_on_idle_minutes: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRGlobalProtectRemoteUserTunnelConfig(BaseModel):
    name: str
    source_users: List[str] = Field(default_factory=list)
    operating_systems: List[str] = Field(default_factory=list)
    ip_pools: List[str] = Field(default_factory=list)
    split_include_routes: List[str] = Field(default_factory=list)
    resolved_split_include_routes: List[str] = Field(default_factory=list)
    unresolved_split_include_routes: List[str] = Field(default_factory=list)
    split_exclude_routes: List[str] = Field(default_factory=list)
    resolved_split_exclude_routes: List[str] = Field(default_factory=list)
    unresolved_split_exclude_routes: List[str] = Field(default_factory=list)
    retrieve_framed_ip_address: Optional[bool] = None
    no_direct_access_to_local_network: Optional[bool] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRGlobalProtectGateway(BaseModel):
    name: str
    source_context: Optional[str] = None
    ssl_tls_service_profile: Optional[str] = None
    ssl_tls_service_profile_resolved: Optional[bool] = None
    resolved_ssl_tls_service_profile: Optional[str] = None
    tunnel_mode: Optional[bool] = None
    remote_user_tunnel: Optional[str] = None
    remote_user_tunnel_resolved: Optional[bool] = None
    resolved_remote_user_tunnel: Optional[str] = None
    roles: List[IRGlobalProtectGatewayRole] = Field(default_factory=list)
    client_authentication: List[IRGlobalProtectClientAuthentication] = Field(default_factory=list)
    remote_user_tunnel_configs: List[IRGlobalProtectRemoteUserTunnelConfig] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRGlobalProtectNetworkGateway(BaseModel):
    name: str
    source_context: Optional[str] = None
    local_interface: Optional[str] = None
    local_interface_resolved: Optional[bool] = None
    resolved_local_interface: Optional[str] = None
    local_ipv4: Optional[str] = None
    local_ipv6: Optional[str] = None
    tunnel_interface: Optional[str] = None
    tunnel_interface_resolved: Optional[bool] = None
    resolved_tunnel_interface: Optional[str] = None
    ip_pools: List[str] = Field(default_factory=list)
    client_dns_primary: Optional[str] = None
    client_dns_secondary: Optional[str] = None
    dns_suffixes: List[str] = Field(default_factory=list)
    dns_suffix_inherited: Optional[bool] = None
    exclude_video_traffic_enabled: Optional[bool] = None
    third_party_client_enabled: Optional[bool] = None
    third_party_group_name: Optional[str] = None
    third_party_group_password_configured: bool = False
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANLogServerEndpoint(BaseModel):
    name: str
    address: Optional[str] = None
    transport: Optional[str] = None
    port: Optional[int] = None
    format: Optional[str] = None
    facility: Optional[str] = None
    display_name: Optional[str] = None
    gateway: Optional[str] = None
    from_address: Optional[str] = None
    to_addresses: List[str] = Field(default_factory=list)
    snmp_version: Optional[str] = None
    community_configured: Optional[bool] = None
    username: Optional[str] = None
    authentication_password_configured: Optional[bool] = None
    privacy_password_configured: Optional[bool] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANLogServerProfile(BaseModel):
    name: str
    source_context: Optional[str] = None
    profile_type: str
    servers: List[IRPANLogServerEndpoint] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANLogForwardingMatch(BaseModel):
    name: str
    log_type: Optional[str] = None
    filter: Optional[str] = None
    send_to_panorama: Optional[bool] = None
    syslog_profiles: List[str] = Field(default_factory=list)
    email_profiles: List[str] = Field(default_factory=list)
    snmptrap_profiles: List[str] = Field(default_factory=list)
    http_profiles: List[str] = Field(default_factory=list)
    resolved_syslog_profiles: List[str] = Field(default_factory=list)
    unresolved_syslog_profiles: List[str] = Field(default_factory=list)
    resolved_email_profiles: List[str] = Field(default_factory=list)
    unresolved_email_profiles: List[str] = Field(default_factory=list)
    resolved_snmptrap_profiles: List[str] = Field(default_factory=list)
    unresolved_snmptrap_profiles: List[str] = Field(default_factory=list)
    resolved_http_profiles: List[str] = Field(default_factory=list)
    unresolved_http_profiles: List[str] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANLogForwardingProfile(BaseModel):
    name: str
    source_context: Optional[str] = None
    matches: List[IRPANLogForwardingMatch] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANManagementLogSetting(IRPANLogForwardingMatch):
    log_family: Optional[str] = None
class IRPANDNSProxyDomainServer(BaseModel):
    name: str
    domain_names: List[str] = Field(default_factory=list)
    primary: Optional[str] = None
    secondary: Optional[str] = None
    cacheable: Optional[bool] = None
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANDNSProxy(BaseModel):
    name: str
    source_context: Optional[str] = None
    enabled: Optional[bool] = None
    cache_enabled: Optional[bool] = None
    max_ttl_enabled: Optional[bool] = None
    default_primary: Optional[str] = None
    default_secondary: Optional[str] = None
    tcp_queries_enabled: Optional[bool] = None
    interfaces: List[str] = Field(default_factory=list)
    resolved_interfaces: List[str] = Field(default_factory=list)
    unresolved_interfaces: List[str] = Field(default_factory=list)
    domain_servers: List[IRPANDNSProxyDomainServer] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANMonitorProfile(BaseModel):
    name: str
    source_context: Optional[str] = None
    interval_seconds: Optional[int] = None
    threshold: Optional[int] = None
    action: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANQoSClass(BaseModel):
    name: str
    priority: Optional[str] = None
    egress_max: Optional[float] = None
    egress_guaranteed: Optional[float] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANQoSProfile(BaseModel):
    name: str
    source_context: Optional[str] = None
    bandwidth_type: Optional[str] = None
    egress_max: Optional[float] = None
    egress_guaranteed: Optional[float] = None
    classes: List[IRPANQoSClass] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANSDWANInterfaceProfile(BaseModel):
    name: str
    source_context: Optional[str] = None
    path_monitoring: Optional[Dict[str, Any]] = None
    vpn_failover_metric: Optional[str] = None
    probe_settings: Optional[Dict[str, Any]] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANSDWANLinkSettings(BaseModel):
    interface: str
    interface_profile: Optional[str] = None
    path_quality_profile: Optional[str] = None
    traffic_distribution_profile: Optional[str] = None
    saas_quality_profile: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANSDWANPathQualityProfile(BaseModel):
    name: str
    source_context: Optional[str] = None
    latency: Optional[int] = None
    jitter: Optional[int] = None
    packet_loss: Optional[int] = None
    sensitivity: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANSDWANTrafficDistributionProfile(BaseModel):
    name: str
    source_context: Optional[str] = None
    method: Optional[str] = None
    link_tags: List[str] = Field(default_factory=list)
    weights: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANSDWANRule(BaseModel):
    name: str
    source_context: Optional[str] = None
    source_rule_id: Optional[str] = None
    source_order: int = 0
    rulebase_position: str = "local"
    source: List[str] = Field(default_factory=list)
    destination: List[str] = Field(default_factory=list)
    source_user: List[str] = Field(default_factory=list)
    application: List[str] = Field(default_factory=list)
    service: List[str] = Field(default_factory=list)
    input_interface: List[str] = Field(default_factory=list)
    input_zone: List[str] = Field(default_factory=list)
    path_quality_profile: Optional[str] = None
    traffic_distribution_profile: Optional[str] = None
    saas_quality_profile: Optional[str] = None
    action: Optional[str] = None
    failover: Optional[Dict[str, Any]] = None
    disabled: Optional[bool] = None
    migration_status: str = "PARTIALLY_NORMALIZED"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANHAInterface(BaseModel):
    name: str
    ip_address: Optional[str] = None
    netmask: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANHALinkMonitorGroup(BaseModel):
    name: str
    interfaces: List[str] = Field(default_factory=list)
    resolved_interfaces: List[str] = Field(default_factory=list)
    unresolved_interfaces: List[str] = Field(default_factory=list)
    enabled: Optional[bool] = None
    failure_condition: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANHAPathMonitorGroup(BaseModel):
    name: str
    routing_instance: Optional[str] = None
    routing_instance_resolved: Optional[str] = None
    resolved_routing_instance: Optional[str] = None
    destination_ips: List[str] = Field(default_factory=list)
    failure_condition: Optional[str] = None
    ping_interval_ms: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANVirtualWire(BaseModel):
    name: str
    source_context: Optional[str] = None
    interface1: Optional[str] = None
    interface2: Optional[str] = None
    interface1_resolved: Optional[bool] = None
    interface2_resolved: Optional[bool] = None
    resolved_interfaces: List[str] = Field(default_factory=list)
    unresolved_interfaces: List[str] = Field(default_factory=list)
    tag_allowed: Optional[bool] = None
    multicast_firewalling: Optional[bool] = None
    link_state_pass_through: Optional[bool] = None
    vsys: Optional[str] = None
    zones: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANHighAvailability(BaseModel):
    source_context: Optional[str] = None
    enabled: Optional[bool] = None
    group_id: Optional[int] = None
    description: Optional[str] = None
    peer_ip: Optional[str] = None
    preemptive: Optional[bool] = None
    recommended_timers: Optional[bool] = None
    ha2_keep_alive_enabled: Optional[bool] = None
    link_monitoring_enabled: Optional[bool] = None
    link_monitoring_failure_condition: Optional[str] = None
    link_groups: List[IRPANHALinkMonitorGroup] = Field(default_factory=list)
    path_monitoring_enabled: Optional[bool] = None
    path_monitoring_failure_condition: Optional[str] = None
    path_groups: List[IRPANHAPathMonitorGroup] = Field(default_factory=list)
    interfaces: List[IRPANHAInterface] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANDeviceOperationalSettings(BaseModel):
    source_context: Optional[str] = None
    rematch_sessions: Optional[bool] = None
    hostname_type_in_syslog: Optional[str] = None
    auto_acquire_commit_lock: Optional[bool] = None
    wildfire_report_benign_file: Optional[bool] = None
    wildfire_report_grayware_file: Optional[bool] = None
    tcp_urgent_data: Optional[str] = None
    tcp_asymmetric_path: Optional[str] = None
    session_timeout_default_seconds: Optional[int] = None
    session_timeout_tcp_seconds: Optional[int] = None
    multi_vsys_enabled: Optional[bool] = None
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANVsysSettings(BaseModel):
    source_context: Optional[str] = None
    allow_forward_decrypted_content: Optional[bool] = None
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANBotnetUnknownApplicationThreshold(BaseModel):
    protocol: str
    sessions_per_hour: Optional[int] = None
    destinations_per_hour: Optional[int] = None
    minimum_bytes: Optional[int] = None
    maximum_bytes: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANBotnetReportSettings(BaseModel):
    dynamic_dns_enabled: Optional[bool] = None
    dynamic_dns_threshold: Optional[int] = None
    malware_sites_enabled: Optional[bool] = None
    malware_sites_threshold: Optional[int] = None
    recent_domains_enabled: Optional[bool] = None
    recent_domains_threshold: Optional[int] = None
    ip_domains_enabled: Optional[bool] = None
    ip_domains_threshold: Optional[int] = None
    executables_unknown_sites_enabled: Optional[bool] = None
    executables_unknown_sites_threshold: Optional[int] = None
    irc_enabled: Optional[bool] = None
    unknown_application_thresholds: List[IRPANBotnetUnknownApplicationThreshold] = Field(default_factory=list)
    topn: Optional[int] = None
    scheduled: Optional[bool] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRPANCustomReport(BaseModel):
    name: str
    source_context: Optional[str] = None
    report_type: Optional[str] = None
    sort_by: Optional[str] = None
    group_by: Optional[str] = None
    aggregate_by: List[str] = Field(default_factory=list)
    topn: Optional[int] = None
    topm: Optional[int] = None
    caption: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRLogDestinationProfile(BaseModel):
    name: str
    destination_type: str
    servers: List[str] = Field(default_factory=list)
    address: Optional[str] = None
    transport: Optional[str] = None
    port: Optional[int] = None
    tls: Optional[bool] = None
    format: Optional[str] = None
    facility: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRLogForwardingPolicy(BaseModel):
    name: str
    log_type: Optional[str] = None
    filter: Optional[str] = None
    severity: Optional[str] = None
    destinations: List[str] = Field(default_factory=list)
    actions: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRDNSProxy(BaseModel):
    name: str
    interfaces: List[str] = Field(default_factory=list)
    default_servers: List[str] = Field(default_factory=list)
    domain_rules: List[Dict[str, Any]] = Field(default_factory=list)
    cache_enabled: Optional[bool] = None
    tcp_enabled: Optional[bool] = None
    conditional_forwarding: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRMonitorProfile(BaseModel):
    name: str
    probe_type: Optional[str] = None
    targets: List[str] = Field(default_factory=list)
    interval: Optional[int] = None
    timeout: Optional[int] = None
    failure_threshold: Optional[int] = None
    recovery_threshold: Optional[int] = None
    action: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRQoSProfile(BaseModel):
    name: str
    classes: List[Dict[str, Any]] = Field(default_factory=list)
    priority: Optional[str] = None
    guaranteed_bandwidth: Optional[int] = None
    maximum_bandwidth: Optional[int] = None
    queue: Optional[str] = None
    dscp: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRReportDefinition(BaseModel):
    name: str
    report_type: Optional[str] = None
    data_source: Optional[str] = None
    filters: List[Dict[str, Any]] = Field(default_factory=list)
    query: Optional[str] = None
    columns: List[str] = Field(default_factory=list)
    metrics: List[str] = Field(default_factory=list)
    group_by: List[str] = Field(default_factory=list)
    sort_by: List[str] = Field(default_factory=list)
    limit: Optional[int] = None
    time_range: Optional[str] = None
    schedule: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


__all__ = [
    "IRCertificate",
    "IRSSHKey",
    "IRSecurityProfileRule",
    "IRSecurityProfileCredentialEnforcement",
    "IRSecurityProfileDefinition",
    "IRIdentityServerEndpoint",
    "IRUserLDAP",
    "IRUserRADIUSAccountingServer",
    "IRUserRADIUS",
    "IRFSSOEndpoint",
    "IRFSSOProvider",
    "IRUserTACACS",
    "IRFSSOADGroup",
    "IRUserSAML",
    "IRLocalUser",
    "IRUserGroupMatch",
    "IRUserGroupGuest",
    "IRIdentityDependency",
    "IRUserGroup",
    "IRAdministrator",
    "IRAdminProfilePermissionBlock",
    "IRAdminProfile",
    "IRFortiToken",
    "IRSSLVPNHostCheckItem",
    "IRSSLVPNHostCheck",
    "IRFSSOPollingADGroup",
    "IRFSSOPolling",
    "IRSSLVPNPortalSplitDNS",
    "IRSSLVPNPortalBookmarkFormData",
    "IRSSLVPNPortalBookmark",
    "IRSSLVPNPortalBookmarkGroup",
    "IRSSLVPNPortalLandingPageFormData",
    "IRSSLVPNPortalLandingPage",
    "IRSSLVPNPortalMACAddressRule",
    "IRSSLVPNPortalOSCheck",
    "IRSSLVPNPortal",
    "IRSSLVPNAuthenticationRule",
    "IRSSLVPNSettings",
    "IRDoSAnomaly",
    "IRDoSPolicy",
    "IRFirewallSniffer",
    "IRAuthenticationProfile",
    "IRAuthenticationScheme",
    "IRAuthenticationSequence",
    "IRSSLTLSServiceProfile",
    "IRAuthenticationPolicy",
    "IRAuthenticationRule",
    "IRUserAuthenticationSettings",
    "IRUserQuarantineSettings",
    "IRGlobalProtectClientAuthentication",
    "IRGlobalProtectGatewayPriorityRule",
    "IRGlobalProtectExternalGateway",
    "IRGlobalProtectAppSetting",
    "IRGlobalProtectPortalClientConfig",
    "IRGlobalProtectPortalRootCA",
    "IRGlobalProtectPortal",
    "IRGlobalProtectGatewayRole",
    "IRGlobalProtectRemoteUserTunnelConfig",
    "IRGlobalProtectGateway",
    "IRGlobalProtectNetworkGateway",
    "IRPANLogServerEndpoint",
    "IRPANLogServerProfile",
    "IRPANLogForwardingMatch",
    "IRPANLogForwardingProfile",
    "IRPANManagementLogSetting",
    "IRPANDNSProxyDomainServer",
    "IRPANDNSProxy",
    "IRPANMonitorProfile",
    "IRPANQoSClass",
    "IRPANQoSProfile",
    "IRPANSDWANInterfaceProfile",
    "IRPANSDWANLinkSettings",
    "IRPANSDWANPathQualityProfile",
    "IRPANSDWANTrafficDistributionProfile",
    "IRPANSDWANRule",
    "IRPANHAInterface",
    "IRPANHALinkMonitorGroup",
    "IRPANHAPathMonitorGroup",
    "IRPANVirtualWire",
    "IRPANHighAvailability",
    "IRPANDeviceOperationalSettings",
    "IRPANVsysSettings",
    "IRPANBotnetUnknownApplicationThreshold",
    "IRPANBotnetReportSettings",
    "IRPANCustomReport",
    "IRLogDestinationProfile",
    "IRLogForwardingPolicy",
    "IRDNSProxy",
    "IRMonitorProfile",
    "IRQoSProfile",
    "IRReportDefinition",
]
