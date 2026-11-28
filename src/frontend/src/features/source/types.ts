export type SourceVendor = string
export type CollectionField = { name: string; label: string; type: string; required?: boolean; default?: unknown; options?: string[] }
export type SourceVendorOption = {
  vendor_id: SourceVendor
  display_name: string
  file_extensions: string[]
  max_source_bytes?: number
  max_snapshot_bytes?: number
  live_collection?: boolean
  collection?: { method: string; connection_fields: CollectionField[] } | null
}
export type MigrationPairOption = {
  pair_id: string
  source_vendor: string
  target_vendor: string
  display_name: string
  api_prefix: string
  supported_formats: string[]
  export_available: boolean
  destination_aware_available: boolean
  deployment_available: boolean
  mapping_workflow?: string | null
  destination_comparison?: string | null
  execution_mode?: string | null
  activation_steps?: string[]
}
export type LifecycleBadge = {
  id: string
  text: string
  variant: 'allow' | 'warn' | 'deny' | 'info' | 'muted'
}

export type LifecycleRow = {
  label: string
  value: string
}

export type LifecycleRefreshParams = {
  vendor: 'fortigate' | 'palo_alto'
  model?: string
  firmware?: string
  version?: string
  exact?: boolean
}

export type LifecycleCardData = {
  id: string
  vendor: string
  title: string
  subtitle: string
  source_label: string
  snapshot_updated_at?: string
  needs_live_refresh: boolean
  badge: LifecycleBadge
  rows: LifecycleRow[]
  refresh_params?: LifecycleRefreshParams
}

export type SourcePreviewData = {
  source_evidence?: import('../../storage/workspaceTypes').SourceEvidence
  source_digest?: string
  vendor?: string
  summary?: Record<string, unknown>
  sections?: Record<string, unknown>
  [key: string]: unknown
}

export type WhereUsedCategory = {
  key: string
  label: string
  count: number
  columns: string[]
  rows: Record<string, unknown>[]
}

export type WhereUsedResponse = {
  success?: boolean
  vendor: string
  query: string
  query_type: 'ip' | 'cidr' | 'range' | 'name'
  resolved_objects: string[]
  total_matches: number
  categories: WhereUsedCategory[]
}

export type VpnInspectorFinding = {
  severity: 'critical' | 'warning' | 'info' | string
  code: string
  message: string
}

export type VpnInspectorRow = {
  health: 'healthy' | 'warning' | 'critical' | 'disabled' | string
  name: string
  vdom?: string
  scope?: string
  vpn_mode?: string
  remote_gateway?: string | null
  ike_version?: string | null
  tunnel_interface?: string | null
  zones?: string[]
  virtual_router?: string | null
  phase2_count?: number
  route_count?: number
  policy_count?: number
  finding_count?: number
  phase1?: Record<string, unknown>
  phase2?: Record<string, unknown>[]
  binding?: Record<string, unknown>
  routes?: Record<string, unknown>[]
  policies?: Record<string, unknown>[]
  nat_exposures?: Record<string, unknown>[]
  findings?: VpnInspectorFinding[]
  [key: string]: unknown
}

export type CertificateRow = {
  name: string
  store: string
  vdom?: string
  common_name: string
  san: string
  issuer: string
  not_before: string
  expires: string
  days_left: string
  status: 'Expired' | 'Expiring Soon' | 'Valid' | 'No PEM' | string
}

export type CertificateSummary = {
  total: number
  expired: number
  expiring_soon: number
  valid: number
  no_pem: number
}

export type ExposureTarget = {
  ip: string
  port: number
  protocol: string
}

export type ExposureFinding = {
  interface: string
  vdom?: string
  scope?: string
  ip: string
  protocols: string[]
  display_protocols?: string[]
  note: string
  restricted: boolean
  severity: 'critical' | 'warn' | string
  targets?: ExposureTarget[]
}

export type ExposureProbeResult = {
  interface: string
  ip: string
  port: number
  protocol: string
  config_severity: string
  status: 'open' | 'refused' | 'filtered' | string
  detail: string
}

export type ExposureProbeResponse = {
  success?: boolean
  vendor: string
  open_count: number
  total: number
  results: ExposureProbeResult[]
}

export type PostureInfo = {
  internet: string
  internet_sub: string
  disk: string
  disk_sub: string
}

export type HygieneIssue = {
  finding: string
  target: string
  details: string
  severity: string
  tone: 'danger' | 'warn' | string
}

export type UnusedObjectRow = {
  category: string
  name: string
  scope: string
  value: string
}

export type HygieneAnalysis = {
  unused_objects: UnusedObjectRow[]
  hygiene_issues: HygieneIssue[]
  counts: {
    unused: number
    disabled: number
    broad: number
    extra: number
  }
  cleanup_cli: string
}

export type QuickAuditFinding = {
  severity: 'High' | 'Medium' | 'Info' | string
  category: string
  count: number
  details: string
}

export type QuickAuditSummary = {
  findings: QuickAuditFinding[]
  high_count: number
  med_count: number
  info_count: number
}

export type SecurityAuditResponse = {
  success?: boolean
  vendor: string
  certificates: CertificateRow[]
  certificate_summary: CertificateSummary
  exposure: ExposureFinding[]
  posture: PostureInfo
  hygiene: HygieneAnalysis
  quick_audit: QuickAuditSummary
}

export type PmStatus = 'Pass' | 'Warn' | 'Fail' | 'Info' | string

export type PmChecklistRow = {
  no: string
  category: string
  task: string
  status: PmStatus
  finding: string
  guidance: string
}

export type PmChecklistSummary = {
  pass: number
  warn: number
  fail: number
  info: number
  total: number
}

export type PmLegendItem = {
  label: string
  variant: 'success' | 'info' | 'warn' | 'danger' | string
}

export type PmChecklistResponse = {
  success?: boolean
  vendor: string
  vendor_label: string
  hostname: string
  subtitle: string
  rows: PmChecklistRow[]
  summary: PmChecklistSummary
  legend?: PmLegendItem[]
}

export type PolicyLookupRequest = {
  vdom?: string
  scope?: string
  policy_type?: 'security' | 'nat'
  src_iface?: string
  dst_iface?: string
  src_zone?: string
  dst_zone?: string
  src_addr: string
  dst_addr: string
  dst_port?: string
  protocol?: string
  src_user?: string
}

export type PolicyMatchRecord = Record<string, string | number | undefined>

export type PolicyLookupResponse = {
  success?: boolean
  vendor: string
  policy_type?: string
  matched: boolean
  action: string
  reason: string
  match: PolicyMatchRecord | null
  shadowed: PolicyMatchRecord[]
}

export type RouteLookupRequest = {
  dest_ip: string
  vdom?: string
  virtual_router?: string
}

export type RouteCandidate = {
  vdom?: string
  virtual_router?: string
  type: string
  route_name?: string
  destination: string
  prefix_len: number
  gateway?: string
  next_hop?: string
  interface: string
  distance?: number
  priority?: number
  ad?: number
  metric?: number
  comment?: string
}

export type RouteLookupResponse = {
  success?: boolean
  vendor: string
  valid: boolean
  dest_ip?: string
  winner?: RouteCandidate | null
  candidates?: RouteCandidate[]
  active_policy_routes?: number
  virtual_routers?: string[]
  vdoms?: string[]
  error?: string
}

export type PacketTraceRequest = {
  src_ip: string
  dst_ip: string
  dst_port?: string
  protocol?: string
  vdom?: string
  virtual_router?: string
  scope?: string
  check_return?: boolean
}

export type PacketTraceStep = {
  step: string
  stage: string
  outcome: string
  details: string
  tone: 'info' | 'success' | 'warn' | 'danger' | string
}

export type PacketTraceResponse = {
  success?: boolean
  vendor: string
  valid: boolean
  verdict?: string
  src?: string
  dst?: string
  ingress?: string
  egress?: string
  policy?: string
  nat?: string
  return_path?: string
  steps?: PacketTraceStep[]
  warnings?: string[]
  error?: string
}

export type ConfigDiffRow = {
  change: 'Added' | 'Modified' | 'Removed' | string
  item: string
  details: string
  change_type: 'added' | 'modified' | 'removed' | string
}

export type ConfigDiffDomain = {
  name: string
  count: number
  rows: ConfigDiffRow[]
}

export type ConfigDiffResponse = {
  success?: boolean
  vendor: string
  before_name: string
  after_name: string
  has_diff: boolean
  summary: {
    added: number
    modified: number
    removed: number
    total: number
  }
  domains: ConfigDiffDomain[]
}

export type SslToIpsecPolicyRow = {
  id: string
  name: string
  status: string
  srcintf: string
  dstintf: string
  srcaddr: string
  dstaddr: string
  service: string
  action: string
  nat: string
  schedule: string
  groups: string
  users: string
  profiles: string
}

export type SslToIpsecGuiRow = {
  parameter: string
  recommended_value: string
  notes: string
}

export type SslToIpsecClientRow = {
  setting: string
  value: string
}

export type SslToIpsecCutoverRow = {
  step: string
  phase: string
  action: string
}

export type SslToIpsecResponse = {
  success?: boolean
  has_ssl_vpn: boolean
  vdom: string | null
  vdoms: string[]
  model: string
  firmware: string
  servercert?: string
  is_factory_cert?: boolean
  require_client_cert?: boolean
  auth_mode?: 'saml' | 'cert' | 'eap' | string
  auth_label?: string
  wan_intf?: string
  listen_interfaces?: string[]
  primary_pool?: string
  ip_pools?: string[]
  portals_count?: number
  ssl_policies_count?: number
  referenced_groups?: string[]
  warnings?: string[]
  infos?: string[]
  ssl_policies?: SslToIpsecPolicyRow[]
  gui_rows?: SslToIpsecGuiRow[]
  cli_draft?: string
  forticlient_rows?: SslToIpsecClientRow[]
  cutover_rows?: SslToIpsecCutoverRow[]
}
