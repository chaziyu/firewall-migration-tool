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
