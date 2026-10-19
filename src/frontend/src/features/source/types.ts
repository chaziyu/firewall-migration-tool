export type SourceVendor = string
export type CollectionField = { name: string; label: string; type: string; required?: boolean; default?: unknown; options?: string[] }
export type SourceVendorOption = {
  vendor_id: SourceVendor
  display_name: string
  file_extensions: string[]
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
export type SourcePreviewData = {
  source_evidence?: import('../../storage/workspaceTypes').SourceEvidence
  source_digest?: string
  vendor?: string
  summary?: Record<string, unknown>
  sections?: Record<string, unknown>
  [key: string]: unknown
}
