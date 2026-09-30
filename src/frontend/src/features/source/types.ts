export type SourceVendor = string
export type CollectionField = { name: string; label: string; type: string; required?: boolean; default?: unknown; options?: string[] }
export type SourceVendorOption = {
  vendor_id: SourceVendor
  display_name: string
  file_extensions: string[]
  live_collection?: boolean
  collection?: { method: string; connection_fields: CollectionField[] } | null
}
export type SourcePreviewData = {
  preview_id?: string
  vendor?: string
  summary?: Record<string, unknown>
  sections?: Record<string, unknown>
  [key: string]: unknown
}
