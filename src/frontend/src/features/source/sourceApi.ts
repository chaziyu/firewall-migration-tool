import { apiFetch, postBlob, postForm } from '../../api/client'
import type { SourcePreviewData, SourceVendor, SourceVendorOption } from './types'

export async function loadSourceVendors(): Promise<SourceVendorOption[]> {
  const response = await apiFetch('/api/vendors')
  const data: unknown = await response.json()
  if (!response.ok || !isVendorResponse(data)) {
    const message = typeof data === 'object' && data !== null && 'error' in data && typeof data.error === 'string'
      ? data.error
      : 'Could not load vendors'
    throw new Error(message)
  }
  return data.sources
}

function isVendorResponse(value: unknown): value is { sources: SourceVendorOption[] } {
  return typeof value === 'object' && value !== null && 'sources' in value && Array.isArray(value.sources)
    && value.sources.every((vendor: unknown) => typeof vendor === 'object' && vendor !== null
      && 'vendor_id' in vendor && typeof vendor.vendor_id === 'string'
      && 'display_name' in vendor && typeof vendor.display_name === 'string'
      && 'file_extensions' in vendor && Array.isArray(vendor.file_extensions)
      && vendor.file_extensions.every((extension: unknown) => typeof extension === 'string'))
}

export function previewSource(file: File, vendor: SourceVendor) {
  const formData = new FormData()
  formData.append('file', file)
  formData.append('source_vendor', vendor)
  return postForm<SourcePreviewData>('/api/preview', formData)
}

export function downloadSourceWorkbook(vendor: SourceVendor, source: import('../../storage/workspaceTypes').SourceEvidence, profile: 'fast' | 'full') {
  return postBlob('/api/extract/excel', {
    source_vendor: vendor,
    source,
    excel_profile: profile,
  })
}

export function importCollectionSnapshot(file: File) {
  const formData = new FormData()
  formData.append('file', file)
  return postForm<{
    snapshot: import('../../storage/workspaceTypes').SourceEvidence
    vendor_id: SourceVendor
    preview: SourcePreviewData
    collection: { status: string; warnings: string[] }
  }>('/api/collection/snapshot/import', formData)
}
