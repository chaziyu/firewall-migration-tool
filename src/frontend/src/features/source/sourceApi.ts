import { apiFetch, postBlob, postForm, postJson } from '../../api/client'
import type {
  ExposureProbeResponse,
  LifecycleCardData,
  LifecycleRefreshParams,
  PmChecklistResponse,
  SecurityAuditResponse,
  SourcePreviewData,
  SourceVendor,
  SourceVendorOption,
  WhereUsedResponse,
} from './types'
export { loadMigrationPairs } from '../migration/pairApi'

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

export function downloadSourceWorkbook(vendor: SourceVendor, source: import('../../storage/workspaceTypes').SourceEvidence, profile: 'fast' | 'full', signal?: AbortSignal) {
  return postBlob('/api/extract/excel', {
    source_vendor: vendor,
    source,
    excel_profile: profile,
  }, { signal, contentTypes: ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/octet-stream'], requireNonEmpty: true })
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

export async function fetchLifecycleStatus(
  params: LifecycleRefreshParams,
  signal?: AbortSignal,
): Promise<LifecycleCardData> {
  const query = new URLSearchParams()
  query.set('vendor', params.vendor)
  if (params.vendor === 'fortigate') {
    if (params.model) query.set('model', params.model)
    if (params.firmware) query.set('firmware', params.firmware)
  } else {
    if (params.version) query.set('version', params.version)
    if (typeof params.exact === 'boolean') query.set('exact', params.exact ? 'true' : 'false')
  }
  const response = await apiFetch(`/api/lifecycle?${query.toString()}`, { signal })
  const data = (await response.json()) as { success?: boolean; error?: string; lifecycle?: LifecycleCardData }
  if (!response.ok || data.success === false || !data.lifecycle) {
    throw new Error(data.error || 'Could not refresh lifecycle status')
  }
  return data.lifecycle
}

export function searchWhereUsed(
  vendor: SourceVendor,
  source: import('../../storage/workspaceTypes').SourceEvidence,
  query: string,
): Promise<WhereUsedResponse> {
  return postJson<WhereUsedResponse>('/api/source/where-used', {
    source_vendor: vendor,
    source,
    query,
  })
}

export function fetchSecurityAudit(
  vendor: SourceVendor,
  source: import('../../storage/workspaceTypes').SourceEvidence,
): Promise<SecurityAuditResponse> {
  return postJson<SecurityAuditResponse>('/api/source/audit', {
    source_vendor: vendor,
    source,
  })
}

export function probePublicExposure(
  vendor: SourceVendor,
  source: import('../../storage/workspaceTypes').SourceEvidence,
): Promise<ExposureProbeResponse> {
  return postJson<ExposureProbeResponse>('/api/source/exposure-probe', {
    source_vendor: vendor,
    source,
  })
}

export function downloadSecurityAuditReport(
  vendor: SourceVendor,
  source: import('../../storage/workspaceTypes').SourceEvidence,
  signal?: AbortSignal,
): Promise<Blob> {
  return postBlob('/api/source/audit-report', {
    source_vendor: vendor,
    source,
  }, {
    signal,
    contentTypes: ['text/html'],
    requireNonEmpty: true,
  })
}

export function fetchPmLookup(
  vendor: SourceVendor,
  source: import('../../storage/workspaceTypes').SourceEvidence,
): Promise<PmChecklistResponse> {
  return postJson<PmChecklistResponse>('/api/source/pm-lookup', {
    source_vendor: vendor,
    source,
  })
}

export function downloadPmLookupExcel(
  vendor: SourceVendor,
  source: import('../../storage/workspaceTypes').SourceEvidence,
  signal?: AbortSignal,
): Promise<Blob> {
  return postBlob('/api/source/pm-lookup/export', {
    source_vendor: vendor,
    source,
  }, {
    signal,
    contentTypes: ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/octet-stream'],
    requireNonEmpty: true,
  })
}
