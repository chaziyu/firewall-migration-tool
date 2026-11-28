import { apiFetch, postBlob, postForm, postJson, RequestError } from '../../api/client'
import type { SourceEvidence } from '../../storage/workspaceTypes'
import type {
  ConfigDiffResponse,
  ExposureProbeResponse,
  LifecycleCardData,
  LifecycleRefreshParams,
  PacketTraceRequest,
  PacketTraceResponse,
  PmChecklistResponse,
  PolicyLookupRequest,
  PolicyLookupResponse,
  RouteLookupRequest,
  RouteLookupResponse,
  SecurityAuditResponse,
  SourcePreviewData,
  SourceVendor,
  SourceVendorOption,
  SslToIpsecResponse,
  WhereUsedResponse,
} from './types'
export { loadMigrationPairs } from '../migration/pairApi'

const sourceDigestRegistry = new WeakMap<object, string>()

export function rememberSourceDigest(source: SourceEvidence | null | undefined, digest: string | null | undefined): void {
  if (source && typeof source === 'object' && typeof digest === 'string' && /^[0-9a-f]{64}$/.test(digest)) {
    sourceDigestRegistry.set(source, digest)
  }
}

function getSourceDigest(source: SourceEvidence | null | undefined): string | undefined {
  return source && typeof source === 'object' ? sourceDigestRegistry.get(source) : undefined
}

function isSourceExpiredError(error: unknown): boolean {
  return error instanceof RequestError && (error.status === 410 || error.details.error_code === 'source_expired')
}

async function postSourceJson<T>(
  path: string,
  vendor: SourceVendor,
  source: SourceEvidence,
  extra: Record<string, unknown> = {},
): Promise<T> {
  const digest = getSourceDigest(source)
  if (!digest) {
    return postJson<T>(path, { source_vendor: vendor, source, ...extra })
  }
  try {
    return await postJson<T>(path, {
      source_vendor: vendor,
      source_digest: digest,
      ...(source.source_name ? { source_name: source.source_name } : {}),
      ...extra,
    })
  } catch (error) {
    if (!isSourceExpiredError(error)) throw error
    sourceDigestRegistry.delete(source)
    return postJson<T>(path, { source_vendor: vendor, source, ...extra })
  }
}

async function postSourceBlob(
  path: string,
  vendor: SourceVendor,
  source: SourceEvidence,
  extra: Record<string, unknown>,
  options: Parameters<typeof postBlob>[2],
): Promise<Blob> {
  const digest = getSourceDigest(source)
  if (!digest) {
    return postBlob(path, { source_vendor: vendor, source, ...extra }, options)
  }
  try {
    return await postBlob(path, {
      source_vendor: vendor,
      source_digest: digest,
      ...(source.source_name ? { source_name: source.source_name } : {}),
      ...extra,
    }, options)
  } catch (error) {
    if (!isSourceExpiredError(error)) throw error
    sourceDigestRegistry.delete(source)
    return postBlob(path, { source_vendor: vendor, source, ...extra }, options)
  }
}

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
  return postForm<SourcePreviewData>('/api/preview', formData).then((result) => {
    rememberSourceDigest(result.source_evidence, result.source_digest)
    return result
  })
}

export function downloadSourceWorkbook(vendor: SourceVendor, source: SourceEvidence, profile: 'fast' | 'full', signal?: AbortSignal) {
  return postSourceBlob('/api/extract/excel', vendor, source, {
    excel_profile: profile,
  }, { signal, contentTypes: ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/octet-stream'], requireNonEmpty: true })
}

export function importCollectionSnapshot(file: File) {
  const formData = new FormData()
  formData.append('file', file)
  return postForm<{
    snapshot: SourceEvidence
    vendor_id: SourceVendor
    preview: SourcePreviewData
    collection: { status: string; warnings: string[] }
  }>('/api/collection/snapshot/import', formData).then((result) => {
    rememberSourceDigest(result.snapshot, result.preview?.source_digest)
    rememberSourceDigest(result.preview?.source_evidence, result.preview?.source_digest)
    return result
  })
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
  source: SourceEvidence,
  query: string,
): Promise<WhereUsedResponse> {
  return postSourceJson<WhereUsedResponse>('/api/source/where-used', vendor, source, { query })
}

export function fetchSecurityAudit(
  vendor: SourceVendor,
  source: SourceEvidence,
): Promise<SecurityAuditResponse> {
  return postSourceJson<SecurityAuditResponse>('/api/source/audit', vendor, source)
}

export function probePublicExposure(
  vendor: SourceVendor,
  source: SourceEvidence,
): Promise<ExposureProbeResponse> {
  return postSourceJson<ExposureProbeResponse>('/api/source/exposure-probe', vendor, source)
}

export function fetchPmLookup(
  vendor: SourceVendor,
  source: SourceEvidence,
): Promise<PmChecklistResponse> {
  return postSourceJson<PmChecklistResponse>('/api/source/pm-lookup', vendor, source)
}

export function downloadPmLookupExcel(
  vendor: SourceVendor,
  source: SourceEvidence,
  signal?: AbortSignal,
): Promise<Blob> {
  return postSourceBlob('/api/source/pm-lookup/export', vendor, source, {}, {
    signal,
    contentTypes: ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/octet-stream'],
    requireNonEmpty: true,
  })
}

export function runPolicyLookup(
  vendor: SourceVendor,
  source: SourceEvidence,
  params: PolicyLookupRequest,
): Promise<PolicyLookupResponse> {
  return postSourceJson<PolicyLookupResponse>('/api/source/policy-lookup', vendor, source, { ...params })
}

export function runRouteLookup(
  vendor: SourceVendor,
  source: SourceEvidence,
  params: RouteLookupRequest,
): Promise<RouteLookupResponse> {
  return postSourceJson<RouteLookupResponse>('/api/source/route-lookup', vendor, source, { ...params })
}

export function runPacketTrace(
  vendor: SourceVendor,
  source: SourceEvidence,
  params: PacketTraceRequest,
): Promise<PacketTraceResponse> {
  return postSourceJson<PacketTraceResponse>('/api/source/packet-trace', vendor, source, { ...params })
}

export async function runConfigDiff(
  vendor: SourceVendor,
  source: SourceEvidence,
  compareFile: File,
): Promise<ConfigDiffResponse> {
  const digest = getSourceDigest(source)
  if (digest) {
    const formData = new FormData()
    formData.append('source_vendor', vendor)
    formData.append('source_digest', digest)
    if (source.source_name) formData.append('source_name', source.source_name)
    formData.append('compare_file', compareFile)
    try {
      return await postForm<ConfigDiffResponse>('/api/source/config-diff', formData)
    } catch (error) {
      if (!isSourceExpiredError(error)) throw error
      sourceDigestRegistry.delete(source)
    }
  }
  const formData = new FormData()
  formData.append('source_vendor', vendor)
  formData.append('source', JSON.stringify(source))
  formData.append('compare_file', compareFile)
  return postForm<ConfigDiffResponse>('/api/source/config-diff', formData)
}

export function fetchSslToIpsec(
  vendor: SourceVendor,
  source: SourceEvidence,
  vdom?: string,
): Promise<SslToIpsecResponse> {
  return postSourceJson<SslToIpsecResponse>('/api/source/ssl-to-ipsec', vendor, source, vdom ? { vdom } : {})
}
