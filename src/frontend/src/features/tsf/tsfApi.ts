import { apiFetch, postForm, RequestError } from '../../api/client'
import type {
  TsfFileResponse,
  TsfProgressResponse,
  TsfSearchResponse,
  TsfStatusResponse,
  TsfTreeResponse,
  TsfUploadResponse,
} from './types'

async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await apiFetch(path, { method: 'GET', signal })
  let data: unknown
  try {
    data = await response.json()
  } catch {
    throw new RequestError(null, response.status)
  }
  if (!response.ok || (typeof data === 'object' && data !== null && (data as Record<string, unknown>).success === false && !('is_binary' in data))) {
    throw new RequestError(data, response.status)
  }
  return data as T
}

export function uploadTsfArchive(file: File): Promise<TsfUploadResponse> {
  const form = new FormData()
  form.append('file', file)
  return postForm<TsfUploadResponse>('/api/tsf/upload', form)
}

export function fetchTsfProgress(jobId: string, signal?: AbortSignal): Promise<TsfProgressResponse> {
  return getJson<TsfProgressResponse>(`/api/tsf/progress/${encodeURIComponent(jobId)}`, signal)
}

export function fetchTsfStatus(sessionId: string, signal?: AbortSignal): Promise<TsfStatusResponse> {
  return getJson<TsfStatusResponse>(`/api/tsf/status?session_id=${encodeURIComponent(sessionId)}`, signal)
}

export function fetchTsfTree(sessionId: string, path = '', signal?: AbortSignal): Promise<TsfTreeResponse> {
  return getJson<TsfTreeResponse>(
    `/api/tsf/tree?session_id=${encodeURIComponent(sessionId)}&path=${encodeURIComponent(path)}`,
    signal,
  )
}

export function fetchTsfFile(
  sessionId: string,
  path: string,
  page = 0,
  jumpLine = 0,
  signal?: AbortSignal,
): Promise<TsfFileResponse> {
  const params = new URLSearchParams({
    session_id: sessionId,
    path,
    page: String(page),
    jump_line: String(jumpLine),
  })
  return getJson<TsfFileResponse>(`/api/tsf/file?${params.toString()}`, signal)
}

export function searchTsf(
  sessionId: string,
  mode: 'filename' | 'content',
  query: string,
  signal?: AbortSignal,
): Promise<TsfSearchResponse> {
  const params = new URLSearchParams({
    session_id: sessionId,
    mode,
    q: query,
  })
  return getJson<TsfSearchResponse>(`/api/tsf/search?${params.toString()}`, signal)
}

export async function downloadTsfFile(sessionId: string, path: string): Promise<Blob> {
  const params = new URLSearchParams({ session_id: sessionId, path })
  const response = await apiFetch(`/api/tsf/download?${params.toString()}`, { method: 'GET' })
  if (!response.ok) {
    let data: unknown
    try {
      data = await response.json()
    } catch {
      data = null
    }
    throw new RequestError(data, response.status)
  }
  return response.blob()
}

export async function deleteTsfSession(sessionId: string): Promise<void> {
  await apiFetch(`/api/tsf/session/${encodeURIComponent(sessionId)}`, { method: 'DELETE' })
}
