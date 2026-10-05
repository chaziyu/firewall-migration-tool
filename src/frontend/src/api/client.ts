export class RequestError extends Error {
  readonly details: Record<string, unknown>

  constructor(data: unknown, status: number) {
    const details = isRecord(data) ? data : {}
    const result = isRecord(details.result) ? details.result : {}
    const validation = isRecord(result.validation) ? result.validation : result
    const messages = [details.error, result.failure_message, validation.response]
      .filter((value): value is string => typeof value === 'string' && value.length > 0)
    super([...new Set(messages)].join('\n') || `Request failed (${status})`)
    this.name = 'RequestError'
    this.details = details
  }
}

type DesktopRuntime = {
  apiBase: string
  token: string
}

const DESKTOP_TOKEN_HEADER = 'X-FWMigrate-Desktop-Token'

function desktopRuntime(): DesktopRuntime | null {
  const candidate = (globalThis as typeof globalThis & { __FWMIGRATE_DESKTOP__?: unknown }).__FWMIGRATE_DESKTOP__
  if (!isRecord(candidate) || typeof candidate.apiBase !== 'string' || typeof candidate.token !== 'string') return null
  if (!candidate.apiBase.startsWith('http://127.0.0.1:') || !candidate.token) return null
  return { apiBase: candidate.apiBase.replace(/\/$/, ''), token: candidate.token }
}

export function isDesktopRuntime(): boolean {
  return desktopRuntime() !== null
}

export function apiUrl(path: string): string {
  const runtime = desktopRuntime()
  return runtime && path.startsWith('/') ? `${runtime.apiBase}${path}` : path
}

export function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const runtime = desktopRuntime()
  const headers = new Headers(init.headers)
  if (runtime) headers.set(DESKTOP_TOKEN_HEADER, runtime.token)
  return fetch(apiUrl(path), { ...init, headers })
}

export async function postForm<T>(path: string, formData: FormData): Promise<T> {
  const response = await apiFetch(path, { method: 'POST', body: formData })
  const data: unknown = await response.json()

  if (!response.ok || (isRecord(data) && data.success === false)) {
    throw new RequestError(data, response.status)
  }

  return data as T
}

export async function postJson<T>(path: string, payload: unknown): Promise<T> {
  const response = await apiFetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  const data: unknown = await response.json()
  if (!response.ok || (isRecord(data) && data.success === false)) {
    throw new RequestError(data, response.status)
  }
  return data as T
}

export async function postBlob(path: string, payload: unknown): Promise<Blob> {
  const response = await apiFetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!response.ok) {
    const data: unknown = await response.json()
    throw new RequestError(data, response.status)
  }
  return response.blob()
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}
