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

export function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  return fetch(path, init)
}

async function readJsonResponse(response: Response): Promise<unknown> {
  try {
    return await response.json()
  } catch (cause) {
    if (!(cause instanceof SyntaxError)) throw cause
    // Proxy error pages and truncated JSON are not trusted diagnostic text.
    throw new RequestError(response.ok
      ? { error: `Server returned an invalid JSON response (${response.status})` }
      : null, response.status)
  }
}

export async function postForm<T>(path: string, formData: FormData): Promise<T> {
  const response = await apiFetch(path, { method: 'POST', body: formData })
  const data = await readJsonResponse(response)

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
  const data = await readJsonResponse(response)
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
    const data = await readJsonResponse(response)
    throw new RequestError(data, response.status)
  }
  return response.blob()
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}
