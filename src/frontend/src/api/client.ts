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

export async function postForm<T>(path: string, formData: FormData): Promise<T> {
  const response = await fetch(path, { method: 'POST', body: formData })
  const data: unknown = await response.json()

  if (!response.ok || (isRecord(data) && data.success === false)) {
    throw new RequestError(data, response.status)
  }

  return data as T
}

export async function postJson<T>(path: string, payload: unknown): Promise<T> {
  const response = await fetch(path, {
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
  const response = await fetch(path, {
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
