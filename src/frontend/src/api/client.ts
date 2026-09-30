export async function postForm<T>(path: string, formData: FormData): Promise<T> {
  const response = await fetch(path, { method: 'POST', body: formData })
  const data: unknown = await response.json()

  if (!response.ok || (isRecord(data) && data.success === false)) {
    const message = isRecord(data) && typeof data.error === 'string'
      ? data.error
      : `Request failed (${response.status})`
    throw new Error(message)
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
    const message = isRecord(data) && typeof data.error === 'string'
      ? data.error
      : `Request failed (${response.status})`
    throw new Error(message)
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
    const message = isRecord(data) && typeof data.error === 'string'
      ? data.error
      : `Request failed (${response.status})`
    throw new Error(message)
  }
  return response.blob()
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}
