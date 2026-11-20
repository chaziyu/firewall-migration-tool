export interface DesktopSaveResult {
  saved: boolean
  cancelled?: boolean
  path?: string
  filename?: string
  error?: string
}

export interface PyWebViewApi {
  save_file?: (filename: string, contentBase64: string) => Promise<DesktopSaveResult>
}

declare global {
  interface Window {
    pywebview?: {
      api?: PyWebViewApi
    }
  }
}

export function getDesktopApi(): PyWebViewApi | undefined {
  return typeof window !== 'undefined' ? window.pywebview?.api : undefined
}

async function blobToBase64(blob: Blob): Promise<string> {
  const bytes = new Uint8Array(await blob.arrayBuffer())
  const chunks: string[] = []
  const chunkSize = 0x8000
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    chunks.push(String.fromCharCode(...bytes.subarray(offset, offset + chunkSize)))
  }
  return btoa(chunks.join(''))
}

export async function saveBlobWithFallback(
  blob: Blob,
  filename: string,
): Promise<{ status: 'saved' | 'cancelled' | 'downloaded'; filename: string }> {
  const saveFile = getDesktopApi()?.save_file
  if (saveFile) {
    const contentBase64 = await blobToBase64(blob)
    const result = await saveFile(filename, contentBase64)
    if (result?.cancelled) return { status: 'cancelled', filename }
    if (!result?.saved) throw new Error(result?.error || 'Could not save file')
    return { status: 'saved', filename: result.filename || filename }
  }

  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.append(link)
  try {
    link.click()
  } finally {
    link.remove()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
  return { status: 'downloaded', filename }
}
