import { isDesktopRuntime } from '../../api/client.ts'
import type { DownloadEvent, Update } from '@tauri-apps/plugin-updater'

export type UpdateStatus =
  | { kind: 'idle' | 'checking' | 'up-to-date' | 'installing' }
  | { kind: 'available'; version: string; notes: string }
  | { kind: 'downloading'; percent?: number }
  | { kind: 'error'; message: string }

export async function installedVersion(): Promise<string> {
  if (!isDesktopRuntime()) throw new Error('Desktop updates are unavailable in the browser.')
  const { getVersion } = await import('@tauri-apps/api/app')
  return getVersion()
}

// Accept only static GitHub Releases metadata for this repository and Windows x64.
export function validateUpdate(update: Update): void {
  const platforms = update.rawJson.platforms as Record<string, unknown> | undefined
  const platform = platforms?.['windows-x86_64'] as Record<string, unknown> | undefined
  if (!platform || typeof platform.url !== 'string' || typeof platform.signature !== 'string' || !platform.signature.trim()) {
    throw new Error('Invalid update metadata. Installation blocked.')
  }
  const url = new URL(platform.url)
  if (url.origin !== 'https://github.com' || url.username || url.password || url.search || url.hash ||
      !/^\/chaziyu\/firewall-migration-tool\/releases\/download\/desktop-v[^/]+\/[^/]+-setup\.exe$/.test(url.pathname) ||
      !url.pathname.startsWith(`/chaziyu/firewall-migration-tool/releases/download/desktop-v${update.version}/`) ||
      !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(update.version)) {
    throw new Error('Invalid update source or version. Installation blocked.')
  }
}

export async function checkForUpdate(): Promise<Update | null> {
  if (!isDesktopRuntime()) throw new Error('Desktop updates are unavailable in the browser.')
  const { invoke } = await import('@tauri-apps/api/core')
  const { Update } = await import('@tauri-apps/plugin-updater')
  // Native check pins the source and attaches sidecar cleanup to verified installation.
  const metadata = await invoke<ConstructorParameters<typeof Update>[0] | null>('check_desktop_update')
  const update = metadata ? new Update(metadata) : null
  if (update) {
    try { validateUpdate(update) }
    catch (error) { await update.close(); throw error }
  }
  return update
}

export async function installUpdate(update: Update, onStatus: (status: UpdateStatus) => void): Promise<void> {
  if (!isDesktopRuntime()) throw new Error('Desktop updates are unavailable in the browser.')
  validateUpdate(update)
  let downloaded = 0
  let total: number | undefined
  onStatus({ kind: 'downloading' })
  await update.downloadAndInstall((event: DownloadEvent) => {
    if (event.event === 'Started') { downloaded = 0; total = event.data.contentLength }
    if (event.event === 'Progress') downloaded += event.data.chunkLength
    // Finished precedes signature verification; only the plugin may install verified bytes.
    onStatus(event.event === 'Finished' ? { kind: 'installing' } : {
      kind: 'downloading', percent: total && total > 0 ? Math.min(100, Math.floor(downloaded / total * 100)) : undefined,
    })
  }, { timeout: 30_000, restartAfterInstall: true })
}
