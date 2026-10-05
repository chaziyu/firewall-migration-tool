import { useEffect, useRef, useState } from 'react'
import type { Update } from '@tauri-apps/plugin-updater'
import { checkForUpdate, installedVersion, installUpdate, type UpdateStatus } from './desktopUpdater'

export function UpdateControl() {
  const [version, setVersion] = useState('')
  const [status, setStatus] = useState<UpdateStatus>({ kind: 'idle' })
  const update = useRef<Update | null>(null)
  const busy = useRef(false)
  const mounted = useRef(false)

  useEffect(() => {
    mounted.current = true
    installedVersion().then((value) => { if (mounted.current) setVersion(value) })
      .catch(() => { if (mounted.current) setStatus({ kind: 'error', message: 'Could not read desktop version.' }) })
    return () => { mounted.current = false; void update.current?.close().catch(() => {}); update.current = null }
  }, [])

  async function run(install = false) {
    if (busy.current) return
    busy.current = true
    try {
      if (install && update.current) {
        await installUpdate(update.current, (next) => { if (mounted.current) setStatus(next) })
      } else {
        setStatus({ kind: 'checking' })
        await update.current?.close()
        update.current = null
        const available = await checkForUpdate()
        if (!mounted.current) { await available?.close(); return }
        update.current = available
        setStatus(available ? { kind: 'available', version: available.version, notes: available.body || 'No release notes provided.' } : { kind: 'up-to-date' })
      }
    } catch {
      if (mounted.current) setStatus({ kind: 'error', message: 'Update failed. Check your connection and release signing, then retry.' })
      await update.current?.close().catch(() => {})
      update.current = null
    } finally { busy.current = false }
  }

  const working = ['checking', 'downloading', 'installing'].includes(status.kind)
  return <section className="sidebar-foot desktop-update" aria-label="Desktop updates">
    <p>Desktop{version && ` v${version}`}</p>
    <div role="status" aria-live="polite">
      {status.kind === 'up-to-date' && <p>You are up to date.</p>}
      {status.kind === 'checking' && <p>Checking for updates…</p>}
      {status.kind === 'downloading' && <p>Downloading… {status.percent === undefined ? '' : `${status.percent}%`}</p>}
      {status.kind === 'installing' && <p>Verifying and installing… The app will restart.</p>}
      {status.kind === 'error' && <p>{status.message}</p>}
    </div>
    {status.kind === 'available' && <>
      <p>Version {status.version} available</p>
      <p className="update-notes">{status.notes}</p>
      <p>Save your work before installing. The app will close and restart.</p>
      <button type="button" className="secondary-button" onClick={() => void run(true)}>Download and install</button>
      <button type="button" className="secondary-button" onClick={() => {
        if (busy.current) return
        void update.current?.close().catch(() => {}); update.current = null; setStatus({ kind: 'idle' })
      }}>Later</button>
    </>}
    {status.kind !== 'available' && <button type="button" className="secondary-button" disabled={working} onClick={() => void run()}>Check for updates</button>}
  </section>
}
