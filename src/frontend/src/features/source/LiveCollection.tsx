import { useState } from 'react'
import { postJson } from '../../api/client'
import { Button } from '../../components/common/Button'
import { ErrorBanner } from '../../components/common/ErrorBanner'
import type { CollectionField, SourcePreviewData, SourceVendorOption } from './types'

export type CollectionResult = {
  vendor_id?: string
  preview: SourcePreviewData
  collection: { status: string; warnings?: string[]; method?: string; vendor?: string }
  snapshot: import('../../storage/workspaceTypes').SourceEvidence
}

export function LiveCollection({ vendor, onCollected }: {
  vendor: SourceVendorOption | undefined
  onCollected: (result: CollectionResult) => void
}) {
  const [values, setValues] = useState<Record<string, string | boolean>>({})
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [snapshot, setSnapshot] = useState<unknown>(null)
  const fields = vendor?.live_collection ? vendor.collection?.connection_fields || [] : []
  if (!fields.length) return null

  async function request(path: string) {
    setBusy(true); setError(null)
    try {
      const result = await postJson<CollectionResult | { status: string }>(path, {
        vendor: vendor?.vendor_id,
        connection: Object.fromEntries(fields.map((field) => [field.name, values[field.name] ?? field.default ?? (field.type === 'checkbox' ? false : '')])),
      })
      if (path.endsWith('/collect')) {
        const collected = result as CollectionResult
        onCollected(collected)
        setSnapshot(collected.snapshot ?? null)
        if (collected.snapshot) downloadSnapshot(collected.snapshot)
        setStatus(`Collected configuration (${collected.collection.status}). ${collected.collection.warnings?.length || 0} warnings.`)
      } else setStatus('Connection successful.')
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Collection failed') }
    finally {
      setBusy(false)
      setValues((current) => Object.fromEntries(Object.entries(current).map(([key, value]) => [key, /password|token|secret|key/i.test(key) ? '' : value])))
    }
  }

  function downloadSnapshot(content = snapshot) {
    if (!content) return
    const url = URL.createObjectURL(new Blob([JSON.stringify(content, null, 2)], { type: 'application/json' }))
    const link = document.createElement('a')
    link.href = url
    link.download = `firewall_snapshot_${vendor?.vendor_id || 'source'}_${new Date().toISOString().replace(/[:.]/g, '-')}.json`
    link.click()
    URL.revokeObjectURL(url)
  }

  return <div className="live-collection-fields" aria-label="Live collection">
    <details className="collection-guide"><summary>ⓘ Collection guide</summary><p>Test Connection checks access. Collect retrieves source configuration, prepares a preview, and downloads a reusable JSON snapshot. It does not change the device.</p><p>{vendor?.collection?.method || 'Collection method'} · Credentials are cleared from the form after each request.</p></details>
    <div className="collection-grid">{fields.map((field: CollectionField) => <label className="field" key={field.name}>
      {field.label}{field.required ? ' *' : ''}
      {field.type === 'checkbox' ? <input type="checkbox" checked={Boolean(values[field.name] ?? field.default)} onChange={(event) => setValues({ ...values, [field.name]: event.target.checked })} />
        : field.options ? <select required={field.required} value={String(values[field.name] ?? field.default ?? '')} onChange={(event) => setValues({ ...values, [field.name]: event.target.value })}>
          <option value="">Select…</option>{field.options.map((option) => <option key={option}>{option}</option>)}
        </select> : <input type={field.type === 'password' ? 'password' : field.type === 'number' ? 'number' : 'text'} required={field.required} autoComplete={field.type === 'password' ? 'new-password' : 'off'} value={String(values[field.name] ?? field.default ?? '')} onChange={(event) => setValues({ ...values, [field.name]: event.target.value })} />}
    </label>)}</div>
    <div className="action-row"><Button disabled={busy} onClick={() => void request('/api/collection/test')}>Test Connection</Button><Button disabled={busy} onClick={() => void request('/api/collection/collect')}>Collect &amp; Download Snapshot</Button></div>
    {snapshot !== null && <Button disabled={busy} onClick={downloadSnapshot}>Download reusable snapshot</Button>}
    {status && <p role="status">{status}</p>}{error && <ErrorBanner message={error} />}
  </div>
}
