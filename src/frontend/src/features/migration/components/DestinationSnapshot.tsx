import { useEffect, useRef, useState } from 'react'
import { Button } from '../../../components/common/Button'
import type { SourceEvidence } from '../../../storage/workspaceTypes'
import { FileUpload } from '../../source/FileUpload'
import { previewSource } from '../../source/sourceApi'
import type { SourceVendor } from '../../source/types'

export type DestinationEvidence = {
  source: SourceEvidence
  metadata: { context: string; version: string; mode: string; complete_families: string[] }
}

export function DestinationSnapshot({ vendor, families, value, disabled, onChange, onPendingChange }: {
  vendor: SourceVendor
  families: readonly string[]
  value: DestinationEvidence | null
  disabled: boolean
  onChange: (value: DestinationEvidence | null) => void
  onPendingChange: (pending: boolean) => void
}) {
  const [file, setFile] = useState<File | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const requests = useRef(0)
  useEffect(() => () => { requests.current++; onPendingChange(false) }, [onPendingChange])

  async function upload(next: File | null) {
    const request = ++requests.current
    const metadata = value?.metadata ?? { context: '', version: '', mode: '', complete_families: [] }
    onChange(null)
    setFile(null)
    setError(null)
    setLoading(Boolean(next))
    onPendingChange(Boolean(next))
    if (!next) return
    try {
      const result = await previewSource(next, vendor)
      if (request !== requests.current) return
      if (!result.source_evidence) throw new Error('The destination snapshot could not be sanitized')
      setFile(next)
      onChange({ source: result.source_evidence, metadata })
    } catch (cause) {
      if (request === requests.current) setError(cause instanceof Error ? cause.message : 'Destination upload failed')
    } finally {
      if (request === requests.current) { setLoading(false); onPendingChange(false) }
    }
  }

  return <section aria-label="Destination snapshot">
    <h3>Optional destination snapshot</h3>
    <p>Compare a configuration export. Declare only complete configuration families. This does not verify the live device.</p>
    <FileUpload title="Upload destination snapshot" file={file} disabled={disabled} onChange={(next) => { void upload(next) }} />
    {loading && <p role="status">Analyzing destination snapshot…</p>}
    {error && <p role="alert">{error}</p>}
    {value && <>
      <p>Loaded: {value.source.source_name || 'Destination configuration'}</p>
      {(['context', 'version', 'mode'] as const).map((field) => <label className="field" key={field}>
        Snapshot {field}<input disabled={disabled || loading} value={value.metadata[field]} onChange={(event) => onChange({ ...value, metadata: { ...value.metadata, [field]: event.target.value } })} />
      </label>)}
      <fieldset disabled={disabled || loading}><legend>Complete configuration families</legend>
        {families.map((family) => <label key={family}><input type="checkbox" checked={value.metadata.complete_families.includes(family)} onChange={(event) => onChange({ ...value, metadata: { ...value.metadata, complete_families: event.target.checked ? [...value.metadata.complete_families, family] : value.metadata.complete_families.filter((item) => item !== family) } })} />{family.replaceAll('_', ' ')}</label>)}
      </fieldset>
      <Button disabled={disabled} onClick={() => { void upload(null) }}>Remove destination evidence</Button>
    </>}
  </section>
}
