import { useEffect, useRef, useState } from 'react'
import { Button } from '../../../components/common/Button'
import { ErrorBanner } from '../../../components/common/ErrorBanner'
import { FileUpload } from '../../source/FileUpload'
import { prepareSetReview } from '../migrationApi'
import type { SetReview } from '../migrationApi'

export function MigrationSetUpload({ host, port, busy, approved, canPrepare, onInvalidate, onPrepare }: {
  host: string; port: string; busy: boolean; approved: boolean; canPrepare: boolean
  onInvalidate: () => void; onPrepare: (review: SetReview) => void
}) {
  const [file, setFile] = useState<File | null>(null)
  const [target, setTarget] = useState<File | null>(null)
  const [device, setDevice] = useState('')
  const [devices, setDevices] = useState<string[]>([])
  const [reviewState, setReviewState] = useState<{ context: string; review: SetReview | null } | null>(null)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const version = useRef(0)
  const context = JSON.stringify([host, port])
  const review = reviewState?.context === context ? reviewState.review : null
  useEffect(() => {
    version.current++
    // A changed connection cancels any upload review still in flight.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setLoading(false)
    // This ref is a request counter, not a DOM node.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    return () => { version.current++ }
  }, [context])

  function invalidate() {
    version.current++
    setReviewState(null); setPage(1); setError(''); setLoading(false)
    onInvalidate()
  }
  async function reviewFile() {
    if (!file || !target || busy || loading) return
    const request = ++version.current
    setLoading(true); setError(''); setReviewState(null); setPage(1)
    onInvalidate()
    const form = new FormData()
    form.append('file', file); form.append('target_file', target)
    form.append('target_device', device); form.append('host', host); form.append('port', port)
    try {
      const result = await prepareSetReview(form)
      if (request !== version.current) return
      setDevices(result.devices)
      setReviewState({ context, review: result.review })
      if (result.review) setDevice(result.review.context.target_device)
    } catch (cause) {
      if (request === version.current) setError(cause instanceof Error ? cause.message : 'Could not review uploaded commands.')
    } finally { if (request === version.current) setLoading(false) }
  }
  const currentPage = Math.min(page, Math.max(1, Math.ceil((review?.command_count ?? 0) / 50)))
  return <section className="panel migration-set-upload" aria-label="Upload PAN-OS commands">
    <h2>Upload .set file</h2>
    <p>Upload ordinary PAN-OS commands and actual destination XML. Review does not push commands. Supported configuration paths only; secrets, session commands and Panorama wrappers are excluded.</p>
    <FileUpload file={file} accept=".set,text/plain" title="Choose PAN-OS .set file" disabled={busy || loading}
      onChange={(value) => { invalidate(); setFile(value) }} />
    <FileUpload file={target} accept=".xml,application/xml,text/xml" title="Choose actual destination XML" disabled={busy || loading}
      onChange={(value) => { invalidate(); setTarget(value); setDevice(''); setDevices([]) }} />
    {devices.length > 1 && <label className="field">Destination device<select value={device} disabled={busy || loading} onChange={(event) => { invalidate(); setDevice(event.target.value) }}><option value="">Select a device</option>{devices.map((name) => <option key={name}>{name}</option>)}</select></label>}
    <Button disabled={busy || loading || !file || !target || !host.trim() || !port} onClick={() => void reviewFile()}>{loading ? 'Checking upload…' : 'Review uploaded commands'}</Button>
    {devices.length > 1 && !device && <p role="status">Select a destination device, then review again.</p>}
    {error && <ErrorBanner message={error} />}
    {review && <section aria-label="Uploaded command review">
      <h3>{review.filename} · {review.command_count.toLocaleString()} {review.command_count === 1 ? 'command' : 'commands'}</h3>
      <p>Destination: {review.context.host}:{review.context.port} · {review.context.target_device} · serial {review.context.target_serial}</p>
      <p>These commands can modify existing configuration. Syntax checks and your review do not establish migration coverage, references, capacity or licensing. Candidate validation follows preparation.</p>
      <pre className="set-command-preview">{review.commands.slice((currentPage - 1) * 50, currentPage * 50).map((command, index) => `${review.line_numbers[(currentPage - 1) * 50 + index]}: ${command}`).join('\n')}</pre>
      {review.command_count > 50 && <div className="report-pager"><Button disabled={currentPage === 1} onClick={() => setPage(currentPage - 1)}>Previous commands</Button><span>Page {currentPage} of {Math.ceil(review.command_count / 50)}</span><Button disabled={currentPage * 50 >= review.command_count} onClick={() => setPage(currentPage + 1)}>Next commands</Button></div>}
      <details><summary>Review identity</summary><p>Command SHA-256: {review.command_sha256}</p><p>File SHA-256: {review.file_sha256}</p><p>Review expires {new Date(review.expires_at * 1000).toLocaleString()}.</p></details>
      {!approved && <Button disabled={busy || loading || !canPrepare} onClick={() => onPrepare(review)}>Approve and prepare candidate</Button>}
      {!approved && !canPrepare && <p>Enter your SSH username and password to prepare the reviewed commands.</p>}
    </section>}
  </section>
}
