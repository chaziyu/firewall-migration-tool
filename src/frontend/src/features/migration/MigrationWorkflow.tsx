import { useCallback, useEffect, useRef, useState } from 'react'
import { ErrorBanner } from '../../components/common/ErrorBanner'
import { Button } from '../../components/common/Button'
import type { SourcePreviewData } from '../source/types'
import type { MigrationDecisionDocument } from './types'
import {
  buildPlan, commitCandidate, deployArtifact, downloadBundle, downloadCommands, downloadFile,
  loadCommandPreview, validateCandidate,
} from './migrationApi'
import type { PlanArtifact } from './migrationApi'
import { PlanReview } from './PlanReview'

type Props = { preview: SourcePreviewData; previewId: string; decisionDocument: MigrationDecisionDocument | null; targetPreviewId: string; targetDevice: string; activeSection: 'plan' | 'live'; onViewChange: (view: 'live') => void; onReviewDecision: (key: string) => void }

export function MigrationWorkflow({ preview, previewId, decisionDocument, targetPreviewId, targetDevice, activeSection, onViewChange, onReviewDecision }: Props) {
  const [artifact, setArtifact] = useState<PlanArtifact | null>(null)
  const [commandText, setCommandText] = useState('')
  const [connection, setConnection] = useState({ host: '', port: '22', username: '', password: '' })
  const [sessionId, setSessionId] = useState('')
  const [candidateValidated, setCandidateValidated] = useState(false)
  const [status, setStatus] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [activityLog, setActivityLog] = useState(['[SYSTEM] Candidate workflow is ready. Prepare (push + validate) → explicit commit.'])
  const [autoScroll, setAutoScroll] = useState(true)
  const activityRef = useRef<HTMLDivElement>(null)
  const autoBuildStarted = useRef(false)
  const buildRequest = useRef(0)

  useEffect(() => () => { buildRequest.current++ }, [])

  const generatePlan = useCallback(async () => {
    if (!decisionDocument || preview.vendor !== 'fortigate') return
    const request = ++buildRequest.current
    setArtifact(null); setCommandText('')
    setBusy(true); setError(null); setStatus('Building migration plan…'); setSessionId(''); setCandidateValidated(false)
    setActivityLog((lines) => [...lines, '[PLAN] Building a plan from the current confirmed decisions.'])
    try {
      const result = await buildPlan(previewId, decisionDocument, targetPreviewId || undefined, targetDevice || undefined)
      if (request !== buildRequest.current) return
      setArtifact(result)
      if (result.commands > 0 || result.plan_status === 'READY_NO_CHANGES') {
        const commands = await loadCommandPreview(result.artifact_id)
        if (request !== buildRequest.current) return
        setCommandText(commands.command_text)
      }
      setStatus(`Plan status: ${result.plan_status}`)
      setActivityLog((lines) => [...lines, `[PLAN] ${result.plan_status}: ${result.commands} commands rendered.`])
    } catch (cause) {
      if (request !== buildRequest.current) return
      const message = cause instanceof Error ? cause.message : 'Migration planning failed'
      setError(message)
      setArtifact(null); setCommandText(''); setStatus('Plan generation failed.')
      setActivityLog((lines) => [...lines, `[ERROR] Plan generation failed: ${message}`])
    }
    finally { if (request === buildRequest.current) setBusy(false) }
  }, [decisionDocument, preview.vendor, previewId, targetPreviewId, targetDevice])

  useEffect(() => {
    if (preview.vendor === 'fortigate' && decisionDocument && !autoBuildStarted.current) {
      autoBuildStarted.current = true
      void generatePlan()
    }
  }, [preview.vendor, decisionDocument, generatePlan])

  useEffect(() => {
    if (autoScroll && activityRef.current) activityRef.current.scrollTop = activityRef.current.scrollHeight
  }, [activityLog, autoScroll])

  if (preview.vendor !== 'fortigate') return null

  function log(line: string) { setActivityLog((lines) => [...lines, line]) }

  async function runDeployment(action: 'prepare' | 'validate' | 'commit') {
    if (!artifact) return
    setBusy(true); setError(null)
    const credentials = { ...connection, port: Number(connection.port) }
    try {
      if (action === 'prepare') {
        log('[PREPARE] Pushing reviewed commands to the candidate configuration.')
        const result = await deployArtifact(artifact.artifact_id, credentials) as { deployment_session_id?: string; candidate_validated?: boolean; result?: { commands_succeeded?: number; validation?: { status?: string; response?: string } } }
        setSessionId(result.deployment_session_id || '')
        const validation = result.result?.validation
        const validated = result.candidate_validated === true && validation?.status === 'SUCCESS'
        setCandidateValidated(validated)
        setStatus(validated ? 'Candidate pushed and validated.' : 'Candidate preparation did not validate.')
        log(`[PREPARE] Pushed ${result.result?.commands_succeeded ?? 0} candidate commands.`)
        log(`[VALIDATE] Candidate ${String(validation?.status || 'unknown').toLowerCase()}: ${validation?.response || ''}`)
        if (!validated) throw new Error('Candidate preparation did not validate successfully.')
      } else if (action === 'validate' && sessionId) {
        log('[REVALIDATE] Checking the current candidate configuration.')
        const result = await validateCandidate(artifact.artifact_id, sessionId, credentials) as { deployment_session_id?: string; result?: { status?: string; response?: string } }
        setSessionId(result.deployment_session_id || '')
        const validated = Boolean(result.deployment_session_id && result.result?.status === 'SUCCESS')
        setCandidateValidated(validated)
        setStatus(validated ? 'Candidate validation succeeded.' : 'Candidate validation failed.')
        log(`[REVALIDATE] Candidate ${String(result.result?.status || 'unknown').toLowerCase()}: ${result.result?.response || ''}`)
      } else if (action === 'commit' && sessionId && window.confirm('Commit the validated candidate configuration?')) {
        const result = await commitCandidate(artifact.artifact_id, sessionId, credentials) as { result?: { job_id?: string } }
        setSessionId(''); setCandidateValidated(false); setStatus('Commit submitted.')
        log(`[COMMIT] Commit completed (job ${result.result?.job_id || 'unknown'}).`)
      }
    } catch (cause) {
      setSessionId(''); setCandidateValidated(false)
      const message = cause instanceof Error ? cause.message : 'Deployment action failed'
      setError(message)
      log(`[ERROR] ${action === 'prepare' ? 'Candidate preparation' : action === 'validate' ? 'Candidate revalidation' : 'Commit'} failed: ${message}`)
    }
    finally {
      setBusy(false)
      setConnection((current) => ({ ...current, password: '' }))
    }
  }

  async function saveArtifact(kind: 'bundle' | 'commands') {
    if (!artifact) return
    setBusy(true); setError(null)
    try {
      const blob = await (kind === 'bundle' ? downloadBundle(artifact.artifact_id) : downloadCommands(artifact.artifact_id))
      downloadFile(blob, kind === 'bundle' ? 'migration_fortigate_to_palo_alto.zip' : 'palo_alto_config.set')
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Download failed') }
    finally { setBusy(false) }
  }

  return activeSection === 'plan' ? <section className="panel migration-workflow" aria-labelledby="migration-title">
    <h2 id="migration-title"><span className="step-num">03</span> Migration plan</h2>
    <p>The plan updates as source, target evidence, or confirmed decisions change.</p>
    <Button disabled={busy || !decisionDocument} onClick={() => void generatePlan()}>Rebuild now</Button>
    {status && <p role="status" aria-live="polite">{status}</p>}
    {artifact && <div className="artifact-summary">
      <h3>04 Review migration plan</h3>
      <p><strong>Plan status: {artifact.plan_status}</strong></p>
      <p>{artifact.render_summary.create || 0} to create · {artifact.render_summary.reuse || 0} to reuse · {artifact.render_summary.blocked || 0} blocked · {artifact.commands} commands</p>
      <p className="artifact-identity">Artifact: {artifact.artifact_id} · SHA-256: {artifact.report.command_sha256 ?? 'Not reported'}</p>
      <PlanReview key={artifact.artifact_id} artifact={artifact} onReviewDecision={onReviewDecision} />
      <h3>Generated commands</h3>
      {artifact.commands > 0 ? <label className="field">Command preview<textarea readOnly value={commandText} rows={10} /></label> : <div className="review-work-card">
        <p>{artifact.plan_status === 'READY_NO_CHANGES' ? 'The reviewed plan requires no changes.' : artifact.plan_status === 'NEEDS_MAPPING' ? 'Complete required target mappings to render commands.' : 'Review blockers and support guidance before commands can be rendered.'}</p>
        {artifact.plan_status === 'NEEDS_MAPPING' && <Button onClick={() => onReviewDecision(String(decisionDocument?.decisions.find((item) => item.mode !== 'AUTO' && item.mode !== 'UNSUPPORTED' && item.review_state !== 'CONFIRMED')?.key ?? artifact.support_guidance?.find((item) => item.decision_key)?.decision_key ?? ''))}>Review required mappings</Button>}
      </div>}
      <div className="action-row"><Button disabled={busy || (!artifact.commands && artifact.plan_status !== 'READY_NO_CHANGES')} onClick={() => void saveArtifact('bundle')}>Download migration bundle</Button><Button disabled={busy || !artifact.commands} onClick={() => void saveArtifact('commands')}>Download .set</Button></div>
      <Button className="text-button" onClick={() => onViewChange('live')}>Open live migration</Button>
    </div>}
    {error && <ErrorBanner message={error} />}
  </section> : <>
    <section className="panel" aria-labelledby="target-connection-title">
      <h2 id="target-connection-title"><span className="step-num">02</span> Connect the target</h2>
      <p>Connect to the PAN-OS management interface.</p>
      <div className="connection-grid">
        <label className="field">Management IP or hostname *<input required autoComplete="off" spellCheck={false} value={connection.host} onChange={(event) => setConnection({ ...connection, host: event.target.value })} /></label>
        <label className="field">SSH port *<input type="number" min="1" max="65535" value={connection.port} onChange={(event) => setConnection({ ...connection, port: event.target.value })} /></label>
        <label className="field">Admin username *<input required autoComplete="username" spellCheck={false} value={connection.username} onChange={(event) => setConnection({ ...connection, username: event.target.value })} /></label>
        <label className="field">Admin password *<input required type="password" autoComplete="current-password" value={connection.password} onChange={(event) => setConnection({ ...connection, password: event.target.value })} /></label>
      </div>
    </section>
    <section className="panel" aria-labelledby="deployment-title">
      <h2 id="deployment-title"><span className="step-num">03</span> Review &amp; deploy</h2>
      <p aria-live="polite">{artifact ? `${artifact.commands} reviewed commands · ${artifact.plan_status} · ${sessionId ? 'Candidate session active' : 'No deployment session'}` : 'No current reviewed artifact. Build and review a migration plan first.'}</p>
      <div className="workflow-stepper">
        {[
          ['1', 'Prepare candidate', 'Push the reviewed artifact and validate the candidate automatically.', 'prepare', !artifact || busy || artifact.plan_status !== 'READY' || !artifact.commands],
          ['2', 'Validation', 'Revalidate the artifact-bound candidate session.', 'validate', busy || !sessionId],
          ['3', 'Commit configuration', 'Submit an explicit commit after successful validation.', 'commit', busy || !sessionId || !candidateValidated],
        ].map(([number, title, description, action, disabled]) => <div className="step-box" key={number as string}>
          <span className="step-badge" aria-hidden="true">{number}</span><span className="step-info"><strong>{title}</strong><span>{description}</span></span>
          <Button className={action === 'commit' ? 'outline-button' : ''} disabled={Boolean(disabled)} onClick={() => void runDeployment(action as 'prepare' | 'validate' | 'commit')}>{action === 'prepare' ? 'Prepare Candidate' : action === 'validate' ? 'Revalidate Candidate' : 'Commit'}</Button>
        </div>)}
      <div className="action-row">
      </div>
      </div>
      <div className="terminal-container">
        <div className="terminal-header"><div className="terminal-dots"><i className="term-dot dot-red" /><i className="term-dot dot-yellow" /><i className="term-dot dot-green" /><span className="terminal-title">Activity log</span></div>
          <div className="terminal-actions"><label className="term-checkbox"><input type="checkbox" checked={autoScroll} onChange={(event) => setAutoScroll(event.target.checked)} />Auto-scroll</label><button className="btn-term-action" type="button" onClick={() => setActivityLog(['[SYSTEM] Terminal logs cleared. Ready for operations.'])}>Clear</button><button className="btn-term-action" type="button" onClick={() => void navigator.clipboard?.writeText(activityLog.join('\n')).catch(() => setError('Could not copy the activity log.'))}>Copy</button></div>
        </div>
        <div className="terminal-body" role="log" aria-live="polite" aria-relevant="additions text" tabIndex={0} ref={activityRef}>{activityLog.map((line, index) => <div className={`term-line ${line.startsWith('[ERROR]') ? 'term-error' : line.startsWith('[SYSTEM]') ? 'term-system' : 'term-success'}`} key={`${index}:${line}`}>{line}</div>)}</div>
      </div>
    </section>
    {error && <ErrorBanner message={error} />}
  </>
}
