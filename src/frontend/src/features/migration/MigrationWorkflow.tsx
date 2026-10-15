import { saveWorkspace, workspace } from '../../storage/workspaceStore'
import type { SourceEvidence } from '../../storage/workspaceTypes'
import { useCallback, useEffect, useRef, useState } from 'react'
import { RequestError } from '../../api/client'
import { ErrorBanner } from '../../components/common/ErrorBanner'
import { Button } from '../../components/common/Button'
import type { SourcePreviewData } from '../source/types'
import type { MigrationDecisionDocument } from './types'
import {
  buildPlan, commitCandidate, deployArtifact, downloadBundle, downloadCommands, downloadFile,
  validateCandidate, inspectCandidate,
} from './migrationApi'
import type { CandidateRecovery, PlanArtifact } from './migrationApi'
import { PlanReview } from './PlanReview'
import { planFamilySummary } from './reviewPresentation'

type Props = { generationRequest?: number; preview: SourcePreviewData; decisionDocument: MigrationDecisionDocument | null; targetSource: SourceEvidence | null; targetDevice: string; activeSection: 'plan' | 'live'; onViewChange: (view: 'live') => void; onReviewDecision: (key: string) => void }

export function MigrationWorkflow({ preview, decisionDocument, targetSource, targetDevice, activeSection, onViewChange, onReviewDecision, generationRequest }: Props) {
  const [artifact, setArtifact] = useState<PlanArtifact | null>(workspace().artifact)
  const [commandText, setCommandText] = useState(workspace().artifact?.artifact.commands.join('\n') || '')
  const [connection, setConnection] = useState({ host: '', port: '22', username: '', password: '' })
  const [sessionId, setSessionId] = useState('')
  const [candidateValidated, setCandidateValidated] = useState(false)
  const [recovery, setRecovery] = useState<CandidateRecovery | null>(null)
  const operationPending = useRef(false)
  const [status, setStatus] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [activityLog, setActivityLog] = useState(['[SYSTEM] Candidate workflow is ready. Prepare (push + validate) → explicit commit.'])
  const [autoScroll, setAutoScroll] = useState(true)
  const activityRef = useRef<HTMLDivElement>(null)
  const buildRequest = useRef(0)
  const contextKey = JSON.stringify({ decisionDocument, targetSource, targetDevice, source: preview.source_digest })

  useEffect(() => () => { buildRequest.current++ }, [])

  const generatePlan = useCallback(async () => {
    if (!decisionDocument || preview.vendor !== 'fortigate'
        || !decisionDocument.design_approval) return
    const request = ++buildRequest.current
    setArtifact(null); setCommandText('')
    setBusy(true); setError(null); setStatus('Building migration plan…'); setSessionId(''); setCandidateValidated(false)
    setActivityLog((lines) => [...lines, '[PLAN] Building a plan from the current confirmed decisions.'])
    try {
      const result = await buildPlan(preview.source_evidence!, decisionDocument, targetSource, targetDevice || undefined, workspace().workflowMode ?? 'offline')
      if (request !== buildRequest.current) return
      setArtifact(result)
      await saveWorkspace({ artifact: result })
      if (request !== buildRequest.current) return
      if (result.artifact.command_count > 0 || result.plan_status === 'READY_NO_CHANGES') {
        setCommandText(result.artifact.commands.join('\n'))
      }
      setStatus(`Plan status: ${result.plan_status}`)
      setActivityLog((lines) => [...lines, `[PLAN] ${result.plan_status}: ${result.artifact.command_count} commands rendered.`])
    } catch (cause) {
      if (request !== buildRequest.current) return
      const message = cause instanceof Error ? cause.message : 'Migration planning failed'
      setError(message)
      setArtifact(null); setCommandText(''); setStatus('Plan generation failed.')
      setActivityLog((lines) => [...lines, `[ERROR] Plan generation failed: ${message}`])
    }
    finally { if (request === buildRequest.current) setBusy(false) }
  }, [decisionDocument, preview.source_evidence, preview.vendor, targetSource, targetDevice])

  useEffect(() => {
    buildRequest.current++
    // Context changes immediately revoke displayed commands and candidate eligibility.
    if (sessionId || operationPending.current) setRecovery({ state: 'SESSION_LOST', artifact_id: artifact?.artifact_id })
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setArtifact(null); setCommandText(''); setSessionId(''); setCandidateValidated(false)
    setBusy(false)
    setError(null)
    setStatus(decisionDocument?.design_approval ? 'Design approved. Build the artifact explicitly.' : decisionDocument ? 'Approve the proposed design before building an artifact.' : 'Migration review is updating. Previous candidate eligibility has been revoked.')
    void saveWorkspace({ artifact: null })
    // Capture the previous execution state only when the signed review context changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [contextKey])

  useEffect(() => {
    // Approval is an explicit user event propagated from the review component.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (generationRequest) void generatePlan()
    // A coordinated approval event triggers one build; retries use the build button.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [generationRequest])

  useEffect(() => {
    if (autoScroll && activityRef.current) activityRef.current.scrollTop = activityRef.current.scrollHeight
  }, [activityLog, autoScroll])

  if (preview.vendor !== 'fortigate') return null
  const partial = artifact ? !['READY', 'READY_NO_CHANGES'].includes(artifact.plan_status)
    : Boolean(decisionDocument?.decisions?.some((row) => row.mode !== 'AUTO' && row.review_state !== 'CONFIRMED'))
  const families = planFamilySummary(artifact?.report.items ?? [])
  const noTrafficRules = artifact && !['security_rule', 'nat_rule', 'static_route'].some((family) => (families[family]?.included ?? 0) > 0)

  function log(line: string) { setActivityLog((lines) => [...lines, line]) }

  async function runDeployment(action: 'prepare' | 'validate' | 'commit' | 'inspect') {
    if (operationPending.current || !artifact || !decisionDocument?.design_approval) return
    if (action === 'prepare' && (artifact.report.deployment_eligibility?.eligible !== true || sessionId || (recovery && recovery.state !== 'CLEAN_BASELINE'))) return
    operationPending.current = true
    const request = buildRequest.current
    setBusy(true); setError(null)
    const credentials = { ...connection, port: Number(connection.port) }
    try {
      if (action === 'inspect') {
        const result = await inspectCandidate(artifact, credentials)
        if (request !== buildRequest.current) return
        setRecovery(result.recovery)
        setSessionId(''); setCandidateValidated(false)
        setStatus(result.inspection.state === 'CLEAN_BASELINE' ? 'Verified clean reviewed baseline. A new preparation is available.' : 'Candidate requires operator reconciliation. Do not replay or discard changes automatically.')
        log(`[INSPECT] ${result.inspection.state} · serial ${result.inspection.device_serial || 'Unverified'} · baseline ${result.inspection.baseline_matches ? 'matches' : 'does not match'} · candidate ${result.inspection.candidate_clean ? 'clean' : 'dirty or unknown'}`)
      } else if (action === 'prepare') {
        log('[PREPARE] Pushing reviewed commands to the candidate configuration.')
        const result = await deployArtifact(artifact, credentials) as { deployment_session_id?: string; candidate_validated?: boolean; result?: { commands_succeeded?: number; validation?: { status?: string; response?: string } } }
        if (request !== buildRequest.current) return
        setSessionId(result.deployment_session_id || '')
        const validation = result.result?.validation
        const validated = result.candidate_validated === true && validation?.status === 'SUCCESS'
        setCandidateValidated(validated)
        setRecovery(null)
        setStatus(validated ? 'Candidate pushed and validated.' : 'Candidate preparation did not validate.')
        log(`[PREPARE] Pushed ${result.result?.commands_succeeded ?? 0} candidate commands.`)
        log(`[VALIDATE] Candidate ${String(validation?.status || 'unknown').toLowerCase()}: ${validation?.response || ''}`)
        if (!validated) throw new Error('Candidate preparation did not validate successfully.')
      } else if (action === 'validate' && sessionId) {
        log('[REVALIDATE] Checking the current candidate configuration.')
        const result = await validateCandidate(artifact, sessionId, credentials) as { deployment_session_id?: string; result?: { status?: string; response?: string } }
        if (request !== buildRequest.current) return
        setSessionId(result.deployment_session_id || '')
        const validated = Boolean(result.deployment_session_id && result.result?.status === 'SUCCESS')
        setCandidateValidated(validated)
        setStatus(validated ? 'Candidate validation succeeded.' : 'Candidate validation failed.')
        log(`[REVALIDATE] Candidate ${String(result.result?.status || 'unknown').toLowerCase()}: ${result.result?.response || ''}`)
      } else if (action === 'commit' && sessionId && window.confirm('Commit the validated candidate configuration?')) {
        const result = await commitCandidate(artifact, sessionId, credentials) as { result?: { job_id?: string } }
        if (request !== buildRequest.current) return
        setSessionId(''); setCandidateValidated(false); setStatus('Commit completed and confirmed.'); setRecovery({ state: 'COMMITTED' })
        log(`[COMMIT] Commit completed (job ${result.result?.job_id || 'unknown'}).`)
      }
    } catch (cause) {
      if (request !== buildRequest.current) return
      setSessionId(''); setCandidateValidated(false)
      const message = cause instanceof Error ? cause.message : 'Deployment action failed'
      setError(message)
      setRecovery(cause instanceof RequestError && cause.details.recovery ? cause.details.recovery as CandidateRecovery : { state: 'OUTCOME_UNKNOWN' })
      setStatus('Execution disabled. Inspect the candidate and reconcile its state before preparing again. A missing response does not prove that no changes occurred.')
      log(`[ERROR] ${action === 'prepare' ? 'Candidate preparation' : action === 'validate' ? 'Candidate revalidation' : 'Commit'} failed: ${message}`)
      if (cause instanceof RequestError) {
        if (cause.details.error_code === 'artifact_ineligible') {
          setArtifact(null); setCommandText('')
          setStatus('Review and approve the current design before preparing another candidate.')
          void saveWorkspace({ artifact: null })
        }
        const feedback = cause.details.validation_feedback as { mapping_status?: string; migration_items?: Array<{ source_vdom?: string; source_name?: string; decision_keys?: string[] }> } | undefined
        if (feedback?.mapping_status) log(`[REVIEW] Validation feedback: ${feedback.mapping_status}`)
        for (const item of feedback?.migration_items || []) {
          log(`[REVIEW] ${item.source_vdom || ''}/${item.source_name || ''}: ${(item.decision_keys || []).join(', ')}`)
        }
      }
    }
    finally {
      if (request === buildRequest.current) setBusy(false)
      operationPending.current = false
      setConnection((current) => ({ ...current, password: '' }))
    }
  }

  async function saveArtifact(kind: 'bundle' | 'commands') {
    if (!artifact || !decisionDocument?.design_approval) return
    const request = buildRequest.current
    setBusy(true); setError(null)
    try {
      const blob = await (kind === 'bundle' ? downloadBundle(artifact, preview.source_evidence!) : downloadCommands(artifact))
      if (request !== buildRequest.current) return
      downloadFile(blob, kind === 'bundle' ? `migration_fortigate_to_palo_alto${partial ? '_PARTIAL' : ''}.zip` : `palo_alto_config${partial ? '_PARTIAL' : ''}.set`)
      setStatus(`${partial ? 'Partial' : 'Migration'} ${kind === 'bundle' ? 'bundle' : 'commands'} downloaded. ${partial ? 'Blocked items are excluded; deployment is not ready.' : 'Review the artifact before deployment.'}`)
    } catch (cause) { if (request === buildRequest.current) setError(cause instanceof Error ? cause.message : 'Download failed') }
    finally { if (request === buildRequest.current) setBusy(false) }
  }

  return activeSection === 'plan' ? <section className="panel migration-workflow" aria-labelledby="migration-title">
    <h2 id="migration-title">Export</h2>
    <p>Approval generates commands. Retry generation here if the build fails. Source, target evidence or mapping edits revoke the previous artifact.</p>
    {!artifact && <Button disabled={busy || !decisionDocument || !decisionDocument.design_approval} onClick={() => void generatePlan()}>{error ? 'Retry generation with current approval' : partial ? 'Build approved partial plan' : 'Build approved artifact'}</Button>}
    {(!decisionDocument?.design_approval || (!artifact && error)) && <Button onClick={() => onReviewDecision('')}>Review and approve design</Button>}
    {status && <p role="status" aria-live="polite">{status}</p>}
    {artifact && <div className="artifact-summary">
      <h3>Approved migration changes</h3>
      <p><strong>{artifact.plan_status === 'READY_NO_CHANGES' ? 'No changes needed' : artifact.plan_status === 'NEEDS_MAPPING' ? 'Needs mapping' : partial ? 'Partial export' : 'Ready for export'}</strong></p>
      {artifact.report.workflow_mode === 'OFFLINE_EXPORT' ? <p>Destination unverified. Check destination collisions, hardware compatibility and licensing before applying these commands.</p> : <p>Candidate preparation: {artifact.report.deployment_eligibility?.eligible ? 'Eligible — live preflight still required' : artifact.report.deployment_eligibility?.reason || 'Eligibility unverified'}</p>}
      <p>{artifact.render_summary.create || 0} to create · {artifact.render_summary.configure || 0} to configure · {artifact.render_summary.reuse || 0} to reuse · {artifact.render_summary.blocked || 0} blocked · {artifact.artifact.command_count} commands</p>
      {partial && <p className="error-banner" role="status">Partial export: blocked and unsupported work is excluded. This artifact is not deployment-ready.</p>}
      {noTrafficRules && <p role="status">No security policies, NAT rules or static routes are included. This export contains supporting configuration only.</p>}
      <div className="report-table-wrap"><table className="report-table"><caption>Included and blocked configuration</caption><thead><tr><th>Family</th><th>Included</th><th>Blocked</th></tr></thead><tbody>{Object.entries(families).map(([family, counts]) => <tr key={family}><td>{family.replaceAll('_', ' ')}</td><td>{counts.included}</td><td>{counts.blocked}</td></tr>)}</tbody></table></div>
      <details><summary>Artifact identity</summary><p className="artifact-identity">Artifact: {artifact.artifact_id} · SHA-256: {artifact.report.command_sha256 ?? 'Not reported'}</p></details>
      <PlanReview key={artifact.artifact_id} artifact={artifact} onReviewDecision={onReviewDecision} />
      <h3>Generated commands</h3>
      {artifact.artifact.command_count > 0 ? <details><summary>Command preview ({artifact.artifact.command_count})</summary><label className="field">Command preview<textarea aria-label="Command preview" readOnly value={commandText} rows={10} /></label></details> : <div className="review-work-card">
        <p>{artifact.plan_status === 'READY_NO_CHANGES' ? 'The reviewed plan requires no changes.' : artifact.plan_status === 'NEEDS_MAPPING' ? 'Complete required target mappings to render commands.' : 'Review blockers and support guidance before commands can be rendered.'}</p>
        {artifact.plan_status === 'NEEDS_MAPPING' && <Button onClick={() => onReviewDecision(String(decisionDocument?.decisions.find((item) => item.mode !== 'AUTO' && item.mode !== 'UNSUPPORTED' && item.review_state !== 'CONFIRMED')?.key ?? artifact.support_guidance?.find((item) => item.decision_key)?.decision_key ?? ''))}>Review required mappings</Button>}
      </div>}
      <div className="action-row"><Button disabled={busy || (!artifact.artifact.command_count && artifact.plan_status !== 'READY_NO_CHANGES')} onClick={() => void saveArtifact('bundle')}>{partial ? 'Download partial bundle' : 'Download migration bundle'}</Button><Button disabled={busy || !artifact.artifact.command_count} onClick={() => void saveArtifact('commands')}>{partial ? 'Download partial .set' : 'Download .set'}</Button></div>
      {artifact.report.workflow_mode !== 'OFFLINE_EXPORT' && <Button className="text-button" onClick={() => onViewChange('live')}>Open live migration</Button>}
    </div>}
    {error && <ErrorBanner message={error} />}
  </section> : <>
    <section className="panel" aria-labelledby="target-connection-title">
      <h2 id="target-connection-title">Connect the target</h2>
      <p>Connect to the PAN-OS management interface.</p>
      <div className="connection-grid">
        <label className="field">Management IP or hostname *<input required autoComplete="off" spellCheck={false} value={connection.host} onChange={(event) => setConnection({ ...connection, host: event.target.value })} /></label>
        <label className="field">SSH port *<input type="number" min="1" max="65535" value={connection.port} onChange={(event) => setConnection({ ...connection, port: event.target.value })} /></label>
        <label className="field">Admin username *<input required autoComplete="username" spellCheck={false} value={connection.username} onChange={(event) => setConnection({ ...connection, username: event.target.value })} /></label>
        <label className="field">Admin password *<input required type="password" autoComplete="current-password" value={connection.password} onChange={(event) => setConnection({ ...connection, password: event.target.value })} /></label>
      </div>
    </section>
    <section className="panel" aria-labelledby="deployment-title">
      <h2 id="deployment-title">Review &amp; deploy</h2>
      <p>Candidate preparation requires actual destination XML, a selected device and serial, an approved baseline, and a clean candidate. Verify hardware capacity and licensing before deployment.</p>
      <p aria-live="polite">{artifact && decisionDocument ? `${artifact.artifact.command_count} reviewed commands · ${artifact.plan_status} · ${sessionId ? 'Candidate session active' : 'No deployment session'}` : 'No current reviewed artifact. Build and review a migration plan first.'}</p>
      {artifact && artifact.report.deployment_eligibility?.eligible !== true && <p role="status">{artifact.report.deployment_eligibility?.reason || 'Build a current artifact to check candidate deployment eligibility.'}</p>}
      {status && <p role="status" aria-live="polite">{status}</p>}
      {(!decisionDocument?.design_approval || (!artifact && error)) && <Button onClick={() => onReviewDecision('')}>Review and approve design</Button>}
      {recovery && recovery.state !== 'COMMITTED' && <section className="review-work-card" aria-label="Candidate recovery" role="status">
        <h3>{recovery.state.replaceAll('_', ' ').toLowerCase()}</h3><p>Artifact {recovery.artifact_id || artifact?.artifact_id} · destination {targetDevice || 'Unverified'} · host {connection.host || 'Enter host'}.</p>
        <p>Attempted: {recovery.commands_attempted ?? 'Unknown'} · Known accepted: {recovery.commands_succeeded ?? 'Unknown'}{recovery.failed_command_index != null ? ` · failed index ${recovery.failed_command_index}` : ''}.</p>
        <p>{recovery.explanation || 'Re-enter your password for a read-only identity, baseline and candidate inspection. Changes may include another administrator’s work. Reconcile with the operator; no automatic replay, rollback or discard.'}</p>
        <Button disabled={busy || !artifact || !decisionDocument?.design_approval} onClick={() => void runDeployment('inspect')}>Inspect candidate (read-only)</Button>
      </section>}
      <p>Your password is cleared after each operation. Re-enter it to inspect, revalidate or commit. Successful preparation already validates the candidate; revalidation is optional.</p>
      <div className="workflow-stepper">
        {[
          ['1', 'Prepare candidate', 'Push the reviewed artifact and validate the candidate automatically.', 'prepare', !decisionDocument?.design_approval || !artifact || busy || artifact.report.deployment_eligibility?.eligible !== true || !!sessionId || (!!recovery && recovery.state !== 'CLEAN_BASELINE')],
          ['2', 'Validation', 'Revalidate the artifact-bound candidate session.', 'validate', !decisionDocument?.design_approval || busy || !sessionId],
          ['3', 'Commit configuration', 'Submit an explicit commit after successful validation.', 'commit', !decisionDocument?.design_approval || busy || !sessionId || !candidateValidated],
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
