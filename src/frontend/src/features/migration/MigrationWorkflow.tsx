import { saveWorkspace, workspace } from '../../storage/workspaceStore'
import type { SourceEvidence } from '../../storage/workspaceTypes'
import { useCallback, useEffect, useRef, useState } from 'react'
import { ErrorBanner } from '../../components/common/ErrorBanner'
import { Button } from '../../components/common/Button'
import type { SourcePreviewData } from '../source/types'
import type { MigrationDecisionDocument } from './types'
import { buildPlan, downloadBundle, downloadCommands, downloadFile } from './migrationApi'
import type { PlanArtifact } from './migrationApi'
import { PlanReview } from './PlanReview'
import { conversionFamilies, exportCategoryLabels, planFamilySummary } from './reviewPresentation'

type Props = {
  generationRequest?: number
  preview: SourcePreviewData
  decisionDocument: MigrationDecisionDocument | null
  targetSource: SourceEvidence | null
  targetDevice: string
  onReviewDecision: (key: string) => void
}

export function MigrationWorkflow({ preview, decisionDocument, targetSource, targetDevice, onReviewDecision, generationRequest }: Props) {
  const [artifact, setArtifact] = useState<PlanArtifact | null>(workspace().artifact)
  const [commandText, setCommandText] = useState(workspace().artifact?.artifact.commands.join('\n') || '')
  const [status, setStatus] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const buildRequest = useRef(0)
  const contextKey = JSON.stringify({ decisionDocument, targetSource, targetDevice, source: preview.source_digest })

  useEffect(() => () => { buildRequest.current++ }, [])

  const generatePlan = useCallback(async () => {
    if (!decisionDocument || preview.vendor !== 'fortigate'
        || !decisionDocument.design_approval) return
    const request = ++buildRequest.current
    setArtifact(null); setCommandText('')
    setBusy(true); setError(null); setStatus('Building migration plan…')
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
    } catch (cause) {
      if (request !== buildRequest.current) return
      const message = cause instanceof Error ? cause.message : 'Migration planning failed'
      setError(message)
      setArtifact(null); setCommandText(''); setStatus('Plan generation failed.')
    }
    finally { if (request === buildRequest.current) setBusy(false) }
  }, [decisionDocument, preview.source_evidence, preview.vendor, targetSource, targetDevice])

  useEffect(() => {
    buildRequest.current++
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setArtifact(null); setCommandText('')
    setBusy(false)
    setError(null)
    setStatus(decisionDocument?.design_approval ? 'Design approved. Build the artifact explicitly.' : decisionDocument ? 'Approve the proposed design before building an artifact.' : 'Migration review is updating.')
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

  if (preview.vendor !== 'fortigate') return null
  const partial = artifact ? !['READY', 'READY_NO_CHANGES'].includes(artifact.plan_status)
    : Boolean(decisionDocument?.decisions?.some((row) => row.mode !== 'AUTO' && row.review_state !== 'CONFIRMED'))
  const families = planFamilySummary(artifact?.report.items ?? [])
  const noTrafficRules = artifact && !['security_rule', 'nat_rule', 'static_route'].some((family) => (families[family]?.INCLUDED ?? 0) > 0)

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

  return <section className="panel migration-workflow" aria-labelledby="migration-title">
    <h2 id="migration-title">Download</h2>
    <p>Command syntax baseline: PAN-OS 11.1. Other releases and live-device compatibility remain unverified.</p>
    <p>Approval generates commands. Retry generation here if the build fails. Source, target evidence or mapping edits revoke the previous artifact.</p>
    {!artifact && <Button disabled={busy || !decisionDocument || !decisionDocument.design_approval} onClick={() => void generatePlan()}>{error ? 'Retry generation with current approval' : partial ? 'Build approved partial plan' : 'Build approved artifact'}</Button>}
    {(!decisionDocument?.design_approval || (!artifact && error)) && <Button onClick={() => onReviewDecision('')}>Review and approve design</Button>}
    {status && <p role="status" aria-live="polite">{status}</p>}
    {artifact && <div className="artifact-summary">
      <h3>Approved migration changes</h3>
      <p><strong>{artifact.plan_status === 'READY_NO_CHANGES' ? 'No changes needed' : artifact.plan_status === 'NEEDS_MAPPING' ? 'Partial conversion - unresolved work excluded' : partial ? 'Partial export' : 'Ready for export'}</strong></p>
      {artifact.report.workflow_mode === 'OFFLINE_EXPORT' ? <p>Destination unverified. Check destination collisions, hardware compatibility and licensing before applying these commands.</p> : <p>Candidate preparation: {artifact.report.deployment_eligibility?.eligible ? 'Eligible — live preflight still required' : artifact.report.deployment_eligibility?.reason || 'Eligibility unverified'}</p>}
      <ul aria-label="Generated conversion coverage">{conversionFamilies.map(([label, names]) => <li key={label}>{label}: {names.reduce((total, name) => total + (families[name]?.INCLUDED ?? 0), 0)} included configuration items</li>)}</ul>
      {partial && <p>Unresolved work: {Object.entries(exportCategoryLabels).filter(([category]) => category !== 'INCLUDED' && artifact.report.export_counts?.[category]).map(([category, label]) => `${label}: ${artifact.report.export_counts?.[category]}`).join(' · ') || 'Review the exclusion reasons below.'} Hardware choices do not resolve unsupported semantics.</p>}
      <p>Planned items: {artifact.render_summary.create || 0} to create · {artifact.render_summary.configure || 0} to configure · {artifact.render_summary.reuse || 0} to reuse · {artifact.render_summary.blocked || 0} excluded · {artifact.artifact.command_count} commands</p>
      {!!artifact.report.coverage?.unplanned_count && <p role="status">{artifact.report.coverage.unplanned_count} source records remain outside this plan. Review Remaining source work below.</p>}
      {!!artifact.report.export_counts?.NOT_APPROVED && <p role="status">{artifact.report.export_counts.NOT_APPROVED} supported configuration items were not selected for approval. Review the proposed selection to include them.</p>}
      {partial && <p className="error-banner" role="status">Partial export: blocked and unsupported work is excluded. This artifact is not deployment-ready.</p>}
      {noTrafficRules && <p role="status">No security policies, NAT rules or static routes are included. This export contains supporting configuration only.</p>}
      {partial && <Button className="secondary-button" disabled={busy} onClick={() => onReviewDecision('')}>Review remaining changes</Button>}
      <div className="report-table-wrap"><table className="report-table"><caption>Planned configuration and exclusion reasons</caption><thead><tr><th>Family</th>{Object.entries(exportCategoryLabels).filter(([category]) => category === 'INCLUDED' || Object.values(families).some((counts) => counts[category])).map(([category, label]) => <th key={category}>{label}</th>)}</tr></thead><tbody>{Object.entries(families).map(([family, counts]) => <tr key={family}><td>{family.replaceAll('_', ' ')}</td>{Object.keys(exportCategoryLabels).filter((category) => category === 'INCLUDED' || Object.values(families).some((values) => values[category])).map((category) => <td key={category}>{counts[category] ?? 0}</td>)}</tr>)}</tbody></table></div>
      <details><summary>Artifact identity</summary><p className="artifact-identity">Artifact: {artifact.artifact_id} · SHA-256: {artifact.report.command_sha256 ?? 'Not reported'}</p></details>
      <PlanReview key={artifact.artifact_id} artifact={artifact} onReviewDecision={onReviewDecision} />
      <h3>Generated commands</h3>
      {artifact.artifact.command_count > 0 ? <details><summary>Command preview ({artifact.artifact.command_count})</summary><label className="field">Command preview<textarea aria-label="Command preview" readOnly value={commandText} rows={10} /></label></details> : <div className="review-work-card">
        <p>{artifact.plan_status === 'READY_NO_CHANGES' ? 'The reviewed plan requires no changes.' : artifact.plan_status === 'NEEDS_MAPPING' ? 'Complete required target mappings to render commands.' : 'Review blockers and support guidance before commands can be rendered.'}</p>
        {artifact.plan_status === 'NEEDS_MAPPING' && <Button onClick={() => onReviewDecision(String(decisionDocument?.decisions.find((item) => item.mode !== 'AUTO' && item.mode !== 'UNSUPPORTED' && item.review_state !== 'CONFIRMED')?.key ?? artifact.support_guidance?.find((item) => item.decision_key)?.decision_key ?? ''))}>Review required mappings</Button>}
      </div>}
      <div className="action-row"><Button disabled={busy || (!artifact.artifact.command_count && artifact.plan_status !== 'READY_NO_CHANGES')} onClick={() => void saveArtifact('bundle')}>{partial ? 'Download partial bundle' : 'Download migration bundle'}</Button><Button disabled={busy || !artifact.artifact.command_count} onClick={() => void saveArtifact('commands')}>{partial ? 'Download partial .set' : 'Download .set'}</Button></div>
    </div>}
    {error && <ErrorBanner message={error} />}
  </section>
}
