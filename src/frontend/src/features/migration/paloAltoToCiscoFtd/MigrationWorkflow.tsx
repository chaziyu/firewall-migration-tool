import { useEffect, useState } from 'react'
import { Button } from '../../../components/common/Button'
import { ErrorBanner } from '../../../components/common/ErrorBanner'
import { saveWorkspace, workspace } from '../../../storage/workspaceStore'
import type { SourceEvidence } from '../../../storage/workspaceTypes'
import { DestinationSnapshot } from '../components/DestinationSnapshot'
import type { DestinationEvidence } from '../components/DestinationSnapshot'
import { OfflineMigrationReview } from '../components/OfflineMigrationReview'
import { OfflineMigrationExport } from '../components/OfflineMigrationExport'
import { useMigrationReviewActivity } from '../hooks/useMigrationReviewActivity'
import { downloadFile } from '../migrationApi'
import type { MigrationStage } from '../types'
import type { FTDOptions, FTDWorkspace } from './types'
import * as api from './migrationApi'
import { approvalSelection } from './reviewSelection'

const emptyOptions = (): FTDOptions => ({
  source_scope: '',
  target_mode: 'new',
  manager_target: 'fmc.example.com',
  domain_id: 'e276abec-e0f2-11e3-8169-6d9ed49b625f',
  domain_name: 'Global',
  fmc_api_version: '7.7.0',
  policy_name: '',
  target_device_id: '',
  target_device_name: '',
})

const fileSpecs = [
  { key: 'fmc-operations', name: 'cisco_fmc_operations.json', label: 'FMC REST API request specification' },
  { key: 'fmc-curl', name: 'cisco_fmc_curl.sh', label: 'Fresh-policy FMC curl shell script' },
  { key: 'bindings', name: 'cisco_fmc_bindings.json', label: 'ID bindings and file manifest' },
  { key: 'instructions', name: 'ftd_application_instructions.txt', label: 'FTD application instructions' },
]

export function PaloAltoToCiscoFtdWorkflow({
  source,
  sourceKey,
  stage: controlledStage,
  onStageChange,
}: {
  source: SourceEvidence
  sourceKey: string
  stage?: MigrationStage
  onStageChange?: (stage: MigrationStage) => void
}) {
  const [state, setState] = useState<FTDWorkspace>(() => {
    const saved = workspace().panosMigration
    return saved?.pairId === 'palo_alto_to_cisco_ftd' && saved.sourceKey === sourceKey
      ? saved
      : {
          pairId: 'palo_alto_to_cisco_ftd',
          sourceKey,
          options: emptyOptions(),
          review: null,
          approval: null,
          artifact: null,
          stage: 'review',
        }
  })
  const [selected, setSelected] = useState<string[]>([])
  const [approvalKeys, setApprovalKeys] = useState<string[] | null>(null)
  const [tab, setTab] = useState<'changes' | 'decisions' | 'manual'>('changes')
  const [targetPending, setTargetPending] = useState(false)
  const activity = useMigrationReviewActivity({
    source,
    targetSource: state.targetSource?.source ?? null,
    targetDevice: '',
    workflowMode: 'offline',
    pairId: 'palo_alto_to_cisco_ftd',
  })

  const [requests] = useState(() => ({
    begin: activity.beginReviewRequest,
    finish: activity.finishReviewRequest,
    current: activity.currentReviewVersion,
    isCurrent: activity.reviewRequestIsCurrent,
    invalidate: activity.invalidateReviewRequests,
    run: activity.run,
  }))
  const { setError } = activity
  const { options, review, approval, artifact, targetSource } = state
  const [scopes, setScopes] = useState(state.review?.source_scopes ?? [])
  const stage = controlledStage ?? state.stage
  const rows = review?.report.items ?? []
  const busy = activity.busy || targetPending

  useEffect(() => {
    void saveWorkspace({ panosMigration: { ...state, stage } })
  }, [state, stage])

  useEffect(() => {
    const request = requests.begin()
    let active = true
    const timer = setTimeout(() => {
      void api
        .prepare(source, options, targetSource)
        .then((result) => {
          if (!active || !requests.isCurrent(request)) return
          setScopes(result.source_scopes)
          setState((current) => ({
            ...current,
            review: JSON.stringify(options) === JSON.stringify(result.options) ? result : null,
            options: JSON.stringify(options) === JSON.stringify(result.options) ? options : result.options, ...(JSON.stringify(options) === JSON.stringify(result.options) ? {} : { approval: null, artifact: null }),
          }))
        })
        .catch((cause) => {
          if (active && requests.isCurrent(request)) {
            setError(cause instanceof Error ? cause.message : 'Cisco FTD proposal failed')
          }
        })
        .finally(() => {
          if (active) requests.finish(request)
        })
    }, 250)
    return () => {
      active = false
      clearTimeout(timer)
      requests.invalidate()
    }
  }, [source, options, targetSource, requests, setError])

  useEffect(() => () => requests.invalidate(), [requests])

  function setStage(next: MigrationStage) {
    setState((current) => ({ ...current, stage: next }))
    onStageChange?.(next)
  }

  function update(next: Partial<FTDWorkspace>) {
    requests.invalidate()
    setSelected([])
    setApprovalKeys(null)
    setError('')
    setState((current) => ({ ...current, ...next, review: null, approval: null, artifact: null }))
  }

  async function generate(currentApproval = approval) {
    if (!currentApproval) return
    const request = requests.current()
    const built = await api.build(source, options, currentApproval, targetSource)
    if (requests.isCurrent(request)) {
      setState((current) => ({ ...current, artifact: built.artifact }))
      setStage('export')
    }
  }

  async function approve() {
    if (!review || !approvalKeys) return
    const request = requests.current()
    const result = await api.approve(source, options, review.draft, approvalKeys, targetSource)
    if (!requests.isCurrent(request)) return
    const signed = result.approval.selected_items
    if (!Array.isArray(signed) || JSON.stringify([...signed].sort()) !== JSON.stringify([...approvalKeys].sort())) {
      throw new Error('Approved operations differ from the reviewed selection')
    }
    setState((current) => ({ ...current, approval: result.approval, artifact: null }))
    setApprovalKeys(null)
    setStage('export')
    await generate(result.approval)
  }

  function download(kind: string) {
    if (!artifact) return
    const spec = fileSpecs.find((file) => file.key === kind)
    if (kind !== 'bundle' && !spec) return
    const request = requests.current()
    void requests.run(async () => {
      const blob = await api.download(source, artifact, kind)
      if (requests.isCurrent(request)) {
        downloadFile(blob, spec?.name ?? 'migration_palo_alto_to_cisco_ftd.zip')
      }
    })
  }

  const manual = rows.filter((row) => row.render_disposition === 'BLOCK')
  const unresolvedInputs = review?.requirements.filter((row) => row.value == null || row.value === '') ?? []
  const inputCount = unresolvedInputs.length

  return (
    <section className="panel" aria-label="PAN-OS to Cisco FTD">
      <h2>PAN-OS → Cisco FTD</h2>
      <p>Cisco FMC REST API 7.7.0. Offline files only. Device interface assignment and deployment require manual action.</p>
      {activity.error && <ErrorBanner message={activity.error} />}
      {busy && <p role="status">Preparing reviewed migration…</p>}

      {stage === 'load' && (
        <Button disabled={busy || !review} onClick={() => setStage('place')}>
          Continue to target setup
        </Button>
      )}

      {(stage === 'place' || stage === 'review') && (
        <details aria-label="Target setup" open={stage === 'place'}><summary>Target setup and choices</summary>
          <h3>Target setup</h3>
          <p>Configure FMC management domain, version, and Access Control Policy container parameters.</p>
          <fieldset disabled={busy} style={{ display: 'grid', gap: '0.75rem', maxWidth: '32rem' }}>
            <label>
              Source PAN-OS VSYS:
              <select
                value={options.source_scope}
                onChange={(e) => update({ options: { ...options, source_scope: e.target.value } })}
              >
                <option value="">Choose VSYS</option>
                {scopes.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Target FMC Mode:
              <select
                value={options.target_mode}
                onChange={(e) => update({ options: { ...options, target_mode: e.target.value as 'new' | 'existing' }, targetSource: null })}
              >
                <option value="new">Create new Access Control Policy</option>
                <option value="existing">Compare against existing FMC snapshot</option>
              </select>
            </label>
            <label>
              FMC Domain Name:
              <input
                type="text"
                value={options.domain_name}
                onChange={(e) => update({ options: { ...options, domain_name: e.target.value } })}
              />
            </label>
            <label>
              FMC Domain UUID:
              <input
                type="text"
                value={options.domain_id}
                onChange={(e) => update({ options: { ...options, domain_id: e.target.value } })}
              />
            </label>
            <label>
              Access Control Policy Name:
              <input
                type="text"
                value={options.policy_name}
                onChange={(e) => update({ options: { ...options, policy_name: e.target.value } })}
              />
            </label>
            <label>
              FMC Host / IP:
              <input
                type="text"
                value={options.manager_target}
                onChange={(e) => update({ options: { ...options, manager_target: e.target.value } })}
              />
            </label>
            <label>
              FMC API Version:
              <input type="text" readOnly value={options.fmc_api_version} />
            </label>
          </fieldset>

          {options.target_mode === 'existing' && (
            <DestinationSnapshot
              vendor="cisco_ftd"
              families={['objects', 'services', 'access_policies', 'security_zones']}
              value={targetSource ?? null}
              disabled={busy}
              onChange={(next: DestinationEvidence | null) => update({ targetSource: next })}
              onPendingChange={setTargetPending}
            />
          )}

          <div style={{ marginTop: '1rem' }}>
            <Button
              variant="primary"
              disabled={busy || !options.source_scope}
              onClick={() => setStage('review')}
            >
              Continue to Review ({inputCount} parameters checked)
            </Button>
          </div>
        </details>
      )}

      {(stage === 'review' || stage === 'place') && review && (
        <OfflineMigrationReview
          id="panos-ftd"
          title="Cisco FTD"
          rows={rows.map((row) => ({
            key: row.key,
            family: row.family,
            sourceScope: row.source_scope,
            sourceName: row.source_name,
            target: row.target_name,
            operation: row.render_disposition,
            settings: row.settings,
            dependencies: row.dependencies,
            reasons: row.blockers,
            ready: ['CREATE', 'REUSE'].includes(row.render_disposition) && !row.blockers.length,
          }))}
          busy={busy}
          tab={tab}
          onTabChange={setTab}
          inputCount={inputCount}
          manualCount={manual.length}
          issueContent={tab === 'decisions' ? <><p>Complete these FMC choices in setup.</p><ul>{unresolvedInputs.map((row) => <li key={row.key}>{row.label}</li>)}</ul></> :
            <>
              <h3>Remaining choices and manual work</h3>
              <p>
                {inputCount} target choices; {manual.length} blocked items.
              </p>
              <ul>
                {[...new Set(manual.flatMap((row) => row.blockers))].map((reason) => (
                  <li key={reason}>{reason.replaceAll('_', ' ')}</li>
                ))}
              </ul>
            </>
          }
          selected={selected}
          onSelect={(keys: string[]) => {
            setSelected(keys)
            setApprovalKeys(null)
            setState((current) => ({ ...current, approval: null, artifact: null }))
          }}
          approvalKeys={approvalKeys}
          onPreview={(keys: string[]) => {
            try {
              setApprovalKeys(approvalSelection(rows, keys))
            } catch (cause) {
              setError(String(cause))
            }
          }}
          onApprove={() => void requests.run(approve)}
          onCancel={() => setApprovalKeys(null)}
          approvalContext={
            <>
              <p>
                Approve these exact request bodies, returned object ID dependencies and FMC targets.
                No login, push, or deployment is included.
              </p>
              <pre className="set-command-preview">{JSON.stringify(options, null, 2)}</pre>
            </>
          }
          onSetup={() => setStage('place')}
          findings={review.report.findings} approveLabel="Approve and generate"
        />
      )}

      {stage === 'export' && !artifact && <p>Review and approve current changes before download.</p>}
      {stage === 'export' && approval && !artifact && (
        <Button disabled={busy} onClick={() => void requests.run(() => generate())}>
          Retry generation with current approval
        </Button>
      )}
      {stage === 'export' && artifact && (
        <OfflineMigrationExport
          dispositions={artifact.report.items.map((row) => row.render_disposition)}
          artifactId={artifact.artifact_id}
          partial={
            manual.length > 0 ||
            rows.some(
              (row) =>
                !approval ||
                !(approval.selected_items as string[] | undefined)?.includes(row.key),
            )
          }
          noChanges={artifact.report.items.length > 0 && artifact.report.items.every((row) => row.render_disposition === 'REUSE')}
          verification={artifact.report.verification}
          busy={busy}
          files={fileSpecs
            .filter((spec) => artifact.files[spec.name])
            .map((spec) => ({
              key: spec.key,
              label: spec.label,
              previewLabel: spec.label,
              text: artifact.files[spec.name].content,
              sha256: artifact.files[spec.name].sha256,
              count: `${artifact.files[spec.name].byte_count} bytes`,
              downloadLabel: `Download ${spec.label}`,
              downloadable: artifact.files[spec.name].byte_count > 0,
            }))}
          onDownload={download}
          onBundle={() => download('bundle')}
        />
      )}
    </section>
  )
}
