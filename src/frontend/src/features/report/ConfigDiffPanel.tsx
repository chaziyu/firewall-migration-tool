import { useState, type FormEvent } from 'react'
import type { SourceEvidence } from '../../storage/workspaceTypes'
import type { ConfigDiffResponse } from '../source/types'
import { runConfigDiff } from '../source/sourceApi'
import { downloadCsvRows } from './reportPresentation'
import { ErrorBanner } from '../../components/common/ErrorBanner'

type ChangeFilter = 'all' | 'added' | 'modified' | 'removed'

function diffRowClass(changeType: string): string {
  if (changeType === 'added') return 'row-success'
  if (changeType === 'modified') return 'row-warn'
  if (changeType === 'removed') return 'row-danger'
  return ''
}

function diffBadgeVariant(changeType: string): 'allow' | 'warn' | 'deny' | 'muted' {
  if (changeType === 'added') return 'allow'
  if (changeType === 'modified') return 'warn'
  if (changeType === 'removed') return 'deny'
  return 'muted'
}

export function ConfigDiffPanel({
  vendor,
  sourceEvidence,
  currentFilename,
}: {
  vendor: string
  sourceEvidence: SourceEvidence
  currentFilename: string
}) {
  const isFortiGate = vendor === 'fortigate'
  const acceptExt = isFortiGate ? '.conf,.cfg,.txt' : '.xml'
  const [compareFile, setCompareFile] = useState<File | null>(null)
  const [filter, setFilter] = useState<ChangeFilter>('all')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ConfigDiffResponse | null>(null)

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    if (!compareFile) return
    setLoading(true)
    setError(null)
    try {
      const res = await runConfigDiff(vendor, sourceEvidence, compareFile)
      setResult(res)
      setFilter('all')
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Config diff failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fw-sim-panel">
      <section className="fw-card fw-sim-card" aria-label="Firewall-aware structural config diff">
        <div className="fw-sim-header">
          <div>
            <h3 className="fw-sim-title">Firewall-Aware Structural Config Diff</h3>
            <p className="fw-sim-subtitle">
              Compare active snapshot <strong className="fw-mono">{currentFilename}</strong> against a second {isFortiGate ? 'FortiGate (.conf/.cfg)' : 'PAN-OS (.xml)'} snapshot across Policies, NAT, Routes, VPNs, and Interfaces.
            </p>
          </div>
        </div>

        <form className="fw-sim-form" onSubmit={(e) => void handleSubmit(e)}>
          <div className="fw-diff-upload">
            <label className="fw-sim-field fw-diff-file-field">
              <span>Comparison Config File ({acceptExt})</span>
              <input
                type="file"
                accept={acceptExt}
                onChange={(e) => setCompareFile(e.target.files?.[0] ?? null)}
              />
            </label>
            <button type="submit" className="primary-button button-compact" disabled={loading || !compareFile}>
              {loading ? 'Comparing…' : 'Compare Configs'}
            </button>
          </div>
        </form>
      </section>

      {error && <ErrorBanner message={error} />}

      {result && !result.has_diff && (
        <div className="fw-sim-note-success" role="status">
          No structural differences found between <strong className="fw-mono">{result.before_name}</strong> and <strong className="fw-mono">{result.after_name}</strong> across Policies, NAT, Routes, VPNs, and Interfaces.
        </div>
      )}

      {result && result.has_diff && (
        <section className="fw-card fw-sim-result" aria-label="Structural config diff summary">
          <div className="fw-sim-verdict-row">
            <div>
              <div className="fw-sim-verdict-label">
                Diff: <span className="fw-mono">{result.before_name} → {result.after_name}</span>
              </div>
              <div className="fw-sim-verdict-reason">
                Detected {result.summary.total} structural change(s) across {result.domains.length} domain(s).
              </div>
            </div>
            <div className="fw-hero-badges">
              <span className="fw-badge fw-badge-allow">Added: {result.summary.added}</span>
              <span className={`fw-badge fw-badge-${result.summary.modified ? 'warn' : 'muted'}`}>Modified: {result.summary.modified}</span>
              <span className={`fw-badge fw-badge-${result.summary.removed ? 'deny' : 'muted'}`}>Removed: {result.summary.removed}</span>
            </div>
          </div>

          <div className="fw-pm-filter-group" role="group" aria-label="Filter diff changes">
            {([
              ['all', `All (${result.summary.total})`],
              ['added', `Added (${result.summary.added})`],
              ['modified', `Modified (${result.summary.modified})`],
              ['removed', `Removed (${result.summary.removed})`],
            ] as const).map(([key, label]) => (
              <button
                key={key}
                type="button"
                aria-pressed={filter === key}
                className={`fw-pm-filter-btn${filter === key ? ' active' : ''}`}
                onClick={() => setFilter(key)}
              >
                {label}
              </button>
            ))}
          </div>

          {result.domains.map((domain, idx) => {
            const visibleRows = filter === 'all'
              ? domain.rows
              : domain.rows.filter((r) => r.change_type === filter)
            if (!visibleRows.length) return null
            return (
              <details key={domain.name} open className="fw-diff-domain">
                <summary>
                  <span>{domain.name} ({visibleRows.length})</span>
                  <button
                    type="button"
                    className="secondary-button button-compact"
                    onClick={(e) => {
                      e.preventDefault()
                      downloadCsvRows(
                        ['change', 'item', 'details'],
                        visibleRows as unknown as Record<string, unknown>[],
                        `config_diff_${idx}_${domain.name.toLowerCase().replace(/[^a-z0-9]+/g, '_')}.csv`,
                      )
                    }}
                  >
                    ⬇ CSV
                  </button>
                </summary>
                <div className="report-table-wrap">
                  <table className="report-table fw-table">
                    <thead>
                      <tr>
                        <th scope="col">Change</th>
                        <th scope="col">Item</th>
                        <th scope="col">Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {visibleRows.map((row, rowIdx) => (
                        <tr key={`${row.item}-${rowIdx}`} className={diffRowClass(row.change_type)}>
                          <td>
                            <span className={`fw-badge fw-badge-${diffBadgeVariant(row.change_type)}`}>{row.change}</span>
                          </td>
                          <td className="fw-mono">{row.item}</td>
                          <td>{row.details}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </details>
            )
          })}
        </section>
      )}
    </div>
  )
}
