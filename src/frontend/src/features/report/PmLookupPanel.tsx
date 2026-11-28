import { useEffect, useMemo, useState } from 'react'
import type { SourceEvidence } from '../../storage/workspaceTypes'
import type { PmChecklistResponse, PmChecklistRow } from '../source/types'
import { downloadPmLookupExcel, fetchPmLookup } from '../source/sourceApi'
import { saveBlobWithFallback } from '../../utils/desktop'
import { downloadCsvRows } from './reportPresentation'
import { ErrorBanner } from '../../components/common/ErrorBanner'
import { LoadingState } from '../../components/common/LoadingState'
import { Toast } from '../../components/common/Toast'

type StatusFilter = 'all' | 'pass' | 'warn' | 'fail' | 'info'

const PM_DEFAULT_LEGEND = [
  { label: 'Pass (green)', variant: 'success' },
  { label: 'Info (blue)', variant: 'info' },
  { label: 'Warn (amber)', variant: 'warn' },
  { label: 'Fail (red)', variant: 'danger' },
]

function pmRowClass(status: string): string {
  const key = status.trim().toLowerCase()
  if (key === 'pass') return 'row-success'
  if (key === 'warn') return 'row-warn'
  if (key === 'fail') return 'row-danger'
  if (key === 'info') return 'row-info'
  return ''
}

function pmBadgeVariant(status: string): 'allow' | 'warn' | 'deny' | 'info' | 'muted' {
  const key = status.trim().toLowerCase()
  if (key === 'pass') return 'allow'
  if (key === 'warn') return 'warn'
  if (key === 'fail') return 'deny'
  if (key === 'info') return 'info'
  return 'muted'
}

export function PmLookupPanel({
  vendor,
  sourceEvidence,
  initialData = null,
  onLoaded,
}: {
  vendor: string
  sourceEvidence: SourceEvidence
  initialData?: PmChecklistResponse | null
  onLoaded?: (data: PmChecklistResponse) => void
}) {
  const [state, setState] = useState<{
    vendor: string
    sourceEvidence: SourceEvidence
    data: PmChecklistResponse | null
    error: string | null
  } | null>(null)
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')
  const [search, setSearch] = useState('')
  const [exportingExcel, setExportingExcel] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)
  const [exportStatus, setExportStatus] = useState('')

  const matchingState =
    state && state.vendor === vendor && state.sourceEvidence === sourceEvidence
      ? state
      : null
  const data = initialData ?? matchingState?.data ?? null
  const loading = !initialData && !matchingState
  const error = exportError ?? (!initialData ? matchingState?.error ?? null : null)

  useEffect(() => {
    if (initialData) return
    let active = true
    fetchPmLookup(vendor, sourceEvidence)
      .then((res) => {
        if (!active) return
        setState({ vendor, sourceEvidence, data: res, error: null })
        onLoaded?.(res)
      })
      .catch((err: unknown) => {
        if (!active) return
        setState({
          vendor,
          sourceEvidence,
          data: null,
          error: err instanceof Error ? err.message : 'PM Lookup failed',
        })
      })
    return () => { active = false }
  }, [vendor, sourceEvidence, initialData, onLoaded])

  const filteredRows = useMemo<PmChecklistRow[]>(() => {
    const rows = data?.rows ?? []
    const q = search.trim().toLowerCase()
    return rows.filter((row) => {
      if (statusFilter !== 'all' && row.status.trim().toLowerCase() !== statusFilter) {
        return false
      }
      if (!q) return true
      return [row.no, row.category, row.task, row.status, row.finding, row.guidance]
        .some((val) => String(val ?? '').toLowerCase().includes(q))
    })
  }, [data?.rows, statusFilter, search])

  async function handleExportExcel() {
    setExportingExcel(true)
    setExportError(null)
    setExportStatus('')
    try {
      const blob = await downloadPmLookupExcel(vendor, sourceEvidence)
      const outcome = await saveBlobWithFallback(blob, `${vendor}_pm_lookup.xlsx`)
      if (outcome.status === 'cancelled') setExportStatus('PM Lookup Excel export cancelled.')
      else if (outcome.status === 'saved') setExportStatus(`Saved PM Lookup Excel: ${outcome.path || outcome.filename}.`)
      else setExportStatus(`Downloaded PM Lookup Excel: ${outcome.filename}.`)
    } catch (err: unknown) {
      setExportError(err instanceof Error ? err.message : 'PM Lookup Excel export failed')
    } finally {
      setExportingExcel(false)
    }
  }

  function handleExportCsv() {
    downloadCsvRows(
      ['no', 'category', 'task', 'status', 'finding', 'guidance'],
      filteredRows as unknown as Record<string, unknown>[],
      `${vendor}_pm_lookup.csv`,
      (col) => ({
        no: 'No.',
        category: 'Category',
        task: 'Task',
        status: 'Status',
        finding: 'Config Finding',
        guidance: 'Recommendation / Follow-up',
      }[col] ?? col),
    )
  }

  if (loading) {
    return (
      <div className="fw-pm-panel">
        <LoadingState label="Evaluating Preventive Maintenance checks…" />
      </div>
    )
  }

  if (error && !data) {
    return (
      <div className="fw-pm-panel">
        <ErrorBanner message={error} />
      </div>
    )
  }

  if (!data) return null

  const { summary } = data
  const legend = data.legend?.length ? data.legend : PM_DEFAULT_LEGEND
  const filters: Array<{ id: StatusFilter; label: string; count: number }> = [
    { id: 'all', label: 'All', count: summary.total },
    { id: 'pass', label: 'Pass', count: summary.pass },
    { id: 'warn', label: 'Warn', count: summary.warn },
    { id: 'fail', label: 'Fail', count: summary.fail },
    { id: 'info', label: 'Info', count: summary.info },
  ]

  return (
    <div className="fw-pm-panel">
      <p className="fw-pm-note">
        Evaluated {summary.total} backup-config verifiable Preventive Maintenance checks (live-only metrics such as CPU, memory, uptime, PSU, and license expiry are omitted).
      </p>

      {exportError && <ErrorBanner message={exportError} />}
      {exportStatus && <Toast message={exportStatus} onDismiss={() => setExportStatus('')} />}

      <div className="fw-legend" aria-label="PM status color legend">
        {legend.map((item) => (
          <span key={item.label} className={`fw-legend-item fw-legend-${item.variant}`}>
            <span className="fw-legend-swatch" aria-hidden="true" />
            {item.label}
          </span>
        ))}
      </div>

      <div className="report-toolbar fw-table-toolbar">
        <div className="fw-pm-filter-group" role="group" aria-label="Filter PM checks by status">
          {filters.map((item) => (
            <button
              key={item.id}
              type="button"
              aria-pressed={statusFilter === item.id}
              className={`fw-pm-filter-btn${statusFilter === item.id ? ' active' : ''}`}
              onClick={() => setStatusFilter(item.id)}
            >
              {item.label} ({item.count})
            </button>
          ))}
        </div>
        <label className="report-search-control">
          <span className="visually-hidden">Filter PM checks</span>
          <input
            type="search"
            value={search}
            placeholder="Filter checks or findings…"
            onChange={(event) => setSearch(event.target.value)}
          />
        </label>
        <div className="fw-table-toolbar-right">
          <button
            type="button"
            className="secondary-button button-compact"
            onClick={handleExportCsv}
          >
            ⬇ CSV
          </button>
          <button
            type="button"
            className="primary-button button-compact"
            disabled={exportingExcel}
            onClick={() => void handleExportExcel()}
          >
            {exportingExcel ? 'Exporting…' : '⬇ Export Excel'}
          </button>
        </div>
      </div>

      {!filteredRows.length ? (
        <p className="report-empty">No PM checks match the current filter.</p>
      ) : (
        <div className="report-table-wrap" role="region" aria-label="Preventive Maintenance checklist">
          <table className="report-table fw-table fw-pm-table fw-pm-checklist-table">
            <colgroup>
              <col style={{ width: '58px' }} />
              <col style={{ width: '132px' }} />
              <col style={{ width: '185px' }} />
              <col style={{ width: '84px' }} />
              <col style={{ width: '34%' }} />
              <col style={{ width: '34%' }} />
            </colgroup>
            <thead>
              <tr>
                <th scope="col">No.</th>
                <th scope="col">Category</th>
                <th scope="col">Task</th>
                <th scope="col">Status</th>
                <th scope="col">Config Finding</th>
                <th scope="col">Recommendation / Follow-up</th>
              </tr>
            </thead>
            <tbody>
              {filteredRows.map((row) => (
                <tr key={row.no} className={pmRowClass(row.status)}>
                  <td className="fw-cell-mono">{row.no}</td>
                  <td>{row.category}</td>
                  <td><strong>{row.task}</strong></td>
                  <td>
                    <span className={`fw-badge fw-badge-${pmBadgeVariant(row.status)}`}>
                      {row.status}
                    </span>
                  </td>
                  <td>{row.finding}</td>
                  <td>{row.guidance}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
