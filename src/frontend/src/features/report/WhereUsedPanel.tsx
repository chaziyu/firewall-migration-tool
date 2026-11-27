import { useState } from 'react'
import type { SourceEvidence } from '../../storage/workspaceTypes'
import type { WhereUsedResponse } from '../source/types'
import { searchWhereUsed } from '../source/sourceApi'
import { cellSummary, downloadCsvRows, fieldLabel } from './reportPresentation'
import { ErrorBanner } from '../../components/common/ErrorBanner'

export function WhereUsedPanel({
  vendor,
  sourceEvidence,
}: {
  vendor: string
  sourceEvidence: SourceEvidence
}) {
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<WhereUsedResponse | null>(null)

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    const trimmed = query.trim()
    if (!trimmed) {
      setError('Enter an IPv4 address, CIDR subnet, IP range, or object name.')
      return
    }
    setLoading(true)
    setError(null)
    try {
      const response = await searchWhereUsed(vendor, sourceEvidence, trimmed)
      setResult(response)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Where-used search failed')
    } finally {
      setLoading(false)
    }
  }

  function exportAllCsv() {
    if (!result) return
    const flatColumns = new Set<string>(['category'])
    const flatRows: Record<string, unknown>[] = []
    for (const cat of result.categories) {
      for (const col of cat.columns) flatColumns.add(col)
      for (const row of cat.rows) {
        flatRows.push({ category: cat.label, ...row })
      }
    }
    downloadCsvRows(
      [...flatColumns],
      flatRows,
      `${vendor}_where_used_${result.query.replace(/[^A-Za-z0-9_.-]+/g, '_')}.csv`,
    )
  }

  return (
    <details className="where-used-panel">
      <summary className="where-used-summary">
        <span>🔎 Global IP / Object &ldquo;Where-Used&rdquo; Search</span>
        <span className="where-used-hint">
          Search IPv4, CIDR, IP range, or object name across addresses, NAT/VIPs, policies, routes &amp; VPNs
        </span>
      </summary>
      <div className="where-used-body">
        <form className="where-used-form" onSubmit={handleSubmit}>
          <label className="where-used-input-wrap">
            <span className="visually-hidden">IP, CIDR, or object name</span>
            <input
              type="text"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="e.g. 10.10.1.5, 10.10.1.0/24, 10.10.1.1-10.10.1.10, or LAN_SUBNET"
            />
          </label>
          <button type="submit" className="primary-button button-compact" disabled={loading}>
            {loading ? 'Searching…' : 'Search'}
          </button>
          {(result || query || error) && (
            <button
              type="button"
              className="secondary-button button-compact"
              onClick={() => {
                setQuery('')
                setResult(null)
                setError(null)
              }}
            >
              Clear
            </button>
          )}
        </form>

        {error && <ErrorBanner message={error} />}

        {result && (
          <div className="where-used-results">
            <div className="where-used-meta">
              <div className="where-used-badges">
                <span className="fw-badge fw-badge-info">Mode: {result.query_type.toUpperCase()}</span>
                <span className={`fw-badge ${result.total_matches > 0 ? 'fw-badge-allow' : 'fw-badge-muted'}`}>
                  {result.total_matches} {result.total_matches === 1 ? 'match' : 'matches'}
                </span>
              </div>
              {result.total_matches > 0 && (
                <button type="button" className="secondary-button button-compact" onClick={exportAllCsv}>
                  ⬇ Export CSV
                </button>
              )}
            </div>

            {result.resolved_objects.length > 0 && (
              <div className="where-used-resolved">
                <strong>Resolved objects ({result.resolved_objects.length}):</strong>
                <div className="where-used-pills">
                  {result.resolved_objects.map((name) => (
                    <span key={name} className="fw-badge fw-badge-purple">{name}</span>
                  ))}
                </div>
              </div>
            )}

            {result.total_matches === 0 ? (
              <p className="where-used-empty">No references matched &ldquo;{result.query}&rdquo;.</p>
            ) : (
              <div className="where-used-categories">
                {result.categories.filter((cat) => cat.count > 0).map((cat) => (
                  <section key={cat.key} className="where-used-category">
                    <h4>
                      {cat.label} <span className="where-used-cat-count">({cat.count})</span>
                    </h4>
                    <div className="where-used-table-wrap">
                      <table className="where-used-table">
                        <thead>
                          <tr>
                            {cat.columns.map((col) => (
                              <th key={col} scope="col">{fieldLabel(col)}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {cat.rows.map((row, idx) => (
                            <tr key={`${cat.key}-${idx}`}>
                              {cat.columns.map((col) => (
                                <td key={col}>{cellSummary(row[col])}</td>
                              ))}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </section>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </details>
  )
}
