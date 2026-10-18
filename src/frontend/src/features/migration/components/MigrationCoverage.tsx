import { useState } from 'react'
import { Button } from '../../../components/common/Button'

export type MigrationCoverageReport = {
  source_record_count: number
  status_counts: Record<string, number>
  records: Array<{ source_vdom: string | null; source_scope: string; source_path: string; source_name: string | null; status: string }>
  inventory_available: boolean
}

export function MigrationCoverage({ coverage }: { coverage?: MigrationCoverageReport }) {
  const [page, setPage] = useState(1)
  if (!coverage) return null
  const pages = Math.max(1, Math.ceil(coverage.records.length / 25))
  const current = Math.min(page, pages)
  return <details>
    <summary>Source coverage — {coverage.source_record_count} records</summary>
    <p>An approved export can cover only part of the source. Unsupported sections and unapproved changes remain work to review.</p>
    {!coverage.inventory_available && <p role="status">Source inventory is unavailable. Complete coverage cannot be established.</p>}
    <ul>{Object.entries(coverage.status_counts).map(([status, count]) => <li key={status}>{status.toLowerCase().replaceAll('_', ' ')}: {count}</li>)}</ul>
    <div className="report-table-wrap"><table className="report-table">
      <caption>Scoped source coverage</caption><thead><tr><th>Scope</th><th>Source section</th><th>Source item</th><th>Status</th></tr></thead>
      <tbody>{coverage.records.slice((current - 1) * 25, current * 25).map((row, index) => <tr key={index}>
        <td>{row.source_scope} / {row.source_vdom ?? 'Unspecified'}</td><td>{row.source_path}</td><td>{row.source_name ?? 'Section settings'}</td><td>{row.status.toLowerCase().replaceAll('_', ' ')}</td>
      </tr>)}</tbody>
    </table></div>
    <p>Page {current} of {pages}</p>
    <Button disabled={current === 1} onClick={() => setPage(current - 1)}>Previous coverage page</Button>
    <Button disabled={current === pages} onClick={() => setPage(current + 1)}>Next coverage page</Button>
  </details>
}
