import { useMemo, useState } from 'react'
import { asRecord, asRows, cellBadgeVariant, downloadCsvRows, isMonoColumn } from './reportPresentation'
import './SdwanView.css'

type SdwanTableRow = Record<string, string | number | null>

type SdwanColumn = {
  key: string
  label: string
}

const ZONE_COLUMNS: SdwanColumn[] = [
  { key: 'zone', label: 'Zone' },
  { key: 'seq', label: 'Seq' },
  { key: 'interface', label: 'Interface' },
  { key: 'gateway', label: 'Gateway' },
  { key: 'cost', label: 'Cost' },
  { key: 'priority', label: 'Priority' },
  { key: 'status', label: 'Status' },
]

const RULE_COLUMNS: SdwanColumn[] = [
  { key: 'id', label: 'ID' },
  { key: 'name', label: 'Name' },
  { key: 'source', label: 'Source' },
  { key: 'destination', label: 'Destination' },
  { key: 'criteria', label: 'Criteria' },
  { key: 'members', label: 'Members' },
  { key: 'sla', label: 'Performance SLA' },
  { key: 'port', label: 'Port' },
  { key: 'protocol', label: 'Protocol' },
  { key: 'status', label: 'Status' },
]

const SLA_COLUMNS: SdwanColumn[] = [
  { key: 'name', label: 'Name' },
  { key: 'server', label: 'Detect Server' },
  { key: 'protocol', label: 'Protocol' },
  { key: 'interval', label: 'Interval (ms)' },
  { key: 'recoverytime', label: 'Recovery Threshold' },
  { key: 'members', label: 'Members' },
  { key: 'latency', label: 'Latency (ms)' },
  { key: 'jitter', label: 'Jitter (ms)' },
  { key: 'packetloss', label: 'Pkt Loss (%)' },
]

function strOrDash(value: unknown): string {
  if (value == null || value === '') return '—'
  if (Array.isArray(value)) {
    const items = value.map((item) => String(item ?? '').trim()).filter(Boolean)
    return items.length ? items.join(', ') : '—'
  }
  return String(value)
}

function titleStatus(value: unknown, fallback = '—'): string {
  const raw = String(value ?? '').trim()
  if (!raw) return fallback
  const lower = raw.toLowerCase()
  if (lower === 'enable' || lower === 'enabled') return 'Enable'
  if (lower === 'disable' || lower === 'disabled') return 'Disable'
  return raw
}

function formatProtocol(value: unknown): string {
  if (value == null || value === '') return '—'
  const raw = String(value).trim()
  const map: Record<string, string> = { '6': 'TCP', '17': 'UDP', '1': 'ICMP' }
  return map[raw] ?? raw
}

function formatPortRange(startPort: unknown, endPort: unknown): string {
  const s = startPort == null || startPort === '' ? '' : String(startPort)
  const e = endPort == null || endPort === '' ? '' : String(endPort)
  if (s && e && s !== e) return `${s}-${e}`
  if (s) return s
  if (e) return e
  return '—'
}

function formatCriteria(rule: Record<string, unknown>): string {
  const parts: string[] = []
  const mode = String(rule.mode ?? '').trim()
  if (mode) parts.push(`Mode: ${mode.charAt(0).toUpperCase()}${mode.slice(1)}`)
  const hc = Array.isArray(rule.health_check)
    ? rule.health_check.map(String).filter(Boolean).join(', ')
    : String(rule.health_check ?? '').trim()
  if (hc) parts.push(`SLA: ${hc}`)
  const costFactor = String(rule.link_cost_factor ?? '').trim()
  if (costFactor) {
    const nice = costFactor.replace(/-/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
    parts.push(`Cost: ${nice}`)
  }
  return parts.length ? parts.join(' | ') : 'Best Quality'
}

function buildZoneMemberRows(entry: Record<string, unknown>): SdwanTableRow[] {
  const zones = asRows(entry.zones)
  const members = asRows(entry.members)
  const rows: SdwanTableRow[] = []
  const matchedMemberIndexes = new Set<number>()

  for (const zone of zones) {
    const zoneName = String(zone.name ?? '').trim() || '—'
    const zoneMembers: Array<{ member: Record<string, unknown>; index: number }> = []
    members.forEach((member, index) => {
      const mZone = String(member.zone ?? '').trim() || (zones.length === 1 ? zoneName : '')
      if (mZone === zoneName) {
        zoneMembers.push({ member, index })
        matchedMemberIndexes.add(index)
      }
    })
    if (zoneMembers.length > 0) {
      for (const { member } of zoneMembers) {
        rows.push({
          zone: zoneName,
          seq: member.seq_num != null ? Number(member.seq_num) : '—',
          interface: strOrDash(member.interface),
          gateway: strOrDash(member.gateway),
          cost: member.cost != null ? Number(member.cost) : '—',
          priority: member.priority != null ? Number(member.priority) : '—',
          status: titleStatus(member.status, 'Enable'),
        })
      }
    } else {
      rows.push({
        zone: zoneName,
        seq: '—',
        interface: '(no members)',
        gateway: '—',
        cost: '—',
        priority: '—',
        status: '—',
      })
    }
  }

  members.forEach((member, index) => {
    if (matchedMemberIndexes.has(index)) return
    rows.push({
      zone: String(member.zone ?? '').trim() || 'virtual-wan-link',
      seq: member.seq_num != null ? Number(member.seq_num) : '—',
      interface: strOrDash(member.interface),
      gateway: strOrDash(member.gateway),
      cost: member.cost != null ? Number(member.cost) : '—',
      priority: member.priority != null ? Number(member.priority) : '—',
      status: titleStatus(member.status, 'Enable'),
    })
  })

  return rows
}

function buildRuleRows(entry: Record<string, unknown>): SdwanTableRow[] {
  return asRows(entry.services).map((rule) => {
    const priorityMembers = Array.isArray(rule.priority_members)
      ? rule.priority_members.map(String).filter(Boolean).join(' ')
      : ''
    const priorityZones = Array.isArray(rule.priority_zone)
      ? rule.priority_zone.map(String).filter(Boolean).join(', ')
      : ''
    return {
      id: rule.id != null ? Number(rule.id) : '—',
      name: strOrDash(rule.name),
      source: strOrDash(rule.src),
      destination: strOrDash(rule.dst),
      criteria: formatCriteria(rule),
      members: priorityMembers || priorityZones || '—',
      sla: strOrDash(rule.health_check),
      port: formatPortRange(rule.start_port, rule.end_port),
      protocol: formatProtocol(rule.protocol),
      status: titleStatus(rule.status, 'Enable'),
    }
  })
}

function buildSlaRows(entry: Record<string, unknown>): SdwanTableRow[] {
  return asRows(entry.health_checks).map((hc) => {
    const slaList = asRows(hc.sla)
    const firstSla = slaList[0] ?? {}
    const sysDns = String(hc.system_dns ?? '').trim().toLowerCase() === 'enable'
    const server = sysDns ? 'System DNS' : strOrDash(hc.server)
    const protocol = hc.protocol ? String(hc.protocol).toUpperCase() : 'PING'
    const members = Array.isArray(hc.members) && hc.members.length
      ? hc.members.map(String).join(' ')
      : 'All'
    const latency = hc.latency_threshold ?? firstSla.latency_threshold
    const jitter = hc.jitter_threshold ?? firstSla.jitter_threshold
    const packetloss = hc.packetloss_threshold ?? firstSla.packetloss_threshold
    return {
      name: strOrDash(hc.name),
      server,
      protocol,
      interval: hc.interval != null ? Number(hc.interval) : '—',
      recoverytime: hc.recoverytime != null ? Number(hc.recoverytime) : '—',
      members,
      latency: latency != null ? Number(latency) : '—',
      jitter: jitter != null ? Number(jitter) : '—',
      packetloss: packetloss != null ? Number(packetloss) : '—',
    }
  })
}

function SdwanDataTable({
  title,
  columns,
  rows,
  emptyText,
  csvFilename,
  highlightDisabled = false,
  legend,
}: {
  title: string
  columns: SdwanColumn[]
  rows: SdwanTableRow[]
  emptyText: string
  csvFilename: string
  highlightDisabled?: boolean
  legend?: Array<{ label: string; variant: 'default' | 'danger' }>
}) {
  const [search, setSearch] = useState('')
  const [searchCol, setSearchCol] = useState('__all__')
  const [sortCol, setSortCol] = useState<string | null>(null)
  const [sortAsc, setSortAsc] = useState(true)

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    let next = rows
    if (q) {
      next = rows.filter((row) => {
        if (searchCol !== '__all__') {
          return String(row[searchCol] ?? '').toLowerCase().includes(q)
        }
        return columns.some((col) => String(row[col.key] ?? '').toLowerCase().includes(q))
      })
    }
    if (sortCol) {
      next = next.slice().sort((a, b) => {
        const av = a[sortCol] == null ? '' : String(a[sortCol])
        const bv = b[sortCol] == null ? '' : String(b[sortCol])
        const an = Number(av)
        const bn = Number(bv)
        if (!Number.isNaN(an) && !Number.isNaN(bn) && av !== '' && bv !== '' && av !== '—' && bv !== '—') {
          return sortAsc ? an - bn : bn - an
        }
        return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av)
      })
    }
    return next
  }, [rows, columns, search, searchCol, sortCol, sortAsc])

  function onSort(key: string) {
    if (sortCol === key) setSortAsc(!sortAsc)
    else {
      setSortCol(key)
      setSortAsc(true)
    }
  }

  return (
    <section className="sdwan-section">
      <h3 className="sdwan-section-title">
        <span className="sdwan-section-dot" aria-hidden="true" />
        {title}
      </h3>
      {legend && rows.length > 0 && (
        <div className="fw-legend" aria-label={`${title} legend`}>
          {legend.map((item) => (
            <span key={item.label} className={`fw-legend-item fw-legend-${item.variant}`}>
              <span className="fw-legend-swatch" aria-hidden="true" />
              {item.label}
            </span>
          ))}
        </div>
      )}
      <div className="sdwan-table-card">
        <div className="sdwan-table-toolbar">
          <input
            type="search"
            className="sdwan-search-input"
            value={search}
            placeholder="Filter rows..."
            aria-label={`Filter ${title}`}
            onChange={(event) => setSearch(event.target.value)}
          />
          <div className="sdwan-toolbar-actions">
            <select
              aria-label={`Search column for ${title}`}
              className="fw-table-col-select"
              value={searchCol}
              onChange={(event) => setSearchCol(event.target.value)}
            >
              <option value="__all__">All columns</option>
              {columns.map((col) => (
                <option key={col.key} value={col.key}>{col.label}</option>
              ))}
            </select>
            <button
              type="button"
              className="secondary-button button-compact fw-csv-btn"
              onClick={() => downloadCsvRows(columns.map((c) => c.key), filtered, csvFilename)}
            >
              ⬇ CSV
            </button>
          </div>
        </div>
        {!filtered.length ? (
          <div className="sdwan-empty">
            <p>{rows.length ? 'No rows match the current filters.' : emptyText}</p>
          </div>
        ) : (
          <div className="sdwan-table-scroll">
            <table className="sdwan-table fw-table">
              <thead>
                <tr>
                  {columns.map((col) => (
                    <th key={col.key} scope="col" onClick={() => onSort(col.key)}>
                      {col.label}{sortCol === col.key ? (sortAsc ? ' ▲' : ' ▼') : ''}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map((row, idx) => {
                  const isDisabled = highlightDisabled && String(row.status ?? '').toLowerCase() === 'disable'
                  return (
                    <tr key={`${row.id ?? row.seq ?? row.name ?? idx}-${idx}`} className={isDisabled ? 'row-danger' : undefined}>
                      {columns.map((col) => {
                        const val = row[col.key]
                        const badge = col.key === 'status' ? cellBadgeVariant('status', val) : null
                        const mono = isMonoColumn(col.key) || col.key === 'gateway' || col.key === 'seq' || col.key === 'id'
                        return (
                          <td key={col.key} className={mono ? 'fw-cell-mono' : undefined}>
                            {badge ? <span className={`fw-badge fw-badge-${badge}`}>{String(val)}</span> : String(val ?? '—')}
                          </td>
                        )
                      })}
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
        <div className="sdwan-table-footer">{filtered.length} rows</div>
      </div>
    </section>
  )
}

export function SdwanView({
  rows,
  scope,
}: {
  rows: Record<string, unknown>[]
  scope?: string
}) {
  const entries = useMemo(() => {
    const clean = rows.map(asRecord)
    if (!scope) return clean
    return clean.filter((entry) => String(entry.vdom ?? entry.scope ?? '') === scope)
  }, [rows, scope])

  if (!entries.length) {
    return (
      <div className="fw-card sdwan-empty">
        <p>No SD-WAN configuration found.</p>
      </div>
    )
  }

  return (
    <div className="sdwan-view">
      {entries.map((entry, idx) => {
        const vdom = String(entry.vdom ?? 'root')
        const rawStatus = String(entry.status ?? '').trim()
        const statusLabel = rawStatus ? titleStatus(rawStatus) : 'Not reported'
        const statusBadge = rawStatus.toLowerCase() === 'enable'
          ? 'allow'
          : rawStatus.toLowerCase() === 'disable'
            ? 'deny'
            : 'muted'
        const lbMode = entry.load_balance_mode ? String(entry.load_balance_mode) : ''
        const zoneRows = buildZoneMemberRows(entry)
        const ruleRows = buildRuleRows(entry)
        const slaRows = buildSlaRows(entry)

        return (
          <div key={`${vdom}-${idx}`} className="sdwan-vdom-group">
            <div className="fw-card sdwan-status-card">
              <div className="sdwan-status-left">
                <h3 className="sdwan-status-title">SD-WAN Status</h3>
                {entries.length > 1 && <span className="fw-badge fw-badge-info">VDOM: {vdom}</span>}
                {lbMode && <span className="sdwan-status-meta">Load Balance Mode: {lbMode}</span>}
              </div>
              <span className={`fw-badge fw-badge-${statusBadge}`}>{statusLabel}</span>
            </div>

            <SdwanDataTable
              title="SD-WAN Zones / Members"
              columns={ZONE_COLUMNS}
              rows={zoneRows}
              emptyText="No SD-WAN zones."
              csvFilename={`fg_sdwan_zones_${vdom}.csv`}
            />

            <SdwanDataTable
              title="SD-WAN Rules"
              columns={RULE_COLUMNS}
              rows={ruleRows}
              emptyText="No SD-WAN rules."
              csvFilename={`fg_sdwan_rules_${vdom}.csv`}
              highlightDisabled
              legend={[
                { label: 'Enabled (default)', variant: 'default' },
                { label: 'Disabled Rule (red)', variant: 'danger' },
              ]}
            />

            <SdwanDataTable
              title="Performance SLA"
              columns={SLA_COLUMNS}
              rows={slaRows}
              emptyText="No health checks configured."
              csvFilename={`fg_sdwan_sla_${vdom}.csv`}
            />
          </div>
        )
      })}
    </div>
  )
}
