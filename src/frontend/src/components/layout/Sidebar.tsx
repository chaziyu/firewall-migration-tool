import { UpdateChecker } from './UpdateChecker'

export type SidebarReportSection = {
  label: string
  count?: number | null
  tone?: 'danger' | 'warning'
}

export type SidebarWorkspaceMeta = {
  vendorLabel: string
  filename: string
  errors?: number
  warnings?: number
  activeSection?: string
  activeSubsectionLabel?: string
  reportSections?: SidebarReportSection[]
}

const SECTION_ICON_PATHS: Record<string, string> = {
  Overview: 'M4 5h6v6H4zM14 5h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z',
  'Security & Health': 'M12 3 5 6v6c0 4.5 3 7.8 7 9 4-1.2 7-4.5 7-9V6l-7-3Zm-2.5 9 1.8 1.8 3.5-3.6',
  'Policies & NAT': 'M4 6h16M4 12h16M4 18h10M17 16l3 2-3 2',
  Objects: 'M12 3 4 7.5 12 12l8-4.5L12 3ZM4 12l8 4.5 8-4.5M4 16.5 12 21l8-4.5',
  'Interfaces & Network': 'M4 6h5v4H4zM15 6h5v4h-5zM9.5 14h5v4h-5zM6.5 10v2h11v-2M12 12v2',
  'Security Profiles': 'M7 11V7a5 5 0 0 1 10 0v4M5 11h14v9H5z',
  VPN: 'M15 7a4 4 0 1 1-3.4 6.1L7 17.7V20H4.5v-2.5L9.9 12A4 4 0 0 1 15 7Z',
  'Users & Auth': 'M16 19v-1a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v1M9.5 10a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7ZM21 19v-1a3.5 3.5 0 0 0-2.5-3.3M16.5 3.3a3.5 3.5 0 0 1 0 6.4',
  'WiFi & Switch': 'M5 12.5a10 10 0 0 1 14 0M8.5 15.5a5.5 5.5 0 0 1 7 0M12 19h.01',
  'System & Logs': 'M4 6h16v12H4zM8 10h8M8 14h5',
  'Diagnostics & Coverage': 'M9 4h6M9 4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2M9 10h6M9 14h4',
  'Additional sections': 'M12 4v16M4 12h16',
}

function SectionIcon({ label }: { label: string }) {
  const path = SECTION_ICON_PATHS[label] ?? 'M6 4h9l4 4v12H6z'
  return (
    <svg
      className="fw-nav-svg"
      viewBox="0 0 24 24"
      width="15"
      height="15"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={path} />
    </svg>
  )
}

function renderSidebarBody({
  collapsed,
  workspaceMeta,
  onSelectReportSection,
  onNewWorkspace,
}: {
  collapsed: boolean
  workspaceMeta?: SidebarWorkspaceMeta | null
  onSelectReportSection?: (section: string) => void
  onNewWorkspace?: () => void
}) {
  const hasSections = Boolean(workspaceMeta?.reportSections && workspaceMeta.reportSections.length > 0)

  return (
    <>
      <a className="brand" href="/" aria-label="Firewall Config Reader home" title="Firewall Config Reader">
        <span className="brand-mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 3 5 6v6c0 4.5 3 7.8 7 9 4-1.2 7-4.5 7-9V6l-7-3Z" />
            <path d="M9 12h6M12 9v6" />
          </svg>
        </span>
        {!collapsed && (
          <span className="brand-wordmark">
            <span>Firewall</span>
            <small>CONFIG READER</small>
          </span>
        )}
      </a>

      {!collapsed && hasSections && (
        <div className="fw-nav-group fw-nav-group-sections">
          <div className="fw-nav-label">Workspace</div>
          <nav className="fw-nav-list" role="tablist" aria-orientation="vertical" aria-label="Report sections navigation">
            {workspaceMeta!.reportSections!.map((sec) => {
              const isActive = workspaceMeta?.activeSection === sec.label
              return (
                <a
                  key={sec.label}
                  href={`#report-tab-${encodeURIComponent(sec.label)}`}
                  role="tab"
                  aria-selected={isActive}
                  aria-label={sec.label}
                  className={`fw-nav-btn${isActive ? ' active' : ''}`}
                  aria-current={isActive ? 'location' : undefined}
                  onClick={(event) => {
                    event.preventDefault()
                    onSelectReportSection?.(sec.label)
                  }}
                >
                  <span className="fw-nav-icon" aria-hidden="true">
                    <SectionIcon label={sec.label} />
                  </span>
                  <span className="fw-nav-text">{sec.label}</span>
                  {sec.count != null && (
                    <span className={`fw-nav-count${sec.tone ? ` fw-nav-count-${sec.tone}` : ''}`} aria-hidden="true">
                      {sec.count.toLocaleString()}
                    </span>
                  )}
                </a>
              )
            })}
          </nav>
        </div>
      )}

      <div className="fw-sidebar-bottom">
        {workspaceMeta && onNewWorkspace && (
          <button
            type="button"
            className="fw-sidebar-reset-btn"
            title={collapsed ? 'Load new config' : undefined}
            aria-label="Load new config"
            onClick={() => {
              if (typeof window === 'undefined' || typeof window.confirm !== 'function' || window.confirm('Load a new configuration? This clears the current session from this window.')) {
                onNewWorkspace()
              }
            }}
          >
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M12 16V4m0 0-4 4m4-4 4 4M4 17v2a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-2" />
            </svg>
            {!collapsed && <span>Load new config</span>}
          </button>
        )}
        <UpdateChecker collapsed={collapsed} />
      </div>
    </>
  )
}

export function Sidebar({
  collapsed = false,
  mobileOpen = false,
  onClose,
  workspaceMeta,
  onSelectReportSection,
  onNewWorkspace,
}: {
  collapsed?: boolean
  mobileOpen?: boolean
  onClose?: () => void
  workspaceMeta?: SidebarWorkspaceMeta | null
  onSelectReportSection?: (section: string) => void
  onNewWorkspace?: () => void
}) {
  return (
    <>
      <aside className={collapsed ? 'sidebar collapsed' : 'sidebar'} aria-label="Main navigation">
        {renderSidebarBody({
          collapsed,
          workspaceMeta,
          onSelectReportSection,
          onNewWorkspace,
        })}
      </aside>
      {mobileOpen && (
        <div className="sidebar-mobile-backdrop" role="presentation">
          <div className="sidebar-mobile-scrim" onClick={onClose} />
          <aside className="sidebar-mobile-drawer" aria-label="Mobile navigation">
            {renderSidebarBody({
              collapsed: false,
              workspaceMeta,
              onSelectReportSection: (sec) => {
                onSelectReportSection?.(sec)
                onClose?.()
              },
              onNewWorkspace: onNewWorkspace
                ? () => {
                    onNewWorkspace()
                    onClose?.()
                  }
                : undefined,
            })}
          </aside>
        </div>
      )}
    </>
  )
}
