import { useEffect, useRef, useState } from 'react'
import type { WorkflowView } from '../../features/source/SourceConfiguration'
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
  migrationPairLabel?: string
  migrationStages?: Array<{ id: string; label: string; active: boolean }>
}

const navigation: Array<{ id: WorkflowView; label: string }> = [
  { id: 'report', label: 'Configuration report' },
  { id: 'collect', label: 'Live collection' },
  { id: 'migration', label: 'Plan migration' },
]

const navIcons: Record<WorkflowView, string> = {
  report: 'M14 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V9Zm0 0v6h7M8 13h8M8 17h8',
  collect: 'M12 8V4m0 0H8m4 0 3 3m-3 1a4 4 0 1 0 4 4M5.5 16H2v6h7v-6H5.5Zm13 0H15v6h7v-6h-3.5ZM12 12v4m-6.5 0v-4h13v4',
  migration: 'M4 18a2.5 2.5 0 1 0 0 .1M20 8a2.5 2.5 0 1 0 0 .1M6.5 18H9a4 4 0 0 0 4-4v-1a4 4 0 0 1 4-4h.5m-3-3 3 3-3 3',
}

const sectionIcons: Record<string, string> = {
  Overview: '📊',
  'Security & Health': '🩺',
  'Policies & NAT': '🛡',
  Objects: '📦',
  'Interfaces & Network': '🔌',
  'Security Profiles': '🔒',
  VPN: '🔑',
  'Users & Auth': '👥',
  'WiFi & Switch': '📶',
  'Diagnostics & Coverage': '📋',
  'Additional sections': '🧩',
}

function renderModeSelector({
  view,
  liveDeviceAccess,
  collapsed,
  onSelect,
  open,
  setOpen,
  containerRef,
}: {
  view: WorkflowView
  liveDeviceAccess: boolean
  collapsed: boolean
  onSelect: (view: WorkflowView) => void
  open: boolean
  setOpen: (next: boolean | ((current: boolean) => boolean)) => void
  containerRef: React.RefObject<HTMLDivElement | null>
}) {
  const items = navigation.filter((item) => liveDeviceAccess || item.id !== 'collect')
  const activeItem = items.find((item) => item.id === view) ?? items[0]

  return (
    <div className="fw-nav-group fw-mode-selector" ref={containerRef}>
      {!collapsed && <div className="fw-nav-label">Mode</div>}
      <button
        type="button"
        className={`fw-mode-trigger${open ? ' open' : ''}`}
        title={collapsed ? `Mode: ${activeItem.label}` : undefined}
        aria-label={`Mode: ${activeItem.label}`}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((current) => !current)}
      >
        <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d={navIcons[activeItem.id]} />
        </svg>
        {!collapsed && (
          <>
            <span className="fw-mode-trigger-label">{activeItem.label}</span>
            <span className="fw-mode-chevron" aria-hidden="true">▾</span>
          </>
        )}
      </button>
      {open && (
        <div className={`fw-mode-menu${collapsed ? ' collapsed' : ''}`} role="menu" aria-label="Workflow modes">
          {items.map((item) => {
            const selected = view === item.id
            return (
              <button
                key={item.id}
                type="button"
                role="menuitemradio"
                aria-checked={selected}
                className={`fw-mode-option${selected ? ' active' : ''}`}
                onClick={() => {
                  onSelect(item.id)
                  setOpen(false)
                }}
              >
                <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d={navIcons[item.id]} />
                </svg>
                <span>{item.label}</span>
                {selected && <span className="fw-mode-check" aria-hidden="true">✓</span>}
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}

function renderSidebarBody({ view, liveDeviceAccess, collapsed, onSelect, workspaceMeta, onSelectReportSection, onSelectMigrationStage, modeOpen, setModeOpen, modeContainerRef }: {
  view: WorkflowView
  liveDeviceAccess: boolean
  collapsed: boolean
  onSelect: (view: WorkflowView) => void
  workspaceMeta?: SidebarWorkspaceMeta | null
  onSelectReportSection?: (section: string) => void
  onSelectMigrationStage?: (stage: string) => void
  modeOpen: boolean
  setModeOpen: (next: boolean | ((current: boolean) => boolean)) => void
  modeContainerRef: React.RefObject<HTMLDivElement | null>
}) {
  return (
    <>
      <a className="brand" href="/" aria-label="Firewall Migration Tool home" title="Firewall Migration Tool">
        <span className="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M4 7h16m-4-4 4 4-4 4M20 17H4m4 4-4-4 4-4" /></svg></span>
        {!collapsed && <span className="brand-wordmark"><span>Firewall</span><small>MIGRATION TOOL</small></span>}
      </a>

      {renderModeSelector({ view, liveDeviceAccess, collapsed, onSelect, open: modeOpen, setOpen: setModeOpen, containerRef: modeContainerRef })}

      {!collapsed && view === 'report' && workspaceMeta?.reportSections && workspaceMeta.reportSections.length > 0 && (
        <div className="fw-nav-group fw-nav-group-sections">
          <div className="fw-nav-label">Workspace Sections</div>
          <nav className="fw-nav-list" role="tablist" aria-orientation="vertical" aria-label="Report sections navigation">
            {workspaceMeta.reportSections.map((sec) => {
              const isActive = workspaceMeta.activeSection === sec.label
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
                  <span className="fw-nav-icon" aria-hidden="true">{sectionIcons[sec.label] ?? '📄'}</span>
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

      {!collapsed && view === 'migration' && workspaceMeta?.migrationStages && workspaceMeta.migrationStages.length > 0 && (
        <div className="fw-nav-group fw-nav-group-sections">
          <div className="fw-nav-label">{workspaceMeta.migrationPairLabel || 'Migration Stages'}</div>
          <nav className="fw-nav-list" aria-label="Migration stages navigation">
            {workspaceMeta.migrationStages.map((stg, idx) => (
              <a
                key={stg.id}
                href={`#migration-stage-${stg.id}`}
                className={`fw-nav-btn${stg.active ? ' active' : ''}`}
                aria-current={stg.active ? 'step' : undefined}
                onClick={(event) => {
                  event.preventDefault()
                  onSelectMigrationStage?.(stg.id)
                }}
              >
                <span className="fw-nav-step-num" aria-hidden="true">{idx + 1}</span>
                <span className="fw-nav-text">{stg.label}</span>
              </a>
            ))}
          </nav>
        </div>
      )}

      <UpdateChecker collapsed={collapsed} />
    </>
  )
}

export function Sidebar({ view, onViewChange, liveDeviceAccess, collapsed = false, mobileOpen = false, onClose, workspaceMeta, onSelectReportSection, onSelectMigrationStage }: {
  view: WorkflowView
  liveDeviceAccess: boolean
  onViewChange: (view: WorkflowView) => void
  collapsed?: boolean
  mobileOpen?: boolean
  onClose?: () => void
  workspaceMeta?: SidebarWorkspaceMeta | null
  onSelectReportSection?: (section: string) => void
  onSelectMigrationStage?: (stage: string) => void
}) {
  const [modeOpen, setModeOpen] = useState(false)
  const modeContainerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!modeOpen || typeof document === 'undefined') return
    const onPointerDown = (event: MouseEvent) => {
      if (modeContainerRef.current && !modeContainerRef.current.contains(event.target as Node)) {
        setModeOpen(false)
      }
    }
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setModeOpen(false)
    }
    document.addEventListener('mousedown', onPointerDown)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('mousedown', onPointerDown)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [modeOpen])

  return (
    <>
      <aside className={collapsed ? 'sidebar collapsed' : 'sidebar'} aria-label="Main navigation">
        {renderSidebarBody({
          view,
          liveDeviceAccess,
          collapsed,
          onSelect: onViewChange,
          workspaceMeta,
          onSelectReportSection,
          onSelectMigrationStage,
          modeOpen,
          setModeOpen,
          modeContainerRef,
        })}
      </aside>
      {mobileOpen && (
        <div className="sidebar-mobile-backdrop" role="presentation">
          <div className="sidebar-mobile-scrim" onClick={onClose} />
          <aside className="sidebar-mobile-drawer" aria-label="Mobile navigation">
            {renderSidebarBody({
              view,
              liveDeviceAccess,
              collapsed: false,
              onSelect: (nextView) => {
                onViewChange(nextView)
                onClose?.()
              },
              workspaceMeta,
              onSelectReportSection: (sec) => {
                onSelectReportSection?.(sec)
                onClose?.()
              },
              onSelectMigrationStage: (stg) => {
                onSelectMigrationStage?.(stg)
                onClose?.()
              },
              modeOpen,
              setModeOpen,
              modeContainerRef,
            })}
          </aside>
        </div>
      )}
    </>
  )
}

