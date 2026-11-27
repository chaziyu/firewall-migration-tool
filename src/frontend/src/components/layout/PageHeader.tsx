import { Button } from '../common/Button'
import type { SidebarWorkspaceMeta } from './Sidebar'

export type WorkspaceTopbarActions = {
  canSearch: boolean
  canAudit: boolean
  excelProfile: 'fast' | 'full'
  exporting: boolean
  auditExporting: boolean
  onOpenSearch: () => void
  onExportAuditReport: () => void
  onExcelProfileChange: (profile: 'fast' | 'full') => void
  onExportExcel: () => void
}

export function PageHeader({
  page,
  theme,
  collapsed = false,
  onCollapseClick,
  onMenuClick,
  onToggleTheme,
  workspaceMeta,
  workspaceActions,
}: {
  page: { title: string; description: string }
  theme: 'light' | 'dark'
  collapsed?: boolean
  onCollapseClick?: () => void
  onMenuClick?: () => void
  onToggleTheme: () => void
  workspaceMeta?: SidebarWorkspaceMeta | null
  workspaceActions?: WorkspaceTopbarActions | null
}) {
  return (
    <header className="page-header fw-workspace-bar">
      <div className="page-header-leading">
        {onCollapseClick && (
          <Button
            variant="secondary"
            className="sidebar-toggle sidebar-collapse-toggle"
            type="button"
            aria-expanded={!collapsed}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            onClick={onCollapseClick}
          >
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <rect x="3" y="4" width="18" height="16" rx="2" />
              <path d="M9 4v16" />
            </svg>
          </Button>
        )}
        {onMenuClick && (
          <Button
            variant="secondary"
            className="sidebar-toggle sidebar-menu-toggle"
            type="button"
            aria-label="Open navigation menu"
            title="Open navigation menu"
            onClick={onMenuClick}
          >
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </Button>
        )}
        <div className="fw-crumb-wrap">
          {workspaceMeta ? (
            <div className="fw-workspace-crumb" aria-label="Active workspace">
              <span className="fw-crumb-vendor">{workspaceMeta.vendorLabel}</span>
              <span className="fw-workspace-sep" aria-hidden="true">/</span>
              <span className="fw-crumb-section">{workspaceMeta.activeSection || 'Overview'}</span>
              {workspaceMeta.filename && (
                <span className="fw-workspace-file" title={workspaceMeta.filename}>
                  {workspaceMeta.filename}
                </span>
              )}
            </div>
          ) : (
            <h1>{page.title}</h1>
          )}
        </div>
      </div>

      <div className="page-header-actions fw-topbar-actions">
        {workspaceMeta && workspaceActions && (
          <>
            {workspaceActions.canSearch && (
              <Button
                variant="secondary"
                className="fw-topbar-btn fw-qs-trigger"
                type="button"
                title="Global Quick Search (Ctrl+K)"
                onClick={workspaceActions.onOpenSearch}
              >
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <circle cx="11" cy="11" r="7" />
                  <path d="m20 20-3.5-3.5" />
                </svg>
                <span>Search</span>
                <kbd className="fw-kbd">Ctrl+K</kbd>
              </Button>
            )}
            {workspaceActions.canAudit && (
              <Button
                variant="secondary"
                className="fw-topbar-btn"
                type="button"
                disabled={workspaceActions.auditExporting}
                aria-busy={workspaceActions.auditExporting}
                title="Export Security & Health Audit Report (HTML / Print to PDF)"
                onClick={workspaceActions.onExportAuditReport}
              >
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9Zm0 0v6h6M8 13h8M8 17h5" />
                </svg>
                <span>{workspaceActions.auditExporting ? 'Generating…' : 'Audit Report'}</span>
              </Button>
            )}
            <div className="fw-topbar-excel-group">
              <select
                aria-label="Excel export profile"
                className="fw-topbar-profile-select"
                value={workspaceActions.excelProfile}
                disabled={workspaceActions.exporting}
                onChange={(event) => workspaceActions.onExcelProfileChange(event.target.value as 'fast' | 'full')}
              >
                <option value="fast">FAST</option>
                <option value="full">FULL</option>
              </select>
              <Button
                variant="secondary"
                className="fw-topbar-btn fw-topbar-excel-btn"
                type="button"
                disabled={workspaceActions.exporting}
                aria-busy={workspaceActions.exporting}
                title="Export extracted configuration to Excel (.xlsx)"
                onClick={workspaceActions.onExportExcel}
              >
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M12 4v11m0 0-4-4m4 4 4-4M4 17v2a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-2" />
                </svg>
                <span>{workspaceActions.exporting ? 'Exporting…' : 'Export to Excel'}</span>
              </Button>
            </div>
          </>
        )}

        <Button
          variant="secondary"
          className="theme-toggle fw-topbar-btn"
          type="button"
          onClick={onToggleTheme}
          aria-pressed={theme === 'dark'}
        >
          {theme === 'dark' ? (
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <circle cx="12" cy="12" r="4" />
              <path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4m11.4-11.4 1.4-1.4" />
            </svg>
          ) : (
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M20 15a8 8 0 1 1-11-11 7 7 0 0 0 11 11Z" />
            </svg>
          )}
          <span>{theme === 'dark' ? 'Light' : 'Dark'}</span>
        </Button>
      </div>
    </header>
  )
}
