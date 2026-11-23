import { useState, type ReactNode } from 'react'
import { PageHeader } from './PageHeader'
import { Sidebar, type SidebarWorkspaceMeta } from './Sidebar'
import type { WorkflowView } from '../../features/source/SourceConfiguration'

export function AppLayout({ children, view, onViewChange, page, theme, onNewWorkspace, onToggleTheme, liveDeviceAccess, defaultCollapsed = true, workspaceMeta, onSelectReportSection, onSelectMigrationStage }: {
  children: ReactNode
  view: WorkflowView
  liveDeviceAccess: boolean
  onViewChange: (view: WorkflowView) => void
  page: { title: string; description: string }
  theme: 'light' | 'dark'
  onNewWorkspace: () => void
  onToggleTheme: () => void
  defaultCollapsed?: boolean
  workspaceMeta?: SidebarWorkspaceMeta | null
  onSelectReportSection?: (section: string) => void
  onSelectMigrationStage?: (stage: string) => void
}) {
  const [collapsed, setCollapsed] = useState(defaultCollapsed)
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <div className="app-layout fw-shell">
      <Sidebar
        view={view}
        onViewChange={onViewChange}
        liveDeviceAccess={liveDeviceAccess}
        collapsed={collapsed}
        mobileOpen={mobileOpen}
        onClose={() => setMobileOpen(false)}
        workspaceMeta={workspaceMeta}
        onSelectReportSection={onSelectReportSection}
        onSelectMigrationStage={onSelectMigrationStage}
      />
      <main className="app-content fw-main">
        <PageHeader
          page={page}
          theme={theme}
          collapsed={collapsed}
          onCollapseClick={() => setCollapsed((current) => !current)}
          onMenuClick={() => setMobileOpen(true)}
          onNewWorkspace={onNewWorkspace}
          onToggleTheme={onToggleTheme}
        />
        {children}
      </main>
    </div>
  )
}

