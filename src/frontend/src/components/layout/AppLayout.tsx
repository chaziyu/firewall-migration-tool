import { useState, type ReactNode } from 'react'
import { PageHeader, type WorkspaceTopbarActions } from './PageHeader'
import { Sidebar, type SidebarWorkspaceMeta } from './Sidebar'

export function AppLayout({
  children,
  page,
  theme,
  onNewWorkspace,
  onToggleTheme,
  defaultCollapsed = true,
  workspaceMeta,
  workspaceActions,
  onSelectReportSection,
}: {
  children: ReactNode
  page: { title: string; description: string }
  theme: 'light' | 'dark'
  onNewWorkspace: () => void
  onToggleTheme: () => void
  defaultCollapsed?: boolean
  workspaceMeta?: SidebarWorkspaceMeta | null
  workspaceActions?: WorkspaceTopbarActions | null
  onSelectReportSection?: (section: string) => void
}) {
  const [collapsed, setCollapsed] = useState(defaultCollapsed)
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <div className="app-layout fw-shell">
      <Sidebar
        collapsed={collapsed}
        mobileOpen={mobileOpen}
        onClose={() => setMobileOpen(false)}
        workspaceMeta={workspaceMeta}
        onSelectReportSection={onSelectReportSection}
        onNewWorkspace={onNewWorkspace}
      />
      <main className="app-content fw-main">
        <PageHeader
          page={page}
          theme={theme}
          collapsed={collapsed}
          onCollapseClick={() => setCollapsed((current) => !current)}
          onMenuClick={() => setMobileOpen(true)}
          onToggleTheme={onToggleTheme}
          workspaceMeta={workspaceMeta}
          workspaceActions={workspaceActions}
        />
        {children}
      </main>
    </div>
  )
}
