import { useState, type ReactNode } from 'react'
import { PageHeader } from './PageHeader'
import { Sidebar } from './Sidebar'
import type { WorkflowView } from '../../features/source/SourceConfiguration'

export function AppLayout({ children, view, onViewChange, page, theme, onNewWorkspace, onToggleTheme, liveDeviceAccess }: {
  children: ReactNode
  view: WorkflowView
  liveDeviceAccess: boolean
  onViewChange: (view: WorkflowView) => void
  page: { title: string; description: string }
  theme: 'light' | 'dark'
  onNewWorkspace: () => void
  onToggleTheme: () => void
}) {
  const [collapsed, setCollapsed] = useState(true)
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <div className="app-layout">
      <Sidebar
        view={view}
        onViewChange={onViewChange}
        liveDeviceAccess={liveDeviceAccess}
        collapsed={collapsed}
        mobileOpen={mobileOpen}
        onClose={() => setMobileOpen(false)}
      />
      <main className="app-content">
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
