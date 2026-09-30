import type { ReactNode } from 'react'
import { PageHeader } from './PageHeader'
import { Sidebar } from './Sidebar'
import type { WorkflowView } from '../../features/source/SourceConfiguration'

export function AppLayout({ children, view, onViewChange, page, theme, onNewWorkspace, onToggleTheme }: {
  children: ReactNode
  view: WorkflowView
  onViewChange: (view: WorkflowView) => void
  page: { title: string; description: string }
  theme: 'light' | 'dark'
  onNewWorkspace: () => void
  onToggleTheme: () => void
}) {
  return (
    <div className="app-layout">
      <Sidebar view={view} onViewChange={onViewChange} />
      <div className="app-content">
        <PageHeader page={page} theme={theme} onNewWorkspace={onNewWorkspace} onToggleTheme={onToggleTheme} />
        {children}
      </div>
    </div>
  )
}
