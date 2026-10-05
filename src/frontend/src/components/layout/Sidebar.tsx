import type { WorkflowView } from '../../features/source/SourceConfiguration'
import { isDesktopRuntime } from '../../api/client'
import { UpdateControl } from '../../features/update/UpdateControl'

const navigation: Array<{ id: WorkflowView; label: string }> = [
  { id: 'report', label: 'Configuration report' },
  { id: 'collect', label: 'Live collection' },
  { id: 'migration', label: 'Plan migration' },
  { id: 'live', label: 'Live migration' },
]

const navIcons: Record<WorkflowView, string> = {
  report: 'M14 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V9Zm0 0v6h7M8 13h8M8 17h8',
  collect: 'M12 8V4m0 0H8m4 0 3 3m-3 1a4 4 0 1 0 4 4M5.5 16H2v6h7v-6H5.5Zm13 0H15v6h7v-6h-3.5ZM12 12v4m-6.5 0v-4h13v4',
  migration: 'M4 18a2.5 2.5 0 1 0 0 .1M20 8a2.5 2.5 0 1 0 0 .1M6.5 18H9a4 4 0 0 0 4-4v-1a4 4 0 0 1 4-4h.5m-3-3 3 3-3 3',
  live: 'M3 3h18v18H3zM8 9l-3 3 3 3m8-6 3 3-3 3m-3-8-2 10',
}

export function Sidebar({ view, onViewChange }: {
  view: WorkflowView
  onViewChange: (view: WorkflowView) => void
}) {
  return (
    <aside className="sidebar" aria-label="Main navigation">
      <a className="brand" href="/" aria-label="Firewall Migration Tool home">
        <span className="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M4 7h16m-4-4 4 4-4 4M20 17H4m4 4-4-4 4-4" /></svg></span>
        <span className="brand-wordmark"><span>Firewall</span><small>MIGRATION TOOL</small></span>
      </a>
      <nav className="workflow-nav" aria-label="Workflow">
        {navigation.map((item) => <button
          key={item.id}
          type="button"
          aria-current={view === item.id ? 'page' : undefined}
          onClick={() => onViewChange(item.id)}
        ><svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={navIcons[item.id]} /></svg><span>{item.label}</span></button>)}
      </nav>
      {isDesktopRuntime() && <UpdateControl />}
    </aside>
  )
}
