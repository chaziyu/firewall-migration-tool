import { ThemeColorPicker } from './ThemeColorPicker'
import { ZoomControl } from './ZoomControl'
import { Button } from '../common/Button'

export function PageHeader({ page, theme, collapsed = false, onCollapseClick, onMenuClick, onNewWorkspace, onToggleTheme }: {
  page: { title: string; description: string }
  theme: 'light' | 'dark'
  collapsed?: boolean
  onCollapseClick?: () => void
  onMenuClick?: () => void
  onNewWorkspace: () => void
  onToggleTheme: () => void
}) {
  return (
    <header className="page-header">
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
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
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
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </Button>
        )}
        <div>
          <h1>{page.title}</h1>
          <span className="page-description">{page.description}</span>
        </div>
      </div>
      <div className="page-header-actions">
        <ZoomControl />
        <ThemeColorPicker theme={theme} />
        <Button variant="secondary" className="new-workspace" type="button" onClick={() => {
          if (window.confirm('Start a new workspace? This clears the current source from this window.')) onNewWorkspace()
        }}><span aria-hidden="true">＋</span> New workspace</Button>
        <Button variant="secondary" className="theme-toggle" type="button" onClick={onToggleTheme} aria-pressed={theme === 'dark'}>
          <span aria-hidden="true">{theme === 'dark' ? '☼' : '☾'}</span>{theme === 'dark' ? 'Light mode' : 'Dark mode'}
        </Button>
      </div>
    </header>
  )
}
