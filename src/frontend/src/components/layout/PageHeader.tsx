import { ThemeColorPicker } from './ThemeColorPicker'

export function PageHeader({ page, theme, onNewWorkspace, onToggleTheme }: {
  page: { title: string; description: string }
  theme: 'light' | 'dark'
  onNewWorkspace: () => void
  onToggleTheme: () => void
}) {
  return (
    <header className="page-header">
      <div>
        <h1>{page.title}</h1>
        <span className="page-description">{page.description}</span>
      </div>
      <div className="page-header-actions">
        <ThemeColorPicker theme={theme} />
        <button className="secondary-button new-workspace" type="button" onClick={() => {
          if (window.confirm('Start a new workspace? This clears the current source from this window.')) onNewWorkspace()
        }}><span aria-hidden="true">＋</span> New workspace</button>
        <button className="theme-toggle" type="button" onClick={onToggleTheme} aria-pressed={theme === 'dark'}>
          <span aria-hidden="true">{theme === 'dark' ? '☼' : '☾'}</span>{theme === 'dark' ? 'Light mode' : 'Dark mode'}
        </button>
      </div>
    </header>
  )
}
