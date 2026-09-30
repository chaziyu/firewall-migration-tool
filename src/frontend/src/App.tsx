import { useEffect, useState } from 'react'
import './App.css'
import { AppLayout } from './components/layout/AppLayout'
import { SourceConfiguration, type WorkflowView } from './features/source/SourceConfiguration'

const pages: Record<WorkflowView, { title: string; description: string }> = {
  report: { title: 'Configuration Report', description: 'Review reported source state, validation findings, and inventory.' },
  collect: { title: 'Live Collection', description: 'Collect configuration directly from a supported device.' },
  migration: { title: 'Plan migration', description: 'Review what can be migrated, what needs attention, and generate supported PAN-OS commands.' },
  live: { title: 'Live migration', description: 'Prepare and validate a PAN-OS candidate, then commit it explicitly.' },
}

export default function App() {
  const [view, setView] = useState<WorkflowView>('report')
  const [workspace, setWorkspace] = useState(0)
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    try { return localStorage.getItem('fwmigrate-theme') === 'dark' ? 'dark' : 'light' }
    catch { return 'light' }
  })

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try { localStorage.setItem('fwmigrate-theme', theme) } catch { /* Theme remains active for this page. */ }
  }, [theme])

  return (
    <AppLayout
      view={view}
      onViewChange={setView}
      page={pages[view]}
      theme={theme}
      onNewWorkspace={() => setWorkspace((value) => value + 1)}
      onToggleTheme={() => setTheme((current) => current === 'light' ? 'dark' : 'light')}
    >
      <SourceConfiguration key={workspace} view={view} onViewChange={setView} />
    </AppLayout>
  )
}
