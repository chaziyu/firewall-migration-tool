import { useCallback, useEffect, useState } from 'react'
import { clearWorkspace, workspaceExpired } from './storage/workspaceStore'
import { ErrorBanner } from './components/common/ErrorBanner'
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
  const [resetting, setResetting] = useState(false)
  const [workspaceError, setWorkspaceError] = useState<string | null>(null)
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    try { return localStorage.getItem('fwmigrate-theme') === 'dark' ? 'dark' : 'light' }
    catch { return 'light' }
  })

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try { localStorage.setItem('fwmigrate-theme', theme) } catch { /* Theme remains active for this page. */ }
  }, [theme])

  const newWorkspace = useCallback(async () => {
    if (resetting) return
    setResetting(true)
    setWorkspaceError(null)
    try {
      await clearWorkspace()
      setWorkspace((value) => value + 1)
      setView('report')
    } catch (cause) {
      setWorkspaceError(`Could not clear browser workspace: ${String(cause)}`)
    } finally { setResetting(false) }
  }, [resetting])

  useEffect(() => {
    const timer = window.setInterval(() => { if (workspaceExpired()) void newWorkspace() }, 60_000)
    return () => window.clearInterval(timer)
  }, [newWorkspace])

  return (
    <AppLayout
      view={view}
      onViewChange={setView}
      page={pages[view]}
      theme={theme}
      onNewWorkspace={() => void newWorkspace()}
      onToggleTheme={() => setTheme((current) => current === 'light' ? 'dark' : 'light')}
    >
      {workspaceError && <ErrorBanner message={workspaceError} />}
      {!resetting && <SourceConfiguration key={workspace} view={view} onViewChange={setView} />}
    </AppLayout>
  )
}
