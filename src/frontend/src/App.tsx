import { useCallback, useEffect, useState } from 'react'
import { clearWorkspace, workspaceExpired } from './storage/workspaceStore'
import { ErrorBanner } from './components/common/ErrorBanner'
import { apiFetch } from './api/client'
import './App.css'
import { AppLayout } from './components/layout/AppLayout'
import type { SidebarWorkspaceMeta } from './components/layout/Sidebar'
import { SourceConfiguration, type WorkflowView } from './features/source/SourceConfiguration'

const pages: Record<WorkflowView, { title: string; description: string }> = {
  report: { title: 'Configuration Report', description: 'Review reported source state, validation findings, and inventory.' },
  collect: { title: 'Live Collection', description: 'Collect configuration directly from a supported device.' },
  migration: { title: 'Plan migration', description: 'Review the proposed conversion, resolve remaining choices, and generate supported target commands.' },
}

export default function App() {
  const [view, setView] = useState<WorkflowView>('report')
  const [workspace, setWorkspace] = useState(0)
  const [resetting, setResetting] = useState(false)
  const [workspaceError, setWorkspaceError] = useState<string | null>(null)
  const [liveDeviceAccess, setLiveDeviceAccess] = useState(false)
  const [workspaceMeta, setWorkspaceMeta] = useState<SidebarWorkspaceMeta | null>(null)
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    try { return localStorage.getItem('fwmigrate-theme') === 'dark' ? 'dark' : 'light' }
    catch { return 'light' }
  })

  useEffect(() => {
    const controller = new AbortController()
    apiFetch('/api/capabilities', { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error('Could not load server capabilities')
        const capabilities = await response.json()
        if (!controller.signal.aborted) setLiveDeviceAccess(capabilities.live_device_access === true)
      })
      .catch(() => { /* Live device access stays disabled if capabilities are unavailable. */ })
    return () => controller.abort()
  }, [])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try { localStorage.setItem('fwmigrate-theme', theme) } catch { /* Theme remains active for this page. */ }
  }, [theme])

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.addEventListener !== 'function') return
    const onMeta = (event: Event) => {
      const detail = (event as CustomEvent<SidebarWorkspaceMeta | null>).detail
      setWorkspaceMeta(detail ?? null)
    }
    window.addEventListener('fw-workspace-meta', onMeta)
    return () => window.removeEventListener('fw-workspace-meta', onMeta)
  }, [])

  const newWorkspace = useCallback(async () => {
    if (resetting) return
    setResetting(true)
    setWorkspaceError(null)
    setWorkspaceMeta(null)
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

  const handleSelectReportSection = useCallback((section: string) => {
    if (typeof window !== 'undefined' && typeof window.dispatchEvent === 'function') {
      window.dispatchEvent(new CustomEvent('fw-select-report-section', { detail: section }))
    }
  }, [])

  const handleSelectMigrationStage = useCallback((stage: string) => {
    if (typeof window !== 'undefined' && typeof window.dispatchEvent === 'function') {
      window.dispatchEvent(new CustomEvent('fw-select-migration-stage', { detail: stage }))
    }
  }, [])

  return (
    <AppLayout
      view={view}
      liveDeviceAccess={liveDeviceAccess}
      onViewChange={setView}
      page={pages[view]}
      theme={theme}
      defaultCollapsed={false}
      workspaceMeta={workspaceMeta}
      onSelectReportSection={handleSelectReportSection}
      onSelectMigrationStage={handleSelectMigrationStage}
      onNewWorkspace={() => void newWorkspace()}
      onToggleTheme={() => setTheme((current) => current === 'light' ? 'dark' : 'light')}
    >
      {workspaceError && <ErrorBanner message={workspaceError} />}
      {!resetting && <SourceConfiguration key={workspace} view={view} onViewChange={setView} liveDeviceAccess={liveDeviceAccess} />}
    </AppLayout>
  )
}

