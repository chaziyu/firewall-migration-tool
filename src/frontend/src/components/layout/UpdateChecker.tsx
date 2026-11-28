import { useCallback, useEffect, useRef, useState } from 'react'

export interface UpdateCheckResponse {
  mode: 'cloud' | 'desktop' | 'source'
  checked: boolean
  current_version: string
  latest_version?: string
  update_available: boolean
  release_url?: string
  release_notes?: string
  can_auto_install: boolean
  install_method?: 'installer' | 'portable_replace' | 'git_pull' | null
  error?: string
}

const SESSION_STATUS_KEY = 'fwmigrate_update_status'
const AUTO_INSTALL_GUARD_PREFIX = 'fwmigrate_auto_install_'

export function UpdateChecker({ collapsed = false }: { collapsed?: boolean }) {
  const [info, setInfo] = useState<UpdateCheckResponse | null>(() => {
    try {
      const raw = typeof sessionStorage !== 'undefined' ? sessionStorage.getItem(SESSION_STATUS_KEY) : null
      return raw ? (JSON.parse(raw) as UpdateCheckResponse) : null
    } catch {
      return null
    }
  })
  const [checking, setChecking] = useState(false)
  const [installing, setInstalling] = useState(false)
  const [statusLabel, setStatusLabel] = useState<string | null>(null)
  const [installMessage, setInstallMessage] = useState<string | null>(null)
  const [installError, setInstallError] = useState<string | null>(null)
  const mounted = useRef(true)

  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  const triggerInstall = useCallback(async (data: UpdateCheckResponse) => {
    if (!mounted.current) return
    const latest = data.latest_version || ''
    try {
      if (typeof sessionStorage !== 'undefined' && latest) {
        sessionStorage.setItem(`${AUTO_INSTALL_GUARD_PREFIX}${latest}`, '1')
      }
    } catch {
      // Ignore storage failures in restricted contexts.
    }
    setInstalling(true)
    setInstallError(null)
    const isGitPull = data.install_method === 'git_pull'
    setInstallMessage(isGitPull ? `Updating to v${latest} via git pull…` : `Auto-downloading & installing v${latest}…`)
    try {
      const res = await fetch('/api/update/install', { method: 'POST' })
      const payload = (await res.json()) as { ok?: boolean; message?: string; error?: string }
      if (!mounted.current) return
      if (!res.ok || payload.ok === false) {
        setInstallError(payload.error || `Update failed (${res.status})`)
        setInstallMessage(null)
      } else {
        setInstallMessage(payload.message || `Updated to v${latest}.`)
      }
    } catch (err) {
      if (!mounted.current) return
      setInstallError(err instanceof Error ? err.message : 'Network error during update')
      setInstallMessage(null)
    } finally {
      if (mounted.current) setInstalling(false)
    }
  }, [])

  const runCheck = useCallback(async (manual: boolean) => {
    if (!mounted.current) return
    if (manual) {
      setChecking(true)
      setStatusLabel('Checking...')
      setInstallError(null)
    }
    try {
      const res = await fetch('/api/update/check')
      if (!res.ok) {
        if (manual && mounted.current) setStatusLabel('Offline')
        return
      }
      const data = (await res.json()) as UpdateCheckResponse
      if (!mounted.current) return
      setInfo(data)
      try {
        if (typeof sessionStorage !== 'undefined') {
          sessionStorage.setItem(SESSION_STATUS_KEY, JSON.stringify(data))
        }
      } catch {
        // Ignore sessionStorage errors.
      }

      if (data.mode === 'cloud') return

      if (data.update_available) {
        const latest = data.latest_version || ''
        setStatusLabel(`v${latest} new!`)
        if (data.can_auto_install) {
          let alreadyAttempted = false
          try {
            alreadyAttempted = Boolean(
              typeof sessionStorage !== 'undefined' &&
              latest &&
              sessionStorage.getItem(`${AUTO_INSTALL_GUARD_PREFIX}${latest}`),
            )
          } catch {
            alreadyAttempted = false
          }
          if (manual || !alreadyAttempted) {
            void triggerInstall(data)
          }
        }
      } else if (manual) {
        setStatusLabel(data.checked ? 'Up to date ✓' : 'Offline')
        window.setTimeout(() => {
          if (mounted.current) setStatusLabel(null)
        }, 3000)
      }
    } catch {
      if (manual && mounted.current) {
        setStatusLabel('Offline')
        window.setTimeout(() => {
          if (mounted.current) setStatusLabel(null)
        }, 3000)
      }
    } finally {
      if (mounted.current) setChecking(false)
    }
  }, [triggerInstall])

  const didInit = useRef(false)

  useEffect(() => {
    if (didInit.current) return
    didInit.current = true
    if (info?.mode === 'cloud') return
    if (info?.update_available) {
      if (info.can_auto_install && info.latest_version) {
        let alreadyAttempted: boolean
        try {
          alreadyAttempted = Boolean(
            typeof sessionStorage !== 'undefined' &&
            sessionStorage.getItem(`${AUTO_INSTALL_GUARD_PREFIX}${info.latest_version}`),
          )
        } catch {
          alreadyAttempted = false
        }
        if (!alreadyAttempted) {
          const installTimer = window.setTimeout(() => {
            void triggerInstall(info)
          }, 0)
          return () => window.clearTimeout(installTimer)
        }
      }
      return
    }
    const timer = window.setTimeout(() => {
      void runCheck(false)
    }, 1200)
    return () => window.clearTimeout(timer)
  }, [info, runCheck, triggerInstall])

  if (collapsed || info?.mode === 'cloud') return null

  const versionText = `v${info?.current_version || '0.2.6'}`

  return (
    <div className="fw-sidebar-footer">
      <div className="fw-sidebar-version">
        <span>{versionText}</span>
        <button
          type="button"
          className="fw-update-check-link"
          disabled={checking || installing}
          title="Check GitHub Releases for a newer version"
          onClick={() => void runCheck(true)}
        >
          {statusLabel || 'Check update'}
        </button>
      </div>
      {info?.update_available && (
        <div className="fw-update-box" role="status">
          <div className="fw-update-title">
            ⬆ {installMessage || `Update v${info.latest_version} available`}
          </div>
          {installError && <div className="fw-update-error">{installError}</div>}
          <div className="fw-update-actions">
            {info.can_auto_install ? (
              installError && (
                <button
                  type="button"
                  className="fw-update-action-btn"
                  disabled={installing}
                  onClick={() => void triggerInstall(info)}
                >
                  Retry Update
                </button>
              )
            ) : info.release_url ? (
              <a
                href={info.release_url}
                target="_blank"
                rel="noopener noreferrer"
                className="fw-update-action-btn"
              >
                Download Release
              </a>
            ) : null}
          </div>
        </div>
      )}
    </div>
  )
}
