import { useEffect, useState } from 'react'

const ZOOM_STORAGE_KEY = 'fwmigrate-zoom'
const MIN_ZOOM = 70
const MAX_ZOOM = 150
const ZOOM_STEP = 10

function clampZoom(value: number): number {
  return Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, Math.round(value / ZOOM_STEP) * ZOOM_STEP))
}

function readSavedZoom(): number {
  try {
    const raw = Number(localStorage.getItem(ZOOM_STORAGE_KEY))
    return Number.isFinite(raw) && raw >= MIN_ZOOM && raw <= MAX_ZOOM ? clampZoom(raw) : 100
  } catch {
    return 100
  }
}

export function ZoomControl() {
  const [zoom, setZoom] = useState<number>(readSavedZoom)

  useEffect(() => {
    const root = document.documentElement
    if (zoom === 100) {
      root.style.removeProperty('zoom')
      root.style.removeProperty('--app-zoom')
    } else {
      root.style.zoom = `${zoom}%`
      root.style.setProperty('--app-zoom', String(zoom / 100))
    }
    try {
      if (zoom === 100) localStorage.removeItem(ZOOM_STORAGE_KEY)
      else localStorage.setItem(ZOOM_STORAGE_KEY, String(zoom))
    } catch { /* Zoom remains active for this session. */ }
  }, [zoom])

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (!(event.ctrlKey || event.metaKey) || event.altKey) return
      if (event.key === '=' || event.key === '+') {
        event.preventDefault()
        setZoom((current) => clampZoom(current + ZOOM_STEP))
      } else if (event.key === '-' || event.key === '_') {
        event.preventDefault()
        setZoom((current) => clampZoom(current - ZOOM_STEP))
      } else if (event.key === '0') {
        event.preventDefault()
        setZoom(100)
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  return (
    <div className="zoom-control" role="group" aria-label="Page zoom">
      <button
        type="button"
        className="secondary-button zoom-step"
        onClick={() => setZoom((current) => clampZoom(current - ZOOM_STEP))}
        disabled={zoom <= MIN_ZOOM}
        aria-label="Zoom out"
        title="Zoom out (Ctrl+-)"
      >
        −
      </button>
      <button
        type="button"
        className="secondary-button zoom-reset"
        onClick={() => setZoom(100)}
        disabled={zoom === 100}
        aria-label={`Page zoom ${zoom}%, click to reset to 100%`}
        title="Reset zoom to 100% (Ctrl+0)"
      >
        {zoom}%
      </button>
      <button
        type="button"
        className="secondary-button zoom-step"
        onClick={() => setZoom((current) => clampZoom(current + ZOOM_STEP))}
        disabled={zoom >= MAX_ZOOM}
        aria-label="Zoom in"
        title="Zoom in (Ctrl+=)"
      >
        +
      </button>
    </div>
  )
}
