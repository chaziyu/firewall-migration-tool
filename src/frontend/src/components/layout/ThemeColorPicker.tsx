import { useEffect, useRef, useState, type PointerEvent } from 'react'
import { buildColorTheme, COLOR_STORAGE_KEY, CUSTOM_COLOR_PROPERTIES, DEFAULT_COLOR, hexToHsv, hsvToHex, normalizeHex, type HsvColor, type ThemeMode } from '../../styles/themeColor'

const presets = [
  { name: 'Sage', color: null },
  { name: 'Ocean', color: '#367fa0' },
  { name: 'Lavender', color: '#8871b5' },
  { name: 'Rose', color: '#b66b83' },
  { name: 'Amber', color: '#be9038' },
  { name: 'Slate', color: '#667585' },
]

export function ThemeColorPicker({ theme }: { theme: ThemeMode }) {
  const details = useRef<HTMLDetailsElement>(null)
  const [color, setColor] = useState<HsvColor | null>(() => {
    try {
      const saved = normalizeHex(localStorage.getItem(COLOR_STORAGE_KEY))
      return saved ? hexToHsv(saved) : null
    } catch { return null }
  })
  const [hexDraft, setHexDraft] = useState<string | null>(null)
  const selected = color ?? hexToHsv(DEFAULT_COLOR)
  const hex = hsvToHex(selected)
  const customHex = color === null ? null : hex
  const invalidHex = hexDraft !== null && normalizeHex(hexDraft) === null
  const angle = (selected.hue - 90) * Math.PI / 180

  useEffect(() => {
    const root = document.documentElement
    const properties = customHex ? buildColorTheme(customHex, theme) : null
    for (const property of CUSTOM_COLOR_PROPERTIES) {
      if (properties) root.style.setProperty(property, properties[property])
      else root.style.removeProperty(property)
    }
    try {
      if (customHex) localStorage.setItem(COLOR_STORAGE_KEY, customHex)
      else localStorage.removeItem(COLOR_STORAGE_KEY)
    } catch { /* The chosen color still works when storage is unavailable. */ }
  }, [customHex, theme])

  useEffect(() => {
    const closeOutside = (event: globalThis.PointerEvent) => {
      if (details.current?.open && event.target instanceof Node && !details.current.contains(event.target)) details.current.open = false
    }
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && details.current?.open) {
        event.preventDefault()
        details.current.open = false
        details.current.querySelector('summary')?.focus()
      }
    }
    document.addEventListener('pointerdown', closeOutside)
    document.addEventListener('keydown', closeOnEscape)
    return () => {
      document.removeEventListener('pointerdown', closeOutside)
      document.removeEventListener('keydown', closeOnEscape)
    }
  }, [])

  function choose(next: HsvColor | null) {
    setHexDraft(null)
    setColor(next)
  }

  function chooseFromWheel(event: PointerEvent<HTMLDivElement>) {
    const rect = event.currentTarget.getBoundingClientRect()
    const x = event.clientX - rect.left - rect.width / 2
    const y = event.clientY - rect.top - rect.height / 2
    choose({
      ...selected,
      hue: (Math.atan2(y, x) * 180 / Math.PI + 450) % 360,
      saturation: Math.min(1, Math.hypot(x, y) / (rect.width / 2)),
    })
  }

  return <details className="theme-picker" ref={details}>
    <summary className="secondary-button color-picker-toggle"><span className="color-picker-swatch" style={{ background: hex }} aria-hidden="true" />Colors</summary>
    <div className="color-picker-panel" role="group" aria-label="Workspace colors">
      <div className="color-picker-heading"><h2>Workspace color</h2><button type="button" className="text-button" onClick={() => { if (details.current) details.current.open = false; details.current?.querySelector('summary')?.focus() }} aria-label="Close color picker">×</button></div>
      <p className="color-picker-description">Pick a color to make the workspace yours. Your choice saves automatically.</p>
      <div className="color-wheel" role="slider" tabIndex={0} aria-label="Color wheel hue" aria-valuemin={0} aria-valuemax={359} aria-valuenow={Math.round(selected.hue) % 360} aria-valuetext={`${Math.round(selected.hue) % 360} degrees`} aria-describedby="color-wheel-help"
        onPointerDown={(event) => { event.currentTarget.focus(); event.currentTarget.setPointerCapture(event.pointerId); chooseFromWheel(event) }}
        onPointerMove={(event) => { if (event.currentTarget.hasPointerCapture(event.pointerId)) chooseFromWheel(event) }}
        onKeyDown={(event) => {
          const step = event.shiftKey ? 10 : 1
          const changes: Record<string, number> = { ArrowRight: step, ArrowUp: step, ArrowLeft: -step, ArrowDown: -step }
          if (event.key in changes || event.key === 'Home' || event.key === 'End') {
            event.preventDefault()
            choose({ ...selected, hue: event.key === 'Home' ? 0 : event.key === 'End' ? 359 : (selected.hue + changes[event.key] + 360) % 360 })
          }
        }}>
        <span className="color-wheel-shade" style={{ opacity: 1 - selected.value }} />
        <span className="color-wheel-thumb" style={{ left: `${50 + Math.cos(angle) * selected.saturation * 50}%`, top: `${50 + Math.sin(angle) * selected.saturation * 50}%`, background: hex }} />
      </div>
      <span id="color-wheel-help" className="visually-hidden">Drag to choose hue and saturation. Use arrow keys to change hue, or Shift and an arrow for larger steps. Adjust saturation and brightness below.</span>
      <label className="color-range-label"><span>Saturation <span className="color-range-value" aria-hidden="true">{Math.round(selected.saturation * 100)}%</span></span><input type="range" min="0" max="100" value={Math.round(selected.saturation * 100)} onChange={(event) => choose({ ...selected, saturation: Number(event.target.value) / 100 })} /></label>
      <label className="color-range-label"><span>Brightness <span className="color-range-value" aria-hidden="true">{Math.round(selected.value * 100)}%</span></span><input type="range" min="0" max="100" value={Math.round(selected.value * 100)} onChange={(event) => choose({ ...selected, value: Number(event.target.value) / 100 })} /></label>
      <label className="color-hex-label">Hex color<input type="text" value={hexDraft ?? hex.toUpperCase()} maxLength={7} spellCheck={false} autoComplete="off" aria-invalid={invalidHex} aria-describedby={invalidHex ? 'color-hex-error' : undefined} onChange={(event) => {
        const value = event.target.value
        setHexDraft(value)
        const valid = normalizeHex(value)
        if (valid) setColor(hexToHsv(valid))
      }} /></label>
      {invalidHex && <p className="color-hex-error" id="color-hex-error">Enter six hex digits, for example #798777.</p>}
      <div className="color-presets" role="group" aria-label="Color presets">{presets.map((preset) => <button key={preset.name} type="button" className="color-preset" aria-label={`${preset.name} color`} aria-pressed={customHex === preset.color} title={preset.name} onClick={() => choose(preset.color ? hexToHsv(preset.color) : null)}><span style={{ background: preset.color ?? DEFAULT_COLOR }} aria-hidden="true" /></button>)}</div>
      <button className="secondary-button color-reset" type="button" disabled={color === null && hexDraft === null} onClick={() => choose(null)}>Reset to original palette</button>
    </div>
  </details>
}
