import { useEffect, useState } from 'react'
import type { LifecycleCardData } from '../source/types'
import { fetchLifecycleStatus } from '../source/sourceApi'

function fallbackSubtitle(card: LifecycleCardData): string {
  const prefix = card.vendor === 'palo_alto'
    ? 'PAN-OS branch support & patch status'
    : 'Model & FortiOS branch support status'
  return `${prefix} · Source: ${card.source_label || 'Offline snapshot'}`
}

export function LifecycleCard({
  lifecycle,
  onLifecycleResolved,
}: {
  lifecycle: LifecycleCardData
  onLifecycleResolved?: (card: LifecycleCardData) => void
}) {
  const [resolved, setResolved] = useState<{
    forLifecycle: LifecycleCardData
    card: LifecycleCardData
  } | null>(null)

  const card = resolved?.forLifecycle === lifecycle ? resolved.card : lifecycle

  useEffect(() => {
    if (!lifecycle.needs_live_refresh || !lifecycle.refresh_params) return

    const controller = new AbortController()
    let active = true

    fetchLifecycleStatus(lifecycle.refresh_params, controller.signal)
      .then((fresh) => {
        if (!active) return
        setResolved({ forLifecycle: lifecycle, card: fresh })
        onLifecycleResolved?.(fresh)
      })
      .catch((error: unknown) => {
        if (!active || controller.signal.aborted) return
        if (error instanceof DOMException && error.name === 'AbortError') return
        const fallback = {
          ...lifecycle,
          needs_live_refresh: false,
          subtitle: fallbackSubtitle(lifecycle),
        }
        setResolved({
          forLifecycle: lifecycle,
          card: fallback,
        })
        onLifecycleResolved?.(fallback)
      })

    return () => {
      active = false
      controller.abort()
    }
  }, [lifecycle, onLifecycleResolved])

  return (
    <section className="lifecycle-section" aria-labelledby={`${card.id}-title`}>
      <div id={card.id} className="lifecycle-card">
        <div className="lifecycle-card-header">
          <div className="lifecycle-card-heading">
            <h3 id={`${card.id}-title`} className="report-overview-heading fw-section-header">
              <span className="dot" aria-hidden="true" />
              {card.title}
            </h3>
            <p className="lifecycle-subtitle">{card.subtitle}</p>
          </div>
          <span id={card.badge.id} className={`fw-badge fw-badge-${card.badge.variant}`}>
            {card.badge.text}
          </span>
        </div>
        <dl className="lifecycle-rows">
          {card.rows.map((row) => (
            <div key={row.label} className="lifecycle-row">
              <dt>{row.label}</dt>
              <dd>{row.value}</dd>
            </div>
          ))}
        </dl>
      </div>
    </section>
  )
}
