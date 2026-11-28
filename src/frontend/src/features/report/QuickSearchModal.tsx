import { useEffect, useRef } from 'react'
import type { SourceEvidence } from '../../storage/workspaceTypes'
import { WhereUsedSearchContent } from './WhereUsedPanel'

export function QuickSearchModal({
  open,
  onClose,
  vendor,
  sourceEvidence,
}: {
  open: boolean
  onClose: () => void
  vendor: string
  sourceEvidence: SourceEvidence
}) {
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!open) return
    const timer = window.setTimeout(() => {
      inputRef.current?.focus()
    }, 0)
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        onClose()
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => {
      window.clearTimeout(timer)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [open, onClose])

  if (!open) return null

  return (
    <div
      className="fw-qs-backdrop"
      role="presentation"
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose()
      }}
    >
      <div
        className="fw-qs-dialog"
        role="dialog"
        aria-modal="true"
        aria-label="Global Quick Search"
      >
        <div className="fw-qs-header">
          <div className="fw-qs-title">
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <circle cx="11" cy="11" r="7" />
              <path d="m20 20-3.5-3.5" />
            </svg>
            <span>Global Quick Search</span>
            <span className="fw-qs-subtitle">IP, CIDR, or Object Name</span>
          </div>
          <button
            type="button"
            className="fw-qs-close-btn"
            onClick={onClose}
            aria-label="Close quick search"
            title="Close (Esc)"
          >
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M18 6 6 18M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="fw-qs-body">
          <WhereUsedSearchContent
            vendor={vendor}
            sourceEvidence={sourceEvidence}
            inputRef={inputRef}
            compact
          />
        </div>
      </div>
    </div>
  )
}
