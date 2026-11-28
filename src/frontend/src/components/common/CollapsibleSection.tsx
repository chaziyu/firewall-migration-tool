import type { ReactNode } from 'react'

export function CollapsibleSection({
  title,
  meta,
  defaultOpen = false,
  children,
  className = '',
}: {
  title: ReactNode
  meta?: ReactNode
  defaultOpen?: boolean
  children: ReactNode
  className?: string
}) {
  return (
    <details className={['ui-collapsible', className].filter(Boolean).join(' ')} open={defaultOpen}>
      <summary className="ui-collapsible-summary">
        <span>{title}</span>
        {meta != null ? <span className="ui-collapsible-meta">{meta}</span> : null}
      </summary>
      <div className="ui-collapsible-body">{children}</div>
    </details>
  )
}
