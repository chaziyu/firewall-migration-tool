import type { ReactNode } from 'react'

export type AlertTone = 'info' | 'warn' | 'success' | 'danger'

export function AlertBox({
  children,
  tone = 'info',
  title,
  role,
  className = '',
}: {
  children: ReactNode
  tone?: AlertTone
  title?: string
  role?: 'status' | 'alert'
  className?: string
}) {
  return (
    <div
      className={['ui-alert', `ui-alert-${tone}`, className].filter(Boolean).join(' ')}
      role={role ?? (tone === 'danger' ? 'alert' : 'status')}
    >
      {title ? <strong className="ui-alert-title">{title}</strong> : null}
      {children}
    </div>
  )
}
