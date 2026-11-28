import type { ReactNode } from 'react'

export type BadgeVariant = 'allow' | 'warn' | 'deny' | 'info' | 'purple' | 'muted'

export function Badge({
  children,
  variant = 'muted',
  className = '',
  title,
}: {
  children: ReactNode
  variant?: BadgeVariant
  className?: string
  title?: string
}) {
  return (
    <span className={['fw-badge', `fw-badge-${variant}`, className].filter(Boolean).join(' ')} title={title}>
      {children}
    </span>
  )
}
