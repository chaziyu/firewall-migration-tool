import type { ReactNode } from 'react'

export type KeyValueItem = {
  label: string
  value: ReactNode
  mono?: boolean
}

export function KeyValueGrid({
  items,
  className = '',
}: {
  items: KeyValueItem[]
  className?: string
}) {
  return (
    <dl className={['ui-kv-grid', className].filter(Boolean).join(' ')}>
      {items.map((item) => (
        <div key={item.label} className="ui-kv-item">
          <dt>{item.label}</dt>
          <dd className={item.mono ? 'ui-kv-mono' : undefined}>{item.value}</dd>
        </div>
      ))}
    </dl>
  )
}
