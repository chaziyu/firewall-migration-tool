import type { ButtonHTMLAttributes, ReactNode } from 'react'

type Props = ButtonHTMLAttributes<HTMLButtonElement> & {
  children: ReactNode
  variant?: 'primary' | 'secondary' | 'outline' | 'text'
  size?: 'standard' | 'compact'
}

export function Button({ children, className = '', variant, size = 'standard', ...props }: Props) {
  const classes = className.split(/\s+/).filter(Boolean)
  const legacyVariant = classes.find((name) => /^(secondary|outline|text)-button$/.test(name))
  const style = variant ? `${variant}-button` : legacyVariant ?? 'primary-button'
  const extraClasses = classes.filter((name) => !/^(primary|secondary|outline|text)-button$/.test(name))
  return <button className={[style, size === 'compact' ? 'button-compact' : '', ...extraClasses].filter(Boolean).join(' ')} {...props}>{children}</button>
}
