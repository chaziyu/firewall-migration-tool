import type { ButtonHTMLAttributes, ReactNode } from 'react'

type Props = ButtonHTMLAttributes<HTMLButtonElement> & { children: ReactNode }

export function Button({ children, className, ...props }: Props) {
  return <button className={['primary-button', className].filter(Boolean).join(' ')} {...props}>{children}</button>
}
