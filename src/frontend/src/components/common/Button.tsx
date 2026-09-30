import type { ButtonHTMLAttributes, ReactNode } from 'react'

type Props = ButtonHTMLAttributes<HTMLButtonElement> & { children: ReactNode }

export function Button({ children, ...props }: Props) {
  return <button className="primary-button" {...props}>{children}</button>
}
