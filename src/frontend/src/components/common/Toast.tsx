import { useEffect } from 'react'
import styles from './Toast.module.css'

export function Toast({
  message,
  onDismiss,
  durationMs = 5000,
  tone = 'success',
}: {
  message: string
  onDismiss?: () => void
  durationMs?: number
  tone?: 'success' | 'info' | 'danger'
}) {
  useEffect(() => {
    if (!message || !onDismiss || durationMs <= 0) return
    const timer = window.setTimeout(() => {
      onDismiss()
    }, durationMs)
    return () => window.clearTimeout(timer)
  }, [message, onDismiss, durationMs])

  if (!message) return null

  return (
    <div
      className={`${styles.toast} ${styles[tone]}`}
      role="status"
      aria-live="polite"
    >
      <span className={styles.dot} aria-hidden="true" />
      <span className={styles.message}>{message}</span>
      {onDismiss && (
        <button
          type="button"
          className={styles.close}
          onClick={onDismiss}
          aria-label="Dismiss notification"
        >
          ×
        </button>
      )}
    </div>
  )
}
