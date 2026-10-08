import { useRef, useState } from 'react'
import { postJson as requestJson, RequestError } from '../../../api/client'
import type { SourceEvidence } from '../../../storage/workspaceTypes'

export function useMigrationReviewActivity({
  source,
  targetSource,
  targetDevice,
}: {
  source: SourceEvidence | undefined
  targetSource: SourceEvidence | null
  targetDevice: string
}) {
  const requestVersion = useRef(0)
  const actionVersion = useRef(0)
  const [actionBusy, setActionBusy] = useState(false)
  const [reviewLoading, setReviewLoading] = useState(false)
  const [error, setError] = useState('')
  const [status, setStatus] = useState('')

  async function postJson<T>(path: string, payload: Record<string, unknown>): Promise<T> {
    const version = requestVersion.current
    const result = await requestJson<T>(path, {
      source,
      target_source: targetSource,
      target_device: targetDevice,
      ...payload,
    }).catch((cause: unknown) => {
      if (version !== requestVersion.current) throw new DOMException('Review context changed', 'AbortError')
      throw cause
    })
    if (version !== requestVersion.current) throw new DOMException('Review context changed', 'AbortError')
    return result
  }

  async function run(action: () => Promise<void>, done?: string) {
    const version = ++actionVersion.current
    setActionBusy(true)
    setError('')
    setStatus('')
    try {
      await action()
      if (version === actionVersion.current && done) setStatus(done)
    } catch (cause) {
      if (version !== actionVersion.current) return
      if (cause instanceof DOMException && cause.name === 'AbortError') return
      const findings = cause instanceof RequestError && Array.isArray(cause.details.errors) ? cause.details.errors : []
      const details = findings
        .map((finding: unknown) => typeof finding === 'object' && finding !== null && 'message' in finding ? String(finding.message) : '')
        .filter(Boolean)
      setError([cause instanceof Error ? cause.message : 'Migration review failed', ...new Set(details)].join(' '))
    } finally {
      if (version === actionVersion.current) setActionBusy(false)
    }
  }

  return {
    requestVersion,
    actionVersion,
    postJson,
    run,
    busy: actionBusy || reviewLoading,
    setActionBusy,
    setReviewLoading,
    error,
    setError,
    status,
    setStatus,
  }
}
