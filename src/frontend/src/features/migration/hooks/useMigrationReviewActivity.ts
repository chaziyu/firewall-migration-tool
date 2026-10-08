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

  function beginReviewRequest() {
    const version = ++requestVersion.current
    setReviewLoading(true)
    setError('')
    return version
  }

  function finishReviewRequest(version: number) {
    if (version === requestVersion.current) setReviewLoading(false)
  }

  function invalidateReviewRequests() {
    requestVersion.current++
  }

  function reviewRequestIsCurrent(version: number) {
    return version === requestVersion.current
  }

  function currentReviewVersion() {
    return requestVersion.current
  }

  function beginStandaloneAction(statusText: string) {
    const version = ++actionVersion.current
    setActionBusy(true)
    setError('')
    setStatus(statusText)
    return version
  }

  function finishStandaloneAction(version: number) {
    if (version === actionVersion.current) setActionBusy(false)
  }

  function actionIsCurrent(version: number) {
    return version === actionVersion.current
  }

  function invalidateActions() {
    actionVersion.current++
  }

  return {
    postJson,
    run,
    busy: actionBusy || reviewLoading,
    setReviewLoading,
    error,
    setError,
    status,
    setStatus,
    beginReviewRequest,
    finishReviewRequest,
    invalidateReviewRequests,
    reviewRequestIsCurrent,
    currentReviewVersion,
    beginStandaloneAction,
    finishStandaloneAction,
    actionIsCurrent,
    invalidateActions,
  }
}
