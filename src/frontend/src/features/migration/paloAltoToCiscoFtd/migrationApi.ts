import { postBlob, postJson } from '../../../api/client'
import type { SourceEvidence } from '../../../storage/workspaceTypes'
import type { DestinationEvidence } from '../components/DestinationSnapshot'
import type { FTDOptions, FTDReview, FTDArtifact } from './types'

const prefix = '/api/migration/palo_alto_to_cisco_ftd'
const targetPayload = (target?: DestinationEvidence | null) =>
  target ? { target_source: target.source, target_metadata: target.metadata } : {}

export const prepare = (source: SourceEvidence, options: FTDOptions, target?: DestinationEvidence | null) =>
  postJson<FTDReview>(`${prefix}/design/prepare`, { source, options, ...targetPayload(target) })

export const approve = (
  source: SourceEvidence,
  options: FTDOptions,
  draft: FTDReview['draft'],
  selected: string[],
  target?: DestinationEvidence | null,
) =>
  postJson<{ approval: Record<string, unknown> }>(`${prefix}/design/approve`, {
    source,
    options,
    draft,
    selected_items: selected,
    ...targetPayload(target),
  })

export const build = (
  source: SourceEvidence,
  options: FTDOptions,
  approval: Record<string, unknown>,
  target?: DestinationEvidence | null,
) =>
  postJson<{ artifact: FTDArtifact }>(`${prefix}/build`, {
    source,
    options,
    approval,
    ...targetPayload(target),
  })

export const download = (source: SourceEvidence, artifact: FTDArtifact, kind: string) =>
  postBlob(`${prefix}/${kind}`, { source, artifact })
