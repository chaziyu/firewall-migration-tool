import { postBlob, postJson } from '../../../api/client'
import type { SourceEvidence } from '../../../storage/workspaceTypes'
import type { DestinationEvidence } from '../components/DestinationSnapshot'
import type { CPOptions, CPReview, CPArtifact } from './types'

const prefix = '/api/migration/palo_alto_to_checkpoint'
const targetPayload = (target?: DestinationEvidence | null) => target ? { target_source: target.source, target_metadata: target.metadata } : {}
export const prepare = (source: SourceEvidence, options: CPOptions, target?: DestinationEvidence | null) =>
  postJson<CPReview>(`${prefix}/design/prepare`, { source, options, ...targetPayload(target) })
export const approve = (source: SourceEvidence, options: CPOptions, draft: CPReview['draft'], selected: string[], target?: DestinationEvidence | null) =>
  postJson<{ approval: Record<string, unknown> }>(`${prefix}/design/approve`, { source, options, draft, selected_items: selected, ...targetPayload(target) })
export const build = (source: SourceEvidence, options: CPOptions, approval: Record<string, unknown>, target?: DestinationEvidence | null) =>
  postJson<{ artifact: CPArtifact }>(`${prefix}/build`, { source, options, approval, ...targetPayload(target) })
export const download = (source: SourceEvidence, artifact: CPArtifact, kind: string) => postBlob(`${prefix}/${kind}`, { source, artifact })
