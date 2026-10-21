import { postBlob, postJson } from '../../../api/client'
import type { SourceEvidence } from '../../../storage/workspaceTypes'
import type { SRXArtifact, SRXOptions, SRXReview } from './types'
import type { DestinationEvidence } from '../components/DestinationSnapshot'

const prefix = '/api/migration/palo_alto_to_juniper_srx'
const targetPayload = (target?: DestinationEvidence | null) => target ? { target_source: target.source, target_metadata: target.metadata } : {}
export const prepare = (source: SourceEvidence, options: SRXOptions, target?: DestinationEvidence | null) =>
  postJson<SRXReview>(`${prefix}/design/prepare`, { source, options, ...targetPayload(target) })
export const approve = (source: SourceEvidence, options: SRXOptions, draft: SRXReview['draft'], selected: string[], target?: DestinationEvidence | null) =>
  postJson<{ approval: Record<string, unknown> }>(`${prefix}/design/approve`, { source, options, draft, selected_items: selected, ...targetPayload(target) })
export const build = (source: SourceEvidence, options: SRXOptions, approval: Record<string, unknown>, target?: DestinationEvidence | null) =>
  postJson<{ artifact: SRXArtifact }>(`${prefix}/build`, { source, options, approval, ...targetPayload(target) })
export const download = (source: SourceEvidence, artifact: SRXArtifact, kind: 'commands' | 'bundle') =>
  postBlob(`${prefix}/${kind}`, { source, artifact })
