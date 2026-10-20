import type { DestinationEvidence } from '../components/DestinationSnapshot'
import { postBlob, postJson } from '../../../api/client'
import type { SourceEvidence } from '../../../storage/workspaceTypes'
import type { CheckPointArtifact, CheckPointOptions, CheckPointReview } from './types'

const destinationPayload = (destination?: DestinationEvidence | null) => destination ? { target_source: destination.source, target_metadata: destination.metadata } : {}

const prefix = '/api/migration/fortigate_to_checkpoint'

export const requirements = (source: SourceEvidence, options: CheckPointOptions, destination?: DestinationEvidence | null) =>
  postJson<{ options?: CheckPointOptions; source_vdoms?: string[]; requirements: CheckPointReview['requirements']; report: CheckPointReview['report'] }>(`${prefix}/requirements`, { source, options, ...destinationPayload(destination) })

export const prepare = (source: SourceEvidence, options: CheckPointOptions, destination?: DestinationEvidence | null) =>
  postJson<CheckPointReview>(`${prefix}/design/prepare`, { source, options, ...destinationPayload(destination) })

export const approve = (source: SourceEvidence, options: CheckPointOptions, draft: Record<string, unknown>, selected: string[], destination?: DestinationEvidence | null) =>
  postJson<{ approval: Record<string, unknown> }>(`${prefix}/design/approve`, { source, options, draft, selected_items: selected, ...destinationPayload(destination) })

export const build = (source: SourceEvidence, options: CheckPointOptions, approval: Record<string, unknown>, destination?: DestinationEvidence | null) =>
  postJson<{ artifact: CheckPointArtifact }>(`${prefix}/build`, { source, options, approval, ...destinationPayload(destination) })

export const preview = (source: SourceEvidence, artifact: CheckPointArtifact) =>
  postJson<{ files: Record<string, { text: string; sha256: string; byte_count: number }>; report: CheckPointReview['report'] }>(`${prefix}/artifact-preview`, { source, artifact })

export const download = (source: SourceEvidence, artifact: CheckPointArtifact,
                        kind: 'management-operations' | 'management-commands' | 'gaia-config' | 'bindings' | 'bundle') =>
  postBlob(`${prefix}/${kind}`, { source, artifact })

export const exportDecisions = (source: SourceEvidence, options: CheckPointOptions) =>
  postJson<{ document: Record<string, unknown> }>(`${prefix}/decisions/export`, { source, options })

export const importDecisions = (source: SourceEvidence, document: unknown) =>
  postJson<{ options: CheckPointOptions }>(`${prefix}/decisions/import`, { source, document })
