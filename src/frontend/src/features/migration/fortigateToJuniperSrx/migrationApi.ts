import type { DestinationEvidence } from '../components/DestinationSnapshot'
import { postBlob, postJson } from '../../../api/client'
import type { SourceEvidence } from '../../../storage/workspaceTypes'
import type { SrxArtifact, SrxOptions, SrxReview } from './types'

const destinationPayload = (destination?: DestinationEvidence | null) => destination ? { target_source: destination.source, target_metadata: destination.metadata } : {}

const prefix = '/api/migration/fortigate_to_juniper_srx'

export const requirements = (source: SourceEvidence, options: SrxOptions, destination?: DestinationEvidence | null) =>
  postJson<{ requirements: SrxReview['requirements']; report: SrxReview['report'] }>(`${prefix}/requirements`, { source, options, ...destinationPayload(destination) })

export const prepare = (source: SourceEvidence, options: SrxOptions, destination?: DestinationEvidence | null) =>
  postJson<SrxReview>(`${prefix}/design/prepare`, { source, options, ...destinationPayload(destination) })

export const approve = (source: SourceEvidence, options: SrxOptions, draft: Record<string, unknown>, selectedItems: string[], destination?: DestinationEvidence | null) =>
  postJson<{ approval: Record<string, unknown> }>(`${prefix}/design/approve`, { source, options, draft, selected_items: selectedItems, ...destinationPayload(destination) })

export const build = (source: SourceEvidence, options: SrxOptions, approval: Record<string, unknown>, destination?: DestinationEvidence | null) =>
  postJson<{ artifact: SrxArtifact }>(`${prefix}/build`, { source, options, approval, ...destinationPayload(destination) })

export const commandPreview = (artifact: SrxArtifact) =>
  postJson<{ text: string; command_sha256: string }>(`${prefix}/command-preview`, { artifact })

export const download = (source: SourceEvidence, artifact: SrxArtifact, kind: 'commands' | 'bundle') =>
  postBlob(`${prefix}/${kind}`, kind === 'bundle' ? { source, artifact } : { artifact })

export const exportDecisions = (source: SourceEvidence, options: SrxOptions) =>
  postJson<{ document: Record<string, unknown> }>(`${prefix}/decisions/export`, { source, options })

export const importDecisions = (source: SourceEvidence, document: unknown) =>
  postJson<{ options: SrxOptions }>(`${prefix}/decisions/import`, { source, document })
