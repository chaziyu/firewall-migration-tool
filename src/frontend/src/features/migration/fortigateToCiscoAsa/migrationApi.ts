import type { DestinationEvidence } from '../components/DestinationSnapshot'
import { postBlob, postJson } from '../../../api/client'
import type { SourceEvidence } from '../../../storage/workspaceTypes'
import type { AsaArtifact, AsaOptions, AsaReview } from './types'

const destinationPayload = (destination?: DestinationEvidence | null) => destination ? { target_source: destination.source, target_metadata: destination.metadata } : {}

const prefix = '/api/migration/fortigate_to_cisco_asa'
export const requirements = (source: SourceEvidence, options: Partial<AsaOptions>, destination?: DestinationEvidence | null) =>
  postJson<{ requirements: AsaReview['requirements']; report: AsaReview['report'] }>(`${prefix}/requirements`, { source, options, ...destinationPayload(destination) })
export const prepare = (source: SourceEvidence, options: AsaOptions, destination?: DestinationEvidence | null) =>
  postJson<AsaReview>(`${prefix}/design/prepare`, { source, options, ...destinationPayload(destination) })
export const approve = (source: SourceEvidence, options: AsaOptions, draft: Record<string, unknown>, selected: string[], destination?: DestinationEvidence | null) =>
  postJson<{ approval: Record<string, unknown> }>(`${prefix}/design/approve`, { source, options, draft, selected_items: selected, ...destinationPayload(destination) })
export const build = (source: SourceEvidence, options: AsaOptions, approval: Record<string, unknown>, destination?: DestinationEvidence | null) =>
  postJson<{ artifact: AsaArtifact }>(`${prefix}/build`, { source, options, approval, ...destinationPayload(destination) })
export const commandPreview = (artifact: AsaArtifact) =>
  postJson<{ text: string; command_sha256: string }>(`${prefix}/command-preview`, { artifact })
export const download = (source: SourceEvidence, artifact: AsaArtifact, kind: 'commands' | 'bundle') =>
  postBlob(`${prefix}/${kind}`, kind === 'commands' ? { artifact } : { source, artifact })
export const exportDecisions = (source: SourceEvidence, options: AsaOptions) =>
  postJson<{ document: Record<string, unknown> }>(`${prefix}/decisions/export`, { source, options })
export const importDecisions = (source: SourceEvidence, document: unknown) =>
  postJson<{ options: AsaOptions }>(`${prefix}/decisions/import`, { source, document })
