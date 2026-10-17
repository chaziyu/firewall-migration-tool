import { postBlob, postJson } from '../../../api/client'
import type { SourceEvidence } from '../../../storage/workspaceTypes'
import type { SrxArtifact, SrxOptions, SrxReview } from './types'

const prefix = '/api/migration/fortigate_to_juniper_srx'

export const requirements = (source: SourceEvidence, options: SrxOptions) =>
  postJson<{ requirements: SrxReview['requirements']; report: SrxReview['report'] }>(`${prefix}/requirements`, { source, options })

export const prepare = (source: SourceEvidence, options: SrxOptions) =>
  postJson<SrxReview>(`${prefix}/design/prepare`, { source, options })

export const approve = (source: SourceEvidence, options: SrxOptions, draft: Record<string, unknown>, selectedItems: string[]) =>
  postJson<{ approval: Record<string, unknown> }>(`${prefix}/design/approve`, { source, options, draft, selected_items: selectedItems })

export const build = (source: SourceEvidence, options: SrxOptions, approval: Record<string, unknown>) =>
  postJson<{ artifact: SrxArtifact }>(`${prefix}/build`, { source, options, approval })

export const commandPreview = (artifact: SrxArtifact) =>
  postJson<{ text: string; command_sha256: string }>(`${prefix}/command-preview`, { artifact })

export const download = (source: SourceEvidence, artifact: SrxArtifact, kind: 'commands' | 'bundle') =>
  postBlob(`${prefix}/${kind}`, kind === 'bundle' ? { source, artifact } : { artifact })

export const exportDecisions = (source: SourceEvidence, options: SrxOptions) =>
  postJson<{ document: Record<string, unknown> }>(`${prefix}/decisions/export`, { source, options })

export const importDecisions = (source: SourceEvidence, document: unknown) =>
  postJson<{ options: SrxOptions }>(`${prefix}/decisions/import`, { source, document })
