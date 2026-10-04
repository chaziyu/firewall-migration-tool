export type Decision = {
  key: string
  source_vdom: string
  source_kind: string
  source_name: string
  target_field: string
  suggested_value: string | null
  value: string | null
  mode: string
  review_state: string
  reason: string
  evidence_source?: string | null
  evidence_type?: string | null
  evidence_value?: string | null
  target_object?: string | null
  [key: string]: unknown
}

export type DecisionDocument = { decisions?: Decision[]; [key: string]: unknown }

export type Candidate = {
  value: string
  class?: string
  target_scope?: string
  strong_evidence?: string[]
  supporting_evidence?: string[]
  available?: boolean
  contested?: boolean
  assigned_to?: Array<{ source_vdom: string; source_name: string }>
}


export type ReviewGroup = {
  queue: string
  source_vdom: string
  source_kind: string
  source_name: string
  decision_keys: string[]
  decisions: Decision[]
  candidates: Record<string, Candidate[]>
  source_evidence: Record<string, unknown>
  affected_count: number
  dependent_decision_count: number
  next_action?: string | null
  conflicts?: Array<{ decision_key: string; code: string; message: string }>
  actions?: Array<{ type: string; source_key: string; value: string; apply_to: string[] }>
}

export type RuleSuggestion = {
  rule_type: string
  source_vdom: string
  source_zone: string
  target_zone: string
  confirmed_count: number
  affected: string[]
  apply_to: string[]
}

export type ArchitectureQuestion = {
  type: string
  source_vdom: string
  source_name: string
  affected_count?: number
  decision_key?: string
  candidates?: string[]
  fields?: Decision[]
}

export type ReviewData = {
  decisions: { decisions: Decision[] }
  decision_document: DecisionDocument
  target_devices: string[]
  target_device: string | null
  decision_candidates: Record<string, Candidate[]>
  review_groups: ReviewGroup[]
  review_summary: Record<string, number>
  rule_suggestions: RuleSuggestion[]
  architecture_questions?: ArchitectureQuestion[]
  target_evidence: { device?: string; config_digest?: string } | null
  [key: string]: unknown
}
