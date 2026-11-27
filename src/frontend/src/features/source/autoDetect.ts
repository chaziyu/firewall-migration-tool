export type DetectedUploadKind = 'fortigate' | 'palo_alto' | 'tsf' | 'unknown'

export function detectUploadKind(filename: string): DetectedUploadKind {
  const lower = filename.trim().toLowerCase()
  if (lower.endsWith('.xml')) return 'palo_alto'
  if (lower.endsWith('.conf') || lower.endsWith('.cfg') || lower.endsWith('.txt')) return 'fortigate'
  if (lower.endsWith('.zip')) return 'tsf'
  return 'unknown'
}
