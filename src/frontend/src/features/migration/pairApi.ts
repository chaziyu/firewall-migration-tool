import { apiFetch } from '../../api/client'
import type { MigrationPairOption } from '../source/types'

export async function loadMigrationPairs(): Promise<MigrationPairOption[]> {
  const response = await apiFetch('/api/migration/pairs')
  const data: unknown = await response.json()
  if (!response.ok || typeof data !== 'object' || data === null || !('pairs' in data) || !Array.isArray(data.pairs)) {
    throw new Error('Could not load migration targets')
  }
  return data.pairs as MigrationPairOption[]
}
