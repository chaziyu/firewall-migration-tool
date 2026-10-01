import type { Decision } from './reviewTypes'

export function reconcileReviewDrafts(current: Record<string, string>, previous: Decision[], next: Decision[], contextChanged: boolean) {
  const previousByKey = new Map(previous.map((item) => [item.key, item]))
  return Object.fromEntries(next.map((item) => {
    const unchanged = JSON.stringify(previousByKey.get(item.key)) === JSON.stringify(item)
    return [item.key, !contextChanged && unchanged && current[item.key] !== undefined ? current[item.key] : item.value ?? item.suggested_value ?? '']
  }))
}
