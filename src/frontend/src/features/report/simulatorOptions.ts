import { asRows, type ReportRow } from './reportPresentation'

export type SimulatorSelectOptions = {
  interfaces: string[]
  zones: string[]
  vdoms: string[]
  scopes: string[]
  virtualRouters: string[]
}

function sortedUnique(values: Iterable<string>): string[] {
  return [...new Set([...values].map((v) => v.trim()).filter(Boolean))].sort((a, b) => a.localeCompare(b))
}

export function extractSimulatorOptions(sections: ReportRow): SimulatorSelectOptions {
  const ifaceRows = asRows(sections.interfaces)
  const zoneRows = asRows(sections.zones)
  const vrRows = [...asRows(sections.virtual_routers), ...asRows(sections.logical_routers)]
  const policyRows = [...asRows(sections.policies), ...asRows(sections.security_rules)]

  const interfaces = sortedUnique(
    ifaceRows
      .filter((r) => String(r.type ?? '').toLowerCase() !== 'zone')
      .map((r) => String(r.name ?? r.interface ?? '')),
  )

  const zones = sortedUnique([
    ...zoneRows.map((r) => String(r.name ?? r.zone ?? '')),
    ...ifaceRows.filter((r) => String(r.type ?? '').toLowerCase() === 'zone').map((r) => String(r.name ?? r.zone ?? '')),
  ])

  const vdoms = sortedUnique([
    ...ifaceRows.map((r) => String(r.vdom ?? '')),
    ...policyRows.map((r) => String(r.vdom ?? '')),
  ])

  const scopes = sortedUnique(
    policyRows
      .map((r) => String(r.vsys ?? r.device_group ?? r.scope_name ?? ''))
      .filter((v) => v && v !== '<unscoped>'),
  )

  const virtualRouters = sortedUnique(
    vrRows.map((r) => String(r.name ?? '')),
  )

  return { interfaces, zones, vdoms, scopes, virtualRouters }
}
