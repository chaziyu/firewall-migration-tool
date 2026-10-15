import { useEffect, useState } from 'react'
import type { ConversionSettings, MigrationDraft, VPNParameters } from '../types'
import { Button } from '../../../components/common/Button'

export function MigrationConversionSettings({ draft, busy, onApply, onDirtyChange }: {
  draft: MigrationDraft; busy: boolean; onApply: (settings: ConversionSettings) => void; onDirtyChange: (dirty: boolean) => void
}) {
  const initial = draft.context.conversion_settings ?? {}
  const [settings, setSettings] = useState<ConversionSettings>(initial)
  const dirty = JSON.stringify(settings) !== JSON.stringify(initial)
  useEffect(() => onDirtyChange(dirty), [dirty, onDirtyChange])
  const excluded = settings.excluded_interfaces ?? []
  const missing = new Set(draft.source_issues?.filter((row) => row.code === 'SOURCE_INTERFACE_MISSING').map((row) => `${row.source_vdom}/${row.source_name}`))
  const scopes = draft.decisions.filter((row) => row.source_kind === 'interface' && row.target_field === 'target_interface' && !missing.has(`${row.source_vdom}/${row.source_name}`))
  const suggestions = new Set(draft.findings.filter((row) => row.code === 'SCOPE_SUGGESTION').map((row) => row.identity))
  return <details className="migration-review-tools"><summary>Target version, hardware and conversion scope</summary>
    <p>Settings are proposals. Apply, review and approve them before export. XML lists configured interfaces; it does not establish physical port capacity.</p>
    {dirty && <p role="status">Conversion settings have unapplied edits. Apply them before editing mappings or approving configuration.</p>}
    <label className="field">PAN-OS command version<select aria-label="PAN-OS command version" value={settings.panos_version ?? ''} disabled={busy} onChange={(event) => setSettings({ ...settings, panos_version: event.target.value })}>
      <option value="">Version unverified</option><option value="11.1">PAN-OS 11.1</option>
    </select></label>
    <label className="field">Target hardware<select aria-label="Target hardware" value={settings.target_model ?? ''} disabled={busy} onChange={(event) => setSettings({ ...settings, target_model: event.target.value })}>
      <option value="">Hardware unverified</option><option value="PA-820">PA-820 · 12 data ports</option>
    </select></label>
    <details><summary>Interfaces included in conversion ({scopes.length - excluded.length} of {scopes.length})</summary>
      <p>Excluding a source interface retains it in the report. Its dependent configuration stays blocked. Suggestions use source references and settings; review cabling and management roles.</p>
      {scopes.map((row) => { const identity = `${row.source_vdom}/${row.source_name}`; return <label className="field" key={identity}>
        <span><input type="checkbox" checked={!excluded.includes(identity)} disabled={busy} onChange={(event) => setSettings({ ...settings, excluded_interfaces: event.target.checked ? excluded.filter((key) => key !== identity) : [...excluded, identity] })} /> {identity}{suggestions.has(identity) ? ' · no explicit addressing or consumers; review scope' : ''}</span>
      </label> })}
    </details>
    <details><summary>Existing target management profiles</summary>
      <p>Assign an existing target profile only after checking its protocols and permitted IPs. The converter does not create or enable administrative access. Final approval confirms these external prerequisites.</p>
      {draft.findings.filter((row) => row.code === 'MANAGEMENT_PROFILE_REQUIRED').map((row) => <label className="field" key={row.identity}>
        {row.identity} · {row.message}<input aria-label={`Management profile for ${row.identity}`} disabled={busy} value={settings.management_profiles?.[row.identity!] ?? ''} onChange={(event) => {
          const profiles = { ...settings.management_profiles }; if (event.target.value.trim()) profiles[row.identity!] = event.target.value; else delete profiles[row.identity!]; setSettings({ ...settings, management_profiles: profiles })
        }} />
      </label>)}
    </details>
    <details><summary>Existing target VPN prerequisites</summary>
      <p>Leave unchecked unless the gateway, credentials, crypto and selectors already exist and use the proposed tunnel identifier. Final approval records this engineer decision. The converter cannot recover source secrets.</p>
      {draft.findings.filter((row) => row.code === 'VPN_PREREQUISITE').map((row) => <label className="field" key={row.identity}><span>
        <input type="checkbox" disabled={busy} checked={settings.existing_vpns?.includes(row.identity!) ?? false} onChange={(event) => setSettings({ ...settings, existing_vpns: event.target.checked ? [...settings.existing_vpns ?? [], row.identity!] : settings.existing_vpns?.filter((key) => key !== row.identity) })} /> {row.identity}
      </span></label>)}
    </details>
    <details><summary>Missing VPN parameters · grouped decisions</summary>
      <p>These source values are absent. Enter reviewed target values for each group; leaving a field blank keeps the related configuration unresolved. Explicit source values are preserved.</p>
      {draft.findings.filter((row) => row.code === 'VPN_PARAMETERS_REQUIRED').map((group) => <fieldset key={group.member_keys?.join('|')}><legend>{group.source_vdom} · {group.source_kind} · {group.member_keys?.length} source objects</legend>
        {group.fields?.map((field) => {
          const values = group.member_keys?.map((key) => settings.vpn_parameters?.[key]?.[field]) ?? []
          const value = values.length && values.every((item) => item === values[0]) ? values[0] ?? '' : ''
          const change = (raw: string) => {
            const parameters = { ...settings.vpn_parameters }
            for (const key of group.member_keys ?? []) {
              const fields: VPNParameters = { ...parameters[key] }
              if (!raw) delete fields[field]
              else Object.assign(fields, { [field]: field === 'lifetime_seconds' ? Number(raw) : raw })
              if (Object.keys(fields).length) parameters[key] = fields; else delete parameters[key]
            }
            setSettings({ ...settings, vpn_parameters: parameters })
          }
          return <label className="field" key={field}>{field.replaceAll('_', ' ')}
            {field === 'lifetime_seconds' ? <input aria-label="lifetime seconds" type="number" min={180} step={1} disabled={busy} value={value} onChange={(event) => change(event.target.value)} />
              : <select aria-label={field.replaceAll('_', ' ')} disabled={busy} value={value} onChange={(event) => change(event.target.value)}><option value="">Unresolved / mixed</option>
                {(field === 'pfs' ? ['enable', 'disable'] : field === 'ike_version' ? ['1', '2'] : ['group14', 'group15', 'group16', 'group19', 'group20', 'group21']).map((option) => <option key={option} value={option}>{option}</option>)}
              </select>}
          </label>
        })}
      </fieldset>)}
    </details>
    <details><summary>Security profile groups · shared mappings</summary>
      <p>Assign an existing target profile group after reviewing its protection settings. One assignment applies to all policies with the same explicit source settings. SSL/SSH decryption and unsupported matching remain separate blockers.</p>
      {draft.findings.filter((row) => row.code === 'SECURITY_PROFILE_REQUIRED').map((group) => <label className="field" key={group.identity}>
        {group.member_keys?.length} policies · {group.message}
        <input aria-label={`Security profile group for ${group.identity}`} disabled={busy} value={settings.security_profiles?.[group.identity!] ?? ''} onChange={(event) => {
          const profiles = { ...settings.security_profiles }; if (event.target.value.trim()) profiles[group.identity!] = event.target.value; else delete profiles[group.identity!]; setSettings({ ...settings, security_profiles: profiles })
        }} />
      </label>)}
    </details>
    <Button disabled={busy || !dirty} onClick={() => onApply(settings)}>Apply conversion settings</Button>
  </details>
}
