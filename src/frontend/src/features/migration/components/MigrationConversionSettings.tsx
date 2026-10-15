import { useState } from 'react'
import type { ConversionSettings, MigrationDraft, VPNParameters } from '../types'
import { Button } from '../../../components/common/Button'

export function MigrationConversionSettings({ draft, busy, settings, onChange: setSettings, section }: {
  draft: MigrationDraft; busy: boolean; settings: ConversionSettings; onChange: (settings: ConversionSettings) => void
  section: 'hardware' | 'management' | 'vpn' | 'policy'
}) {
  const [managementNetworks, setManagementNetworks] = useState('')
  // Keep applied choices editable after the backend no longer reports them as missing.
  const findings = [...(draft.findings ?? [])]
  const previous = draft.context.conversion_settings ?? {}
  for (const values of [previous, settings]) {
    for (const identity of Object.keys(values.generated_management_profiles ?? {})) {
      if (!findings.some((row) => row.code === 'MANAGEMENT_PROFILE_GROUP' && row.identity === identity)) findings.push({ code: 'MANAGEMENT_PROFILE_GROUP', identity, source_vdom: identity.split('/')[0], message: identity, member_keys: [] })
    }
    for (const identity of Object.keys(values.management_profiles ?? {})) {
      if (!findings.some((row) => row.code === 'MANAGEMENT_PROFILE_GROUP' && row.member_keys?.includes(identity))) findings.push({ code: 'MANAGEMENT_PROFILE_GROUP', identity: `interface:${identity}`, source_vdom: identity.split('/')[0], message: identity, member_keys: [identity] })
    }
    for (const identity of values.existing_vpns ?? []) {
      if (!findings.some((row) => row.code === 'VPN_PREREQUISITE' && row.identity === identity)) findings.push({ code: 'VPN_PREREQUISITE', identity, message: identity })
    }
    for (const [identity, fields] of Object.entries(values.vpn_parameters ?? {})) {
      if (!findings.some((row) => row.code === 'VPN_PARAMETERS_REQUIRED' && row.member_keys?.includes(identity))) findings.push({ code: 'VPN_PARAMETERS_REQUIRED', message: identity, source_vdom: identity.split('/')[0], source_kind: identity.split('/')[1], fields: Object.keys(fields) as Array<keyof VPNParameters>, member_keys: [identity] })
    }
    for (const [vdom, identities] of Object.entries(values.identity_mappings ?? {})) {
      for (const identity of Object.keys(identities)) {
        if (!findings.some((row) => row.code === 'IDENTITY_MAPPING_REQUIRED' && row.source_vdom === vdom && row.identity === identity)) findings.push({ code: 'IDENTITY_MAPPING_REQUIRED', identity, source_vdom: vdom, message: identity, member_keys: [] })
      }
    }
    for (const identity of Object.keys(values.security_profiles ?? {})) {
      if (!findings.some((row) => row.code === 'SECURITY_PROFILE_REQUIRED' && row.identity === identity)) findings.push({ code: 'SECURITY_PROFILE_REQUIRED', identity, message: identity, member_keys: [] })
    }
  }
  const has = (...codes: string[]) => findings.some((row) => codes.includes(row.code))
  if (section === 'hardware') return <details className="migration-review-tools"><summary>Optional target hardware check</summary>
    <p>Limit physical-port proposals to a known model. Uploaded XML does not establish port capacity. Without a model, ports remain unverified.</p>
    <label className="field">Target hardware<select aria-label="Target hardware" value={settings.target_model ?? ''} disabled={busy} onChange={(event) => setSettings({ ...settings, target_model: event.target.value })}>
      <option value="">Hardware unverified</option><option value="PA-820">PA-820 · 12 data ports</option>
    </select></label>
  </details>
  return <>
    {section === 'management' && has('MANAGEMENT_PROFILE_GROUP') && <details className="migration-review-tools" id="settings-management"><summary>Interface management access</summary>
    <p>Use an existing profile or propose one with reviewed permitted networks. Existing per-interface assignments take precedence. Validate changes before approval.</p>
    {findings.some((row) => row.code === 'MANAGEMENT_PROFILE_GROUP' && !row.identity?.startsWith('interface:')) && <details><summary>Generate profiles</summary>
      <p>Proposals reuse explicit source protocols. Review permitted management networks for each group; generated profiles require final approval. Existing per-interface assignments take precedence.</p>
      <label className="field">Permitted networks for all proposed management profiles<input aria-label="Permitted networks for all proposed management profiles" disabled={busy || draft.destination_verified} value={managementNetworks} placeholder="Reviewed CIDRs, separated by commas" onChange={(event) => setManagementNetworks(event.target.value)} /></label>
      <Button disabled={busy || draft.destination_verified || !managementNetworks.trim()} onClick={() => {
        const profiles = { ...settings.generated_management_profiles }
        for (const group of findings.filter((row) => row.code === 'MANAGEMENT_PROFILE_GROUP' && !row.identity?.startsWith('interface:'))) profiles[group.identity!] = { permitted_ips: managementNetworks.split(',').map((value) => value.trim()) }
        setSettings({ ...settings, generated_management_profiles: profiles })
      }}>Propose profiles for all protocol groups</Button>
      {findings.filter((row) => row.code === 'MANAGEMENT_PROFILE_GROUP' && !row.identity?.startsWith('interface:')).map((group) => <label className="field" key={group.identity}>
        {group.source_vdom} · {group.message} · {group.member_keys?.length} interfaces
        <input aria-label={`Permitted management networks for ${group.identity}`} disabled={busy || draft.destination_verified} value={settings.generated_management_profiles?.[group.identity!]?.permitted_ips.join(', ') ?? ''} placeholder="Reviewed CIDRs, separated by commas" onChange={(event) => {
          const profiles = { ...settings.generated_management_profiles }
          const networks = event.target.value.split(',').map((value) => value.trim())
          if (event.target.value.trim()) profiles[group.identity!] = { permitted_ips: networks }; else delete profiles[group.identity!]
          setSettings({ ...settings, generated_management_profiles: profiles })
        }} />
      </label>)}
      {draft.destination_verified && <p>Use existing target profiles until destination profile inventory can be verified.</p>}
    </details>}
    {findings.some((row) => row.code === 'MANAGEMENT_PROFILE_GROUP' && !!row.member_keys?.length) && <details><summary>Existing target management profiles</summary>
      <p>Assign an existing target profile only after checking its protocols and permitted IPs. The converter does not create or enable administrative access. Final approval confirms these external prerequisites.</p>
      {findings.filter((row) => row.code === 'MANAGEMENT_PROFILE_GROUP' && !!row.member_keys?.length).map((group) => {
        const values = group.member_keys?.map((key) => settings.management_profiles?.[key] ?? '') ?? []
        const mixed = !values.every((value) => value === values[0])
        return <label className="field" key={group.identity}>
          {group.source_vdom} · {group.member_keys?.length} interfaces · {group.message}
          <input aria-label={`Management profile for ${group.identity}`} disabled={busy} value={mixed ? '' : values[0] ?? ''} placeholder={mixed ? 'Mixed assignments — enter a profile to apply to this group' : 'Existing target profile'} onChange={(event) => {
            const profiles = { ...settings.management_profiles }
            for (const key of group.member_keys ?? []) {
              if (event.target.value.trim()) profiles[key] = event.target.value; else delete profiles[key]
            }
            setSettings({ ...settings, management_profiles: profiles })
          }} />
          <small>Applies to: {group.member_keys?.join(', ')}. Different assignments are preserved until you edit this group.</small>
        </label>
      })}
    </details>}
    </details>}
    {section === 'vpn' && has('VPN_PREREQUISITE', 'VPN_PARAMETERS_REQUIRED') && <details className="migration-review-tools" id="settings-vpn"><summary>VPN decisions</summary>
    <p>These decisions do not generate a complete VPN. Gateway authentication and other unsupported settings require separate target configuration.</p>
    {has('VPN_PREREQUISITE') && <details><summary>Existing target VPN prerequisites</summary>
      <p>Leave unchecked unless the gateway, credentials, crypto and selectors already exist and use the proposed tunnel identifier. Final approval records this engineer decision. The converter cannot recover source secrets.</p>
      {findings.filter((row) => row.code === 'VPN_PREREQUISITE').map((row) => <label className="field" key={row.identity}><span>
        <input type="checkbox" disabled={busy} checked={settings.existing_vpns?.includes(row.identity!) ?? false} onChange={(event) => setSettings({ ...settings, existing_vpns: event.target.checked ? [...settings.existing_vpns ?? [], row.identity!] : settings.existing_vpns?.filter((key) => key !== row.identity) })} /> {row.identity}
      </span></label>)}
    </details>}
    {has('VPN_PARAMETERS_REQUIRED') && <details><summary>Missing VPN parameters · grouped decisions</summary>
      <p>These source values are absent. Enter reviewed target values for each group; leaving a field blank keeps the related configuration unresolved. Explicit source values are preserved.</p>
      {findings.filter((row) => row.code === 'VPN_PARAMETERS_REQUIRED').map((group) => <fieldset key={group.member_keys?.join('|')}><legend>{group.source_vdom} · {group.source_kind} · {group.member_keys?.length} source objects</legend>
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
    </details>}
    </details>}
    {section === 'policy' && (has('IDENTITY_MAPPING_REQUIRED', 'SECURITY_PROFILE_REQUIRED') || !!settings.identity_prerequisites?.length || !!previous.identity_prerequisites?.length) && <details className="migration-review-tools" id="settings-policy"><summary>Policy decisions</summary>
    {(has('IDENTITY_MAPPING_REQUIRED') || !!settings.identity_prerequisites?.length || !!previous.identity_prerequisites?.length) && <details><summary>Policy identities · shared mappings</summary>
      <p>Map each source user/group to its equivalent target identity once. Confirm that target User-ID and authentication preserve the source restrictions. NAT identity conditions remain separate.</p>
      <Button disabled={busy} onClick={() => {
        const mappings = Object.fromEntries(Object.entries(settings.identity_mappings ?? {}).map(([vdom, values]) => [vdom, { ...values }]))
        for (const group of findings.filter((row) => row.code === 'IDENTITY_MAPPING_REQUIRED' && row.proposed_value)) {
          mappings[group.source_vdom!] ??= {}
          mappings[group.source_vdom!][group.identity!] ??= group.proposed_value!
        }
        setSettings({ ...settings, identity_mappings: mappings })
      }}>Propose source identity names</Button>
      {[...new Set([...findings.filter((row) => row.code === 'IDENTITY_MAPPING_REQUIRED').map((row) => row.source_vdom!), ...settings.identity_prerequisites ?? [], ...previous.identity_prerequisites ?? []])].map((vdom) => <label className="field" key={vdom}><span>
        <input type="checkbox" disabled={busy} checked={settings.identity_prerequisites?.includes(vdom) ?? false} onChange={(event) => setSettings({ ...settings, identity_prerequisites: event.target.checked ? [...settings.identity_prerequisites ?? [], vdom] : settings.identity_prerequisites?.filter((value) => value !== vdom) })} /> {vdom}: target identity and authentication prerequisites are configured and reviewed
      </span></label>)}
      {findings.filter((row) => row.code === 'IDENTITY_MAPPING_REQUIRED').map((group) => <label className="field" key={`${group.source_vdom}/${group.identity}`}>
        {group.source_vdom} · {group.message} · {group.member_keys?.length} policies
        <input aria-label={`Target identity for ${group.source_vdom}/${group.identity}`} disabled={busy} value={settings.identity_mappings?.[group.source_vdom!]?.[group.identity!] ?? ''} onChange={(event) => {
          const mappings = { ...settings.identity_mappings, [group.source_vdom!]: { ...settings.identity_mappings?.[group.source_vdom!] } }
          if (event.target.value.trim()) mappings[group.source_vdom!][group.identity!] = event.target.value; else delete mappings[group.source_vdom!][group.identity!]
          setSettings({ ...settings, identity_mappings: mappings })
        }} />
      </label>)}
    </details>}
    {has('SECURITY_PROFILE_REQUIRED') && <details><summary>Security profile groups · shared mappings</summary>
      <p>Assign an existing target profile group after reviewing its protection settings. One assignment applies to all policies with the same explicit source settings. SSL/SSH decryption and unsupported matching remain separate blockers.</p>
      {findings.filter((row) => row.code === 'SECURITY_PROFILE_REQUIRED').map((group) => <label className="field" key={group.identity}>
        {group.member_keys?.length} policies · {group.message}
        <input aria-label={`Security profile group for ${group.identity}`} disabled={busy} value={settings.security_profiles?.[group.identity!] ?? ''} onChange={(event) => {
          const profiles = { ...settings.security_profiles }; if (event.target.value.trim()) profiles[group.identity!] = event.target.value; else delete profiles[group.identity!]; setSettings({ ...settings, security_profiles: profiles })
        }} />
      </label>)}
    </details>}
    </details>}
  </>
}
