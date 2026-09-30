import type { SourceVendor, SourceVendorOption } from './types'

export function VendorSelect({ value, onChange, vendors }: {
  value: SourceVendor
  onChange: (vendor: SourceVendor) => void
  vendors: SourceVendorOption[]
}) {
  return (
    <label className="field">
      <span>Source vendor</span>
      <span className="vendor-select-wrap"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" aria-hidden="true"><path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6Z" /><path d="m8.5 12 2.5 2.5 4.5-5" /></svg><select className="vendor-select" value={value} onChange={(event) => onChange(event.target.value)} disabled={!vendors.length}>
        {vendors.map((vendor) => <option key={vendor.vendor_id} value={vendor.vendor_id}>{vendor.display_name}</option>)}
      </select></span>
    </label>
  )
}
