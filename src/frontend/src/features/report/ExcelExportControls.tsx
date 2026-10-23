import { useId } from 'react'
import { Button } from '../../components/common/Button'

export function ExcelExportControls({ vendor, profile, onProfileChange, exporting, onExport, onCancel }: {
  vendor: string
  profile: 'fast' | 'full'
  onProfileChange: (value: 'fast' | 'full') => void
  exporting: boolean
  onExport: () => void
  onCancel?: () => void
}) {
  const descriptionId = useId()
  const evidence = vendor === 'palo_alto'
    ? 'FAST omits PAN-OS Source Inventory, Extraction Coverage, and PAN-OS Source Appendix, and skips empty sheets.'
    : vendor === 'fortigate' ? 'FAST omits FortiGate Source Inventory and Extraction Coverage. FULL expands commands into inventory detail rows.'
      : vendor === 'cisco_asa' || vendor === 'juniper_srx' ? 'FAST omits Source Inventory and Extraction Coverage.'
        : vendor === 'cisco_ftd' || vendor === 'checkpoint' ? 'FAST and FULL retain source evidence worksheets.'
          : 'Evidence coverage depends on the source vendor. Check Export Limitations in the workbook summary.'
  return <div className="excel-export-controls">
    <div className="excel-actions">
      <label className="excel-profile-control">Excel profile<select aria-label="Excel export profile" aria-describedby={descriptionId} value={profile} disabled={exporting} onChange={(event) => onProfileChange(event.target.value as 'fast' | 'full')}><option value="fast">FAST</option><option value="full">FULL</option></select></label>
      <Button type="button" className="excel-export-button" disabled={exporting} aria-busy={exporting} onClick={onExport}>{exporting ? 'Preparing workbook…' : 'Export Excel'}</Button>
      {exporting && onCancel && <Button type="button" className="secondary-button" onClick={onCancel}>Cancel export</Button>}
    </div>
    <details className="excel-profile-help"><summary>About Excel profiles</summary><p id={descriptionId} className="excel-profile-description">{evidence} FULL retains all available report sheets; it does not imply complete extraction.</p></details>
  </div>
}
