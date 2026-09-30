import type { SourcePreviewData, SourceVendor } from './types'
import { asRecord, reportCounts } from '../report/reportPresentation'

export function SourceOverview({ vendor, vendorName, file, preview }: { vendor: SourceVendor; vendorName: string; file: File | null; preview: SourcePreviewData }) {
  const { policies, objects, errors, warnings } = reportCounts(preview)
  const collection = asRecord(preview.collection)
  return (
    <div className="source-overview">
      <div className="source-file-summary"><span><strong>{file?.name ?? String(preview.acquisition ?? 'Collection source')}</strong><small>{file ? `${(file.size / 1024 / 1024).toFixed(1)} MB` : vendorName || vendor}</small><span className="preview-status">Parsed · {errors} errors · {warnings} warnings{collection.status ? ` · Collection ${collection.status}` : ''}</span></span></div>
      <h3>Configuration overview</h3>
      <div className="source-overview-stats"><div><strong>{policies ?? 'Unknown'}</strong><span>Configured policies</span></div><div><strong>{objects ?? 'Unknown'}</strong><span>Configured address/service objects</span></div><div><strong>{errors}</strong><span>Errors</span></div><div><strong>{warnings}</strong><span>Warnings</span></div></div>
    </div>
  )
}
