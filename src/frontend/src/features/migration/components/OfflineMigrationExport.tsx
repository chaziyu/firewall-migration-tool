import { useState } from 'react'
import type { ReactNode } from 'react'
import { Button } from '../../../components/common/Button'
import { tabKeyboard } from '../../../components/common/tabKeyboard'

export type OfflineExportFile = { key: string; label: string; previewLabel: string; text: string; sha256: string; count: string; downloadLabel: string; downloadable: boolean }

export function OfflineMigrationExport({ artifactId, partial, noChanges, verification, files, busy, onDownload, onBundle, children }: {
  artifactId: string; partial: boolean; noChanges: boolean; verification: string; files: readonly OfflineExportFile[]
  busy: boolean; onDownload: (key: string) => void; onBundle: () => void; children?: ReactNode
}) {
  const [selectedFile, setSelectedFile] = useState('')
  const current = files.find((file) => file.key === selectedFile) ?? files[0]
  return <section aria-label="Approved offline export">
    <h3>{partial ? 'Partial export' : noChanges ? 'No changes needed' : 'Ready for export'}</h3>
    <p className="artifact-identity">Artifact: {artifactId}</p><p>{verification}</p>
    {partial && <p role="status">Blocked, unsupported and unapproved work is excluded. Review the report before applying this partial configuration.</p>}
    {children}
    {files.length > 1 && <div role="tablist" aria-label="Approved export files" className="migration-review-tabs" onKeyDown={tabKeyboard}>
      {files.map((file) => <button key={file.key} type="button" role="tab" id={`export-file-${file.key}`} aria-controls="export-file-preview" aria-selected={current?.key === file.key} tabIndex={current?.key === file.key ? 0 : -1} onClick={() => setSelectedFile(file.key)}>{file.label}</button>)}
    </div>}
    {current && <section id="export-file-preview" role={files.length > 1 ? 'tabpanel' : undefined} aria-labelledby={files.length > 1 ? `export-file-${current.key}` : undefined}>
      <p className="artifact-identity">{current.count} · SHA-256: {current.sha256}</p>
      <details><summary>{files.length > 1 ? `${current.label} preview` : 'Command preview'}</summary><label className="field">{current.label}<textarea aria-label={current.previewLabel} readOnly value={current.text} rows={12} wrap="off" /></label></details>
    </section>}
    <div className="action-row">
      {files.map((file) => <Button key={file.key} disabled={busy || !file.downloadable} onClick={() => onDownload(file.key)}>{file.downloadLabel}</Button>)}
      <Button disabled={busy} onClick={onBundle}>Download migration bundle</Button>
    </div>
  </section>
}
