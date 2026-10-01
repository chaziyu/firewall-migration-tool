import { useId, useRef, useState } from 'react'

export function FileUpload({ file, onChange, accept, title = 'Drop your configuration here', helpText, disabled = false }: {
  file: File | null
  onChange: (file: File | null) => void
  accept?: string
  title?: string
  helpText?: string
  disabled?: boolean
}) {
  const input = useRef<HTMLInputElement>(null)
  const inputId = useId()
  const [error, setError] = useState<string | null>(null)

  function selectFile(selected: File | undefined) {
    if (!selected || disabled) return
    if (selected.size === 0) {
      setError('This file is empty. Choose a file that contains data.')
      if (input.current) input.current.value = ''
      onChange(null)
      return
    }
    setError(null)
    onChange(selected)
  }

  function removeFile() {
    if (input.current) input.current.value = ''
    setError(null)
    onChange(null)
  }

  return (
    <div className="file-upload">
      <label className="dropzone" htmlFor={inputId} onDragOver={(event) => event.preventDefault()} onDrop={(event) => {
        event.preventDefault()
        selectFile(event.dataTransfer.files[0])
      }}>
        <span className="drop-illustration" aria-hidden="true"><span className="document-back" /><span className="document-front"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9Zm0 0v6h6M8 13h8M8 17h5" /></svg><span className="document-line" /><span className="document-line short" /></span><span className="upload-symbol">↑</span></span>
        <strong>{title}</strong>
        <span>or <span className="browse-link">browse files</span> on your computer</span>
        <small>{helpText ?? `Supports configuration files${accept ? ` (${accept.split(',').join(', ')})` : ''}`}</small>
      </label>
      <input
        ref={input}
        id={inputId}
        type="file"
        accept={accept}
        disabled={disabled}
        className="visually-hidden"
        aria-describedby={error ? `${inputId}-error` : undefined}
        onChange={(event) => { selectFile(event.currentTarget.files?.[0]); event.currentTarget.value = '' }}
      />
      {file && (
        <div className="selected-file" role="status">
          <span><strong>{file.name}</strong> <small>{formatFileSize(file.size)}</small></span>
          <button type="button" aria-label="Remove configuration file" onClick={removeFile}>×</button>
        </div>
      )}
      {error && <small id={`${inputId}-error`} role="alert">{error}</small>}
    </div>
  )
}

function formatFileSize(bytes: number) {
  if (bytes < 1024) return `${bytes} Bytes`
  const units = ['KB', 'MB', 'GB', 'TB']
  let size = bytes / 1024
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024
    unit += 1
  }
  return `${size.toFixed(1)} ${units[unit]}`
}
