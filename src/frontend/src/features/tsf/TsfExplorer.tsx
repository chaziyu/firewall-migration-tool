import { useCallback, useEffect, useRef, useState } from 'react'
import { Button } from '../../components/common/Button'
import { ErrorBanner } from '../../components/common/ErrorBanner'
import { Toast } from '../../components/common/Toast'
import { saveBlobWithFallback } from '../../utils/desktop'
import {
  downloadTsfFile,
  fetchTsfFile,
  fetchTsfStatus,
  fetchTsfTree,
  searchTsf,
} from './tsfApi'
import type {
  TsfFileResponse,
  TsfSearchResult,
  TsfSessionInfo,
  TsfStatusResponse,
  TsfTreeResponse,
} from './types'

type SearchMode = 'filename' | 'content'

export function TsfExplorer({
  session,
  initialRootTree,
  initialStatus,
}: {
  session: TsfSessionInfo
  initialRootTree?: TsfTreeResponse
  initialStatus?: TsfStatusResponse
}) {
  const [searchMode, setSearchMode] = useState<SearchMode>('filename')
  const [query, setQuery] = useState('')
  const [searching, setSearching] = useState(false)
  const [searchError, setSearchError] = useState<string | null>(null)
  const [searchResults, setSearchResults] = useState<TsfSearchResult[] | null>(null)
  const [resultsMode, setResultsMode] = useState<SearchMode>('filename')
  const [viewMode, setViewMode] = useState<'viewer' | 'results'>('viewer')

  const [status, setStatus] = useState<TsfStatusResponse | null>(initialStatus ?? null)
  const [dirCache, setDirCache] = useState<Record<string, TsfTreeResponse>>(() => {
    const initial: Record<string, TsfTreeResponse> = {}
    if (initialRootTree) initial[''] = initialRootTree
    return initial
  })
  const [expandedDirs, setExpandedDirs] = useState<Record<string, boolean>>({})
  const [dirLoading, setDirLoading] = useState<Record<string, boolean>>({})
  const [treeError, setTreeError] = useState<string | null>(null)

  const [selectedPath, setSelectedPath] = useState('')
  const [fileData, setFileData] = useState<TsfFileResponse | null>(null)
  const [fileLoading, setFileLoading] = useState(false)
  const [fileError, setFileError] = useState<string | null>(null)
  const [highlightLine, setHighlightLine] = useState(0)
  const [downloadStatus, setDownloadStatus] = useState('')
  const [downloading, setDownloading] = useState(false)

  const jumpRowRef = useRef<HTMLDivElement | null>(null)
  const fileReqRef = useRef(0)

  const loadDirectory = useCallback(async (dirPath: string) => {
    setDirLoading((prev) => ({ ...prev, [dirPath]: true }))
    setTreeError(null)
    try {
      const data = await fetchTsfTree(session.sessionId, dirPath)
      setDirCache((prev) => ({ ...prev, [dirPath]: data }))
    } catch (cause) {
      setTreeError(cause instanceof Error ? cause.message : 'Failed to load directory.')
    } finally {
      setDirLoading((prev) => ({ ...prev, [dirPath]: false }))
    }
  }, [session.sessionId])

  useEffect(() => {
    if (initialRootTree) return
    let active = true
    void fetchTsfTree(session.sessionId, '')
      .then((data) => {
        if (active) setDirCache((prev) => ({ ...prev, '': data }))
      })
      .catch((cause) => {
        if (active) setTreeError(cause instanceof Error ? cause.message : 'Failed to load directory.')
      })
    return () => { active = false }
  }, [initialRootTree, session.sessionId])

  useEffect(() => {
    if (status?.content_ready) return
    let active = true
    let timer: number | undefined

    const poll = async () => {
      try {
        const next = await fetchTsfStatus(session.sessionId)
        if (!active) return
        setStatus(next)
        if (!next.content_ready) {
          timer = window.setTimeout(poll, 1000)
        }
      } catch {
        if (active) {
          timer = window.setTimeout(poll, 1500)
        }
      }
    }

    void poll()
    return () => {
      active = false
      if (timer !== undefined) window.clearTimeout(timer)
    }
  }, [session.sessionId, status?.content_ready])

  useEffect(() => {
    if (highlightLine > 0 && jumpRowRef.current) {
      jumpRowRef.current.scrollIntoView({ block: 'center' })
    }
  }, [fileData, highlightLine])

  const openFile = useCallback(async (relPath: string, page = 0, jumpLine = 0) => {
    const reqId = ++fileReqRef.current
    setSelectedPath(relPath)
    setViewMode('viewer')
    setFileLoading(true)
    setFileError(null)
    setDownloadStatus('')
    setHighlightLine(jumpLine)
    try {
      const data = await fetchTsfFile(session.sessionId, relPath, page, jumpLine)
      if (reqId !== fileReqRef.current) return
      setFileData(data)
    } catch (cause) {
      if (reqId !== fileReqRef.current) return
      setFileError(cause instanceof Error ? cause.message : 'Failed to load file.')
      setFileData(null)
    } finally {
      if (reqId === fileReqRef.current) setFileLoading(false)
    }
  }, [session.sessionId])

  const toggleDir = useCallback((dirPath: string) => {
    setExpandedDirs((prev) => {
      const nextOpen = !prev[dirPath]
      if (nextOpen && !dirCache[dirPath] && !dirLoading[dirPath]) {
        void loadDirectory(dirPath)
      }
      return { ...prev, [dirPath]: nextOpen }
    })
  }, [dirCache, dirLoading, loadDirectory])

  const runSearch = useCallback(async () => {
    const trimmed = query.trim()
    if (!trimmed) return
    setSearching(true)
    setSearchError(null)
    setViewMode('results')
    try {
      const res = await searchTsf(session.sessionId, searchMode, trimmed)
      setResultsMode(res.mode)
      setSearchResults(res.results)
    } catch (cause) {
      setSearchError(cause instanceof Error ? cause.message : 'TSF search failed.')
      setSearchResults([])
    } finally {
      setSearching(false)
    }
  }, [query, searchMode, session.sessionId])

  const clearSearch = useCallback(() => {
    setQuery('')
    setSearchResults(null)
    setSearchError(null)
    setViewMode('viewer')
  }, [])

  const handleDownload = useCallback(async (relPath: string) => {
    setDownloading(true)
    setDownloadStatus('')
    try {
      const blob = await downloadTsfFile(session.sessionId, relPath)
      const name = relPath.split('/').pop() || 'tsf-file'
      const saved = await saveBlobWithFallback(blob, name)
      if (saved.status === 'saved') {
        setDownloadStatus(`Saved to Downloads: ${saved.path || saved.filename}`)
      } else if (saved.status === 'downloaded') {
        setDownloadStatus(`Download started: ${saved.filename}`)
      }
    } catch (cause) {
      setDownloadStatus(cause instanceof Error ? cause.message : 'Download failed.')
    } finally {
      setDownloading(false)
    }
  }, [session.sessionId])

  function renderTreeBranch(dirPath: string, depth: number) {
    const entry = dirCache[dirPath]
    if (!entry) {
      if (dirLoading[dirPath]) {
        return <div className="tsf-tree-empty" style={{ paddingLeft: `${depth * 14 + 10}px` }}>Loading…</div>
      }
      return null
    }
    if (entry.dirs.length === 0 && entry.files.length === 0) {
      return <div className="tsf-tree-empty" style={{ paddingLeft: `${depth * 14 + 10}px` }}>(empty)</div>
    }
    return (
      <>
        {entry.dirs.map((subDir) => {
          const name = subDir.split('/').pop() || subDir
          const isOpen = Boolean(expandedDirs[subDir])
          return (
            <div key={subDir}>
              <button
                type="button"
                className="tsf-tree-node tsf-tree-dir"
                style={{ paddingLeft: `${depth * 14 + 8}px` }}
                aria-expanded={isOpen}
                onClick={() => toggleDir(subDir)}
              >
                <span className="tsf-tree-caret" aria-hidden="true">{isOpen ? '▾' : '▸'}</span>
                <span className="tsf-tree-label">{name}</span>
              </button>
              {isOpen && renderTreeBranch(subDir, depth + 1)}
            </div>
          )
        })}
        {entry.files.map((file) => {
          const selected = file.rel_path === selectedPath
          return (
            <button
              key={file.rel_path}
              type="button"
              className={`tsf-tree-node tsf-tree-file${selected ? ' selected' : ''}`}
              style={{ paddingLeft: `${depth * 14 + 22}px` }}
              title={file.rel_path}
              onClick={() => void openFile(file.rel_path, 0, 0)}
            >
              <span className="tsf-tree-label">{file.name}</span>
              <span className="tsf-tree-size">{file.size_human}</span>
            </button>
          )
        })}
      </>
    )
  }

  const totalFiles = status?.total_files ?? session.totalFiles
  const contentReady = status?.content_ready ?? false
  const contentPct = Math.round((status?.content_progress ?? 0) * 100)

  return (
    <section className="tsf-explorer" aria-label="Palo Alto TSF Explorer">
      <div className="tsf-toolbar">
        <div className="tsf-mode-group" role="group" aria-label="Search mode">
          <button
            type="button"
            className={`tsf-mode-btn${searchMode === 'filename' ? ' active' : ''}`}
            onClick={() => setSearchMode('filename')}
          >
            Filename
          </button>
          <button
            type="button"
            className={`tsf-mode-btn${searchMode === 'content' ? ' active' : ''}`}
            onClick={() => setSearchMode('content')}
          >
            Content
          </button>
        </div>

        <div className="tsf-search-controls">
          <input
            type="search"
            className="tsf-search-input"
            aria-label="Search TSF archive"
            value={query}
            placeholder={
              searchMode === 'filename'
                ? 'Search filenames (e.g. mp-log, running-config, dp-monitor)…'
                : 'Search inside text files (e.g. error, 10.10.1.1, failover)…'
            }
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') {
                event.preventDefault()
                void runSearch()
              }
            }}
          />
          <Button type="button" onClick={() => void runSearch()} disabled={searching || !query.trim()}>
            {searching ? 'Searching…' : 'Search'}
          </Button>
          {searchResults !== null && (
            <Button type="button" className="text-button" onClick={clearSearch}>
              Clear
            </Button>
          )}
        </div>

        <div className="tsf-status-wrap">
          {session.skippedCount > 0 && (
            <span className="fw-badge fw-badge-muted" title="Files skipped by security screening">
              {session.skippedCount} skipped
            </span>
          )}
          <span className={`fw-badge ${contentReady ? 'fw-badge-allow' : 'fw-badge-info'}`}>
            {contentReady
              ? `Indexed · ${totalFiles.toLocaleString()} files`
              : `Indexing content (${contentPct}%) · ${totalFiles.toLocaleString()} files`}
          </span>
        </div>
      </div>

      {status?.content_error && <ErrorBanner message={status.content_error} />}

      <div className="tsf-split">
        <aside className="tsf-tree-pane" aria-label="TSF directory tree">
          <div className="tsf-pane-header">Archive Tree</div>
          {treeError && <ErrorBanner message={treeError} />}
          <div className="tsf-tree-scroll">{renderTreeBranch('', 0)}</div>
        </aside>

        <div className="tsf-viewer-pane" aria-label="TSF file viewer">
          {viewMode === 'results' && searchResults !== null ? (
            <>
              <div className="tsf-viewer-header">
                <div>
                  <div className="tsf-viewer-path">
                    Search Results ({resultsMode}) — {searchResults.length.toLocaleString()} match(es)
                  </div>
                  <div className="tsf-viewer-meta">Query: &ldquo;{query.trim()}&rdquo;</div>
                </div>
                {fileData && (
                  <Button type="button" className="text-button" onClick={() => setViewMode('viewer')}>
                    Back to file
                  </Button>
                )}
              </div>
              {searchError && <ErrorBanner message={searchError} />}
              {searchResults.length === 0 ? (
                <div className="tsf-empty-state">No matches found.</div>
              ) : (
                <div className="tsf-result-list">
                  {searchResults.map((hit, idx) => (
                    <button
                      key={`${hit.rel_path}:${hit.line_number ?? idx}`}
                      type="button"
                      className="tsf-result-item"
                      onClick={() => void openFile(hit.rel_path, 0, hit.line_number ?? 0)}
                    >
                      <div className="tsf-result-path">
                        {hit.line_number ? `${hit.rel_path}:${hit.line_number}` : hit.rel_path}
                      </div>
                      {(hit.line_text || hit.size_human) && (
                        <div className="tsf-result-snippet">{hit.line_text ?? hit.size_human}</div>
                      )}
                    </button>
                  ))}
                </div>
              )}
            </>
          ) : fileLoading ? (
            <div className="tsf-empty-state">Loading file…</div>
          ) : fileError ? (
            <div className="tsf-empty-state"><ErrorBanner message={fileError} /></div>
          ) : !fileData ? (
            <div className="tsf-empty-state">
              Select a file from the archive tree or search filenames and log contents above.
            </div>
          ) : (
            <>
              <div className="tsf-viewer-header">
                <div>
                  <div className="tsf-viewer-path">{fileData.rel_path}</div>
                  <div className="tsf-viewer-meta">
                    {fileData.success
                      ? `${fileData.size_human} · ${(fileData.total_lines ?? 0).toLocaleString()} lines · Page ${(fileData.page ?? 0) + 1} of ${fileData.total_pages ?? 1}${fileData.truncated ? ' (truncated at 10 MB)' : ''}`
                      : fileData.size_human}
                  </div>
                </div>
                <div className="tsf-viewer-actions">
                  {searchResults !== null && (
                    <Button type="button" className="text-button" onClick={() => setViewMode('results')}>
                      Search results ({searchResults.length})
                    </Button>
                  )}
                  <Button
                    type="button"
                    disabled={downloading}
                    onClick={() => void handleDownload(fileData.rel_path)}
                  >
                    {downloading ? 'Downloading…' : 'Download'}
                  </Button>
                </div>
              </div>

              {downloadStatus && <Toast message={downloadStatus} onDismiss={() => setDownloadStatus('')} />}

              {!fileData.success ? (
                <div className="tsf-empty-state">
                  {fileData.error || 'This file cannot be previewed.'}
                </div>
              ) : (
                <>
                  <div className="tsf-code-wrap">
                    {(fileData.lines ?? []).map(([lineNo, lineText]) => {
                      const isTarget = highlightLine > 0 && lineNo === highlightLine
                      return (
                        <div
                          key={lineNo}
                          ref={isTarget ? jumpRowRef : undefined}
                          className={`tsf-code-line${isTarget ? ' highlight' : ''}`}
                        >
                          <span className="tsf-line-no">{lineNo}</span>
                          <span className="tsf-line-text">{lineText}</span>
                        </div>
                      )
                    })}
                  </div>

                  {(fileData.total_pages ?? 0) > 1 && (
                    <div className="tsf-pager">
                      <Button
                        type="button"
                        disabled={(fileData.page ?? 0) <= 0}
                        onClick={() => void openFile(fileData.rel_path, (fileData.page ?? 0) - 1, 0)}
                      >
                        ← Previous
                      </Button>
                      <span className="tsf-pager-info">
                        Page {(fileData.page ?? 0) + 1} / {fileData.total_pages}
                      </span>
                      <Button
                        type="button"
                        disabled={(fileData.page ?? 0) >= (fileData.total_pages ?? 1) - 1}
                        onClick={() => void openFile(fileData.rel_path, (fileData.page ?? 0) + 1, 0)}
                      >
                        Next →
                      </Button>
                    </div>
                  )}
                </>
              )}
            </>
          )}
        </div>
      </div>
    </section>
  )
}
