export type TsfSessionInfo = {
  sessionId: string
  filename: string
  totalFiles: number
  skippedCount: number
}

export type TsfUploadResponse = {
  success: boolean
  job_id: string
  filename: string
  error?: string
}

export type TsfProgressResponse = {
  success: boolean
  status: 'running' | 'done' | 'error'
  progress: number
  message: string
  session_id: string
  filename: string
  total_files: number
  skipped_count: number
  error: string
}

export type TsfStatusResponse = {
  success: boolean
  total_files: number
  content_ready: boolean
  content_progress: number
  content_error: string
}

export type TsfTreeFile = {
  rel_path: string
  name: string
  size_bytes: number
  size_human: string
  is_text: boolean
}

export type TsfTreeResponse = {
  success: boolean
  path: string
  dirs: string[]
  files: TsfTreeFile[]
}

export type TsfFileResponse = {
  success: boolean
  rel_path: string
  size_human: string
  is_binary?: boolean
  truncated?: boolean
  total_lines?: number
  total_pages?: number
  page?: number
  lines?: [number, string][]
  error?: string
}

export type TsfSearchResult = {
  rel_path: string
  name?: string
  size_human?: string
  line_number?: number
  line_text?: string
}

export type TsfSearchResponse = {
  success: boolean
  mode: 'filename' | 'content'
  results: TsfSearchResult[]
}
