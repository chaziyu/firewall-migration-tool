import { useEffect, useRef, useState } from 'react'
import type { SourcePreviewData } from '../source/types'
import { renderMarkdownBlocks } from './markdown'

export interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
  error?: boolean
}

export interface KeyStatus {
  configured: boolean
  source: string | null
  masked: string | null
}

type ChatSize = 'compact' | 'expanded' | 'overlay'

const SUGGESTED_QUESTIONS = [
  'Summarize interfaces, zones, and routing setup',
  'Highlight top validation errors and unresolved references',
  'Which policies permit wide/any traffic or lack inspection profiles?',
]

export function ConfigChatWidget({ vendor, filename, preview }: {
  vendor: string
  filename: string
  preview: SourcePreviewData
}) {
  const [isOpen, setIsOpen] = useState(false)
  const [size, setSize] = useState<ChatSize>('compact')
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [question, setQuestion] = useState('')
  const [sending, setSending] = useState(false)
  const [vendorMismatch, setVendorMismatch] = useState<string | null>(null)
  const [keyStatus, setKeyStatus] = useState<KeyStatus>({ configured: false, source: null, masked: null })
  const [keyDrawerOpen, setKeyDrawerOpen] = useState(false)
  const [keyInput, setKeyInput] = useState('')
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    let active = true
    fetch('/api/chat')
      .then(async (res) => {
        if (!res.ok) return
        const data = (await res.json()) as {
          history?: ChatMessage[]
          vendor_mismatch?: string | null
          key_status?: KeyStatus
        }
        if (!active) return
        if (data.vendor_mismatch) setVendorMismatch(data.vendor_mismatch)
        if (data.key_status) {
          setKeyStatus(data.key_status)
          if (!data.key_status.configured) setKeyDrawerOpen(true)
        }
        if (Array.isArray(data.history) && data.history.length > 0) {
          setMessages(data.history)
        }
      })
      .catch(() => { /* Chat remains available for manual retry. */ })
    return () => { active = false }
  }, [])

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ block: 'end' })
  }, [messages, sending, isOpen])

  useEffect(() => {
    if (isOpen) inputRef.current?.focus()
  }, [isOpen])

  async function saveApiKey(value: string) {
    try {
      const res = await fetch('/api/chat/key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: value }),
      })
      if (!res.ok) return
      const data = (await res.json()) as { key_status?: KeyStatus }
      if (data.key_status) setKeyStatus(data.key_status)
      setKeyInput('')
      if (value) setKeyDrawerOpen(false)
    } catch {
      // Keep drawer open on failure.
    }
  }

  async function clearConversation() {
    try {
      await fetch('/api/chat', { method: 'DELETE' })
    } catch {
      // Clear local state regardless.
    }
    setMessages([])
  }

  async function sendQuestion(rawQuestion: string) {
    const trimmed = rawQuestion.trim()
    if (!trimmed || sending) return
    setQuestion('')
    setSending(true)
    setMessages((prev) => [...prev, { role: 'user', content: trimmed }])

    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          question: trimmed,
          vendor: vendor || preview.vendor || 'firewall',
          filename: filename || preview.source_evidence?.source_name || 'config',
          source_text: preview.source_evidence?.source_text,
          preview,
        }),
      })
      const data = (await res.json()) as {
        ok?: boolean
        reply?: string
        error?: string
        history?: ChatMessage[]
        vendor_mismatch?: string | null
        key_status?: KeyStatus
      }
      if (data.key_status) setKeyStatus(data.key_status)
      if (data.vendor_mismatch !== undefined) setVendorMismatch(data.vendor_mismatch ?? null)

      if (!res.ok) {
        setMessages((prev) => [...prev, { role: 'assistant', content: `⚠️ ${data.error || 'Chat request failed.'}`, error: true }])
      } else if (data.ok === false) {
        setMessages((prev) => [...prev, { role: 'assistant', content: data.reply || '⚠️ Chat request failed.', error: true }])
        if (!keyStatus.configured) setKeyDrawerOpen(true)
      } else if (Array.isArray(data.history)) {
        setMessages(data.history)
      } else if (data.reply) {
        setMessages((prev) => [...prev, { role: 'assistant', content: data.reply! }])
      }
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: `⚠️ Network error: ${err instanceof Error ? err.message : 'Request failed'}`, error: true },
      ])
    } finally {
      setSending(false)
      inputRef.current?.focus()
    }
  }

  return (
    <>
      {isOpen && size === 'overlay' && (
        <div className="fw-chat-backdrop" onClick={() => setIsOpen(false)} aria-hidden="true" />
      )}
      <button
        type="button"
        id="fw-chat-fab"
        className="fw-chat-fab"
        aria-expanded={isOpen}
        aria-label="Ask AI about this firewall config"
        title="Ask AI about this firewall config"
        onClick={() => setIsOpen((open) => !open)}
      >
        <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
        </svg>
      </button>
      {isOpen && (
        <section
          id="fw-chat-panel"
          className={`fw-chat-panel size-${size}`}
          aria-label="AI Config Assistant"
        >
          <header className="fw-chat-header">
            <div>
              <div className="fw-chat-header-title">✨ Config Assistant</div>
              <div className="fw-chat-header-sub">
                {vendor || 'firewall'} · {filename || 'Loaded config'}
              </div>
            </div>
            <div className="fw-chat-controls">
              <button
                type="button"
                id="fw-chat-key-toggle"
                className={`fw-chat-icon-btn${keyStatus.configured ? ' has-key' : ''}${keyDrawerOpen ? ' active' : ''}`}
                title={keyStatus.configured ? `Gemini API Key configured (${keyStatus.source}: ${keyStatus.masked})` : 'Configure Gemini API Key'}
                onClick={() => setKeyDrawerOpen((open) => !open)}
              >
                🔑
              </button>
              {([['compact', '◳', 'Compact'], ['expanded', '◰', 'Expanded'], ['overlay', '⛶', 'Overlay']] as const).map(
                ([sz, icon, label]) => (
                  <button
                    key={sz}
                    type="button"
                    className={`fw-chat-icon-btn${size === sz ? ' active' : ''}`}
                    title={label}
                    aria-label={label}
                    onClick={() => setSize(sz)}
                  >
                    {icon}
                  </button>
                ),
              )}
              <button
                type="button"
                id="fw-chat-clear"
                className="fw-chat-icon-btn"
                title="Clear conversation"
                aria-label="Clear conversation"
                onClick={() => void clearConversation()}
              >
                🗑
              </button>
              <button
                type="button"
                id="fw-chat-close"
                className="fw-chat-icon-btn"
                title="Close"
                aria-label="Close chat assistant"
                onClick={() => setIsOpen(false)}
              >
                ✕
              </button>
            </div>
          </header>

          {keyDrawerOpen && (
            <div id="fw-chat-key-drawer" className="fw-chat-key-drawer">
              <div className="fw-chat-key-row">
                <span className="fw-chat-key-label">
                  {keyStatus.configured ? '🔑 Gemini API Key' : '🔑 Gemini API Key Required'}
                </span>
                <span className={`fw-chat-key-badge${keyStatus.configured ? ' is-configured' : ''}`}>
                  {keyStatus.configured ? `Active (${keyStatus.masked})` : 'Not configured'}
                </span>
              </div>
              <div className="fw-chat-key-form">
                <input
                  type="password"
                  id="fw-chat-key-input"
                  className="fw-chat-input"
                  placeholder="Paste GEMINI_API_KEY (AIza...)"
                  autoComplete="off"
                  value={keyInput}
                  onChange={(e) => setKeyInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && keyInput.trim()) {
                      e.preventDefault()
                      void saveApiKey(keyInput.trim())
                    }
                  }}
                />
                <button
                  type="button"
                  className="fw-chat-btn-primary"
                  onClick={() => { if (keyInput.trim()) void saveApiKey(keyInput.trim()) }}
                >
                  Save
                </button>
                <button
                  type="button"
                  className="fw-chat-btn-secondary"
                  title="Clear session key"
                  onClick={() => void saveApiKey('')}
                >
                  Clear
                </button>
              </div>
              <div className="fw-chat-key-hint">
                Stored in memory for your current session only — never saved to disk or shared with other users.
              </div>
            </div>
          )}

          {vendorMismatch && (
            <div className="fw-chat-mismatch">{vendorMismatch}</div>
          )}

          <div className="fw-chat-messages">
            {messages.length === 0 && !sending ? (
              <div className="fw-chat-empty">
                <p>Ask anything about policies, routes, VPNs, interfaces, security profiles, or validation findings in this config.</p>
                <div className="fw-chat-suggestions">
                  {SUGGESTED_QUESTIONS.map((suggestion) => (
                    <button
                      key={suggestion}
                      type="button"
                      className="fw-chat-suggestion-chip"
                      onClick={() => void sendQuestion(suggestion)}
                    >
                      {suggestion}
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              messages.map((msg, idx) => (
                <div
                  key={idx}
                  className={`fw-chat-msg fw-chat-msg-${msg.role === 'user' ? 'user' : 'assistant'}${msg.error ? ' fw-chat-msg-error' : ''}`}
                >
                  {msg.role === 'user' ? msg.content : renderMarkdownBlocks(msg.content)}
                </div>
              ))
            )}
            {sending && (
              <div className="fw-chat-msg fw-chat-msg-assistant">
                Thinking…
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          <form
            className="fw-chat-input-bar"
            onSubmit={(e) => {
              e.preventDefault()
              void sendQuestion(question)
            }}
          >
            <input
              ref={inputRef}
              type="text"
              className="fw-chat-input"
              placeholder="Ask about this config..."
              autoComplete="off"
              disabled={sending}
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
            />
            <button type="submit" className="fw-chat-btn-primary" disabled={sending || !question.trim()}>
              Send
            </button>
          </form>
        </section>
      )}
    </>
  )
}
