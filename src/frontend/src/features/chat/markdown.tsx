import { Fragment, type ReactNode } from 'react'

function renderInlineMarkdown(line: string): ReactNode[] {
  const tokens = line.split(/(`[^`\n]+`|\*\*[^*\n]+\*\*|\*[^*\n]+\*)/g)
  return tokens.map((token, idx) => {
    if (token.startsWith('`') && token.endsWith('`') && token.length >= 2) {
      return <code key={idx}>{token.slice(1, -1)}</code>
    }
    if (token.startsWith('**') && token.endsWith('**') && token.length >= 4) {
      return <strong key={idx}>{token.slice(2, -2)}</strong>
    }
    if (token.startsWith('*') && token.endsWith('*') && token.length >= 2) {
      return <em key={idx}>{token.slice(1, -1)}</em>
    }
    return <Fragment key={idx}>{token}</Fragment>
  })
}

export function renderMarkdownBlocks(raw: string): ReactNode[] {
  if (!raw) return []
  const segments = raw.split(/(```[a-zA-Z0-9_-]*\n?[\s\S]*?```)/g)
  const nodes: ReactNode[] = []
  let keyIdx = 0

  for (const segment of segments) {
    if (!segment) continue
    if (segment.startsWith('```') && segment.endsWith('```')) {
      const inner = segment.replace(/^```[a-zA-Z0-9_-]*\r?\n?/, '').replace(/```$/, '').replace(/\n$/, '')
      nodes.push(
        <pre key={`cb-${keyIdx++}`}>
          <code>{inner}</code>
        </pre>,
      )
      continue
    }

    const lines = segment.split(/\r?\n/)
    let para: string[] = []
    let listKind: 'ul' | 'ol' | null = null
    let listItems: string[] = []

    const flushPara = () => {
      if (!para.length) return
      nodes.push(
        <p key={`p-${keyIdx++}`}>
          {para.map((line, i) => (
            <Fragment key={i}>
              {i > 0 && <br />}
              {renderInlineMarkdown(line)}
            </Fragment>
          ))}
        </p>,
      )
      para = []
    }

    const flushList = () => {
      if (!listKind || !listItems.length) {
        listKind = null
        listItems = []
        return
      }
      const Tag = listKind
      nodes.push(
        <Tag key={`list-${keyIdx++}`}>
          {listItems.map((item, i) => (
            <li key={i}>{renderInlineMarkdown(item)}</li>
          ))}
        </Tag>,
      )
      listKind = null
      listItems = []
    }

    for (const line of lines) {
      const trimmed = line.trim()
      if (!trimmed) {
        flushPara()
        flushList()
        continue
      }
      const ulMatch = line.match(/^\s*[-*]\s+(.+)$/)
      if (ulMatch) {
        flushPara()
        if (listKind !== 'ul') {
          flushList()
          listKind = 'ul'
        }
        listItems.push(ulMatch[1])
        continue
      }
      const olMatch = line.match(/^\s*\d+\.\s+(.+)$/)
      if (olMatch) {
        flushPara()
        if (listKind !== 'ol') {
          flushList()
          listKind = 'ol'
        }
        listItems.push(olMatch[1])
        continue
      }
      flushList()
      para.push(line)
    }

    flushPara()
    flushList()
  }

  return nodes
}
