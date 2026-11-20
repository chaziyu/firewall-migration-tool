import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import ts from 'typescript'

function loadDesktopUtils() {
  const compiled = ts.transpileModule(readFileSync(new URL('../src/utils/desktop.ts', import.meta.url), 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS },
  }).outputText
  const exports = {}
  new Function('exports', compiled)(exports)
  return exports
}

test('saveBlobWithFallback uses pywebview.api.save_file when available', async () => {
  const { saveBlobWithFallback } = loadDesktopUtils()
  const originalWindow = globalThis.window
  const calls = []
  globalThis.window = {
    pywebview: {
      api: {
        async save_file(filename, contentBase64) {
          calls.push({ filename, contentBase64 })
          return { saved: true, cancelled: false, filename }
        },
      },
    },
  }
  try {
    const blob = new Blob(['hello-xlsx'], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' })
    const result = await saveBlobWithFallback(blob, 'fortigate-source-report.xlsx')
    assert.deepEqual(result, { status: 'saved', filename: 'fortigate-source-report.xlsx' })
    assert.equal(calls.length, 1)
    assert.equal(calls[0].filename, 'fortigate-source-report.xlsx')
    assert.equal(Buffer.from(calls[0].contentBase64, 'base64').toString('utf8'), 'hello-xlsx')
  } finally {
    globalThis.window = originalWindow
  }
})

test('saveBlobWithFallback returns cancelled when desktop save dialog is cancelled', async () => {
  const { saveBlobWithFallback } = loadDesktopUtils()
  const originalWindow = globalThis.window
  globalThis.window = {
    pywebview: {
      api: {
        async save_file() {
          return { saved: false, cancelled: true }
        },
      },
    },
  }
  try {
    const blob = new Blob(['xlsx'])
    const result = await saveBlobWithFallback(blob, 'fortigate-source-report.xlsx')
    assert.deepEqual(result, { status: 'cancelled', filename: 'fortigate-source-report.xlsx' })
  } finally {
    globalThis.window = originalWindow
  }
})
