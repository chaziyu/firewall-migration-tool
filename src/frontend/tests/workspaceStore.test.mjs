import test from 'node:test'
import assert from 'node:assert/strict'
import { clearWorkspace, restoreWorkspace, saveWorkspace, workspace, workspaceExpired } from '../src/storage/workspaceStore.ts'

// Minimal asynchronous IndexedDB surface used by this store; browser smoke tests cover native IndexedDB.
let saved
globalThis.indexedDB = {
  open() {
    const request = {}
    request.result = {
      close() {},
      transaction() {
        const transaction = {
          objectStore() {
            function operation(action) {
              const result = {}
              setTimeout(() => { result.result = action(); transaction.oncomplete() }, 0)
              return result
            }
            return {
              get: () => operation(() => structuredClone(saved)),
              put: (value) => operation(() => { saved = structuredClone(value) }),
              clear: () => operation(() => { saved = undefined }),
            }
          },
        }
        return transaction
      },
    }
    queueMicrotask(() => request.onsuccess())
    return request
  },
}

test('workspace persists sanitized evidence and decisions, excludes credentials, and clears queued writes', async () => {
  await clearWorkspace()
  const preview = { vendor: 'fortigate', source_evidence: { vendor: 'fortigate', source_text: 'config system global\nend\n' } }
  await saveWorkspace({ preview, password: 'must-not-persist', username: 'admin', connection: { password: 'also-secret' } })
  assert.equal(JSON.stringify(saved).includes('must-not-persist'), false)
  assert.equal(JSON.stringify(saved).includes('also-secret'), false)
  assert.equal('username' in saved, false)
  assert.deepEqual((await restoreWorkspace()).preview, preview)
  const pending = saveWorkspace({ targetDevice: 'device-1' })
  await clearWorkspace()
  await pending
  assert.equal(saved, undefined)
  assert.equal(workspace().preview, null)
})

test('TTL removes expired workspaces and changes invalidate the previous rendered artifact', async () => {
  await saveWorkspace({ preview: { vendor: 'fortigate' } })
  await saveWorkspace({ artifact: { artifact_id: 'old' }, designSession: { proposals: [] } })
  await saveWorkspace({ targetDevice: 'different-target' })
  assert.equal(workspace().artifact, null)
  assert.equal(workspace().designSession, null)
  await saveWorkspace({ artifact: { artifact_id: 'old' } })
  await saveWorkspace({ decisionDocument: { decisions: [{ key: 'changed' }] } })
  assert.equal(workspace().artifact, null)
  const now = Date.now
  Date.now = () => now() + 25 * 60 * 60 * 1000
  try {
    assert.equal(workspaceExpired(), true)
    assert.equal((await restoreWorkspace()).preview, null)
    assert.equal(saved, undefined)
  } finally { Date.now = now }
})
