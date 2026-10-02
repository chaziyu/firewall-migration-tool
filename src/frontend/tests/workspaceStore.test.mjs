import test from 'node:test'
import assert from 'node:assert/strict'
import { clearWorkspace, restoreWorkspace, saveWorkspace, workspace, workspaceExpired } from '../src/storage/workspaceStore.ts'

// Minimal asynchronous IndexedDB surface used only to verify legacy data is cleared.
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

test('workspace keeps customer evidence in memory only and clears legacy IndexedDB data', async () => {
  saved = {
    updatedAt: Date.now(),
    preview: { source_evidence: { source_text: 'legacy-customer-config' } },
  }

  await restoreWorkspace()
  assert.equal(saved, undefined)

  const preview = {
    vendor: 'fortigate',
    source_evidence: { vendor: 'fortigate', source_text: 'config system global\nend\n' },
  }
  await saveWorkspace({
    preview,
    password: 'must-not-persist',
    username: 'admin',
    connection: { password: 'also-secret' },
  })

  assert.equal(saved, undefined)
  assert.deepEqual(workspace().preview, preview)
  assert.deepEqual((await restoreWorkspace()).preview, preview)

  await clearWorkspace()
  assert.equal(workspace().preview, null)
  assert.equal(saved, undefined)
})

test('TTL expires in-memory state and context changes invalidate rendered artifacts', async () => {
  await clearWorkspace()
  await saveWorkspace({ preview: { vendor: 'fortigate' } })
  await saveWorkspace({ artifact: { artifact_id: 'old' } })
  await saveWorkspace({ targetDevice: 'different-target' })
  assert.equal(workspace().artifact, null)

  await saveWorkspace({ artifact: { artifact_id: 'old' } })
  await saveWorkspace({ decisionDocument: { decisions: [{ key: 'changed' }] } })
  assert.equal(workspace().artifact, null)

  const now = Date.now
  Date.now = () => now() + 25 * 60 * 60 * 1000
  try {
    assert.equal(workspaceExpired(), true)
    assert.equal((await restoreWorkspace()).preview, null)
    assert.equal(saved, undefined)
  } finally {
    Date.now = now
  }
})

test('role and decision changes invalidate deterministic state without persistent storage', async () => {
  await clearWorkspace()
  assert.equal(workspace().referenceRole, 'DESTINATION')

  await saveWorkspace({
    preview: { vendor: 'fortigate' },
    deterministicDraft: { digest: 'draft' },
    artifact: { artifact_id: 'approved' },
    decisionDocument: { design_approval: {} },
  })
  await saveWorkspace({ referenceRole: 'TEMPLATE' })
  assert.equal(workspace().deterministicDraft, null)
  assert.equal(workspace().artifact, null)

  await saveWorkspace({ deterministicDraft: { digest: 'draft' }, artifact: { artifact_id: 'approved' } })
  await saveWorkspace({ decisionDocument: null })
  assert.equal(workspace().deterministicDraft, null)
  assert.equal(workspace().artifact, null)
  assert.equal(saved, undefined)
})
