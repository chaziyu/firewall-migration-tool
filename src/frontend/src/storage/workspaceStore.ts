import type { Workspace } from './workspaceTypes'

const TTL = 24 * 60 * 60 * 1000
const empty = (): Workspace => ({ updatedAt: Date.now(), preview: null, targetSource: null, targetDevice: '', decisionDocument: null, designSession: null, deterministicDraft: null, referenceRole: 'DESTINATION', artifact: null })
let current = empty()
let writes = Promise.resolve()
let generation = 0

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('fwmigrate-workspace', 1)
    request.onupgradeneeded = () => request.result.createObjectStore('workspace')
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)
  })
}

async function transact(write: boolean, value?: Workspace | null): Promise<Workspace | undefined> {
  const db = await open()
  try {
    return await new Promise((resolve, reject) => {
      const transaction = db.transaction('workspace', write ? 'readwrite' : 'readonly')
      const store = transaction.objectStore('workspace')
      const request = !write ? store.get('current') : value ? store.put(value, 'current') : store.clear()
      transaction.oncomplete = () => resolve(write ? undefined : request.result as Workspace | undefined)
      transaction.onerror = () => reject(transaction.error)
      transaction.onabort = () => reject(transaction.error)
    })
  } finally { db.close() }
}

export function workspace(): Workspace { return current }

export function workspaceExpired(): boolean { return Boolean(current.preview) && Date.now() - current.updatedAt >= TTL }

export async function restoreWorkspace(): Promise<Workspace> {
  const saved = await transact(false)
  if (saved && Date.now() - saved.updatedAt < TTL) current = { ...empty(), ...saved }
  else await clearWorkspace()
  return current
}

export function saveWorkspace(update: Partial<Workspace>): Promise<void> {
  // Only workflow fields are persisted. Connection forms and credentials never enter this object.
  const contextChanged = (update.preview !== undefined && update.preview !== current.preview)
    || (update.targetSource !== undefined && update.targetSource !== current.targetSource)
    || (update.targetDevice !== undefined && update.targetDevice !== current.targetDevice)
    || (update.referenceRole !== undefined && update.referenceRole !== current.referenceRole)
  const decisionsChanged = update.decisionDocument !== undefined
    && JSON.stringify(update.decisionDocument) !== JSON.stringify(current.decisionDocument)
  current = { updatedAt: Date.now(), preview: update.preview === undefined ? current.preview : update.preview,
    targetSource: update.targetSource === undefined ? current.targetSource : update.targetSource,
    targetDevice: update.targetDevice ?? current.targetDevice,
    referenceRole: update.referenceRole ?? current.referenceRole,
    decisionDocument: update.decisionDocument === undefined ? current.decisionDocument : update.decisionDocument,
    designSession: update.designSession === undefined ? contextChanged ? null : current.designSession : update.designSession,
    deterministicDraft: update.deterministicDraft === undefined ? contextChanged || decisionsChanged ? null : current.deterministicDraft : update.deterministicDraft,
    artifact: update.artifact === undefined ? contextChanged || decisionsChanged ? null : current.artifact : update.artifact }
  const snapshot = current
  const version = generation
  const pending = writes.then(async () => { if (version === generation) await transact(true, snapshot) })
  writes = pending.catch(() => {})
  return pending
}

export function clearWorkspace(): Promise<void> {
  generation++
  current = empty()
  const pending = writes.then(async () => { await transact(true, null) })
  writes = pending.catch(() => {})
  return pending
}
