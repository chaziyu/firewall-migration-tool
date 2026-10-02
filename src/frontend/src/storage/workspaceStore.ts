import type { Workspace } from './workspaceTypes'

const TTL = 24 * 60 * 60 * 1000
const empty = (): Workspace => ({ updatedAt: Date.now(), preview: null, targetSource: null, targetDevice: '', decisionDocument: null, deterministicDraft: null, referenceRole: 'DESTINATION', artifact: null })
let current = empty()

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
  if (workspaceExpired()) current = empty()
  // Customer configuration and migration state are memory-only. Clear data
  // persisted by older releases instead of restoring it into the application.
  if (typeof indexedDB !== 'undefined') await transact(true, null)
  return current
}

export function saveWorkspace(update: Partial<Workspace>): Promise<void> {
  // Workflow state can contain sanitized customer configuration and target topology.
  // Keep it in memory only; connection forms and credentials never enter this object.
  const contextChanged = (update.preview !== undefined && update.preview !== current.preview)
    || (update.targetSource !== undefined && update.targetSource !== current.targetSource)
    || (update.targetDevice !== undefined && update.targetDevice !== current.targetDevice)
    || (update.referenceRole !== undefined && update.referenceRole !== current.referenceRole)
  const decisionsChanged = update.decisionDocument !== undefined
    && JSON.stringify(update.decisionDocument) !== JSON.stringify(current.decisionDocument)
  const derivedStateChanged = contextChanged || decisionsChanged
  current = {
    updatedAt: Date.now(),
    preview: update.preview === undefined ? current.preview : update.preview,
    targetSource: update.targetSource === undefined ? current.targetSource : update.targetSource,
    targetDevice: update.targetDevice ?? current.targetDevice,
    referenceRole: update.referenceRole ?? current.referenceRole,
    decisionDocument: update.decisionDocument === undefined ? current.decisionDocument : update.decisionDocument,
    deterministicDraft: update.deterministicDraft === undefined
      ? (derivedStateChanged ? null : current.deterministicDraft)
      : update.deterministicDraft,
    artifact: update.artifact === undefined
      ? (derivedStateChanged ? null : current.artifact)
      : update.artifact,
  }
  return Promise.resolve()
}

export async function clearWorkspace(): Promise<void> {
  current = empty()
  if (typeof indexedDB !== 'undefined') await transact(true, null)
}
