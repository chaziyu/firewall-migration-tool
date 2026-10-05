import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import ts from 'typescript'
import { mockIPC, clearMocks } from '@tauri-apps/api/mocks'

const source = await readFile(new URL('../src/features/update/desktopUpdater.ts', import.meta.url), 'utf8')
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText
  .replace('../../api/client.ts', new URL('../src/api/client.ts', import.meta.url).href)
  .replaceAll('@tauri-apps/api/app', import.meta.resolve('@tauri-apps/api/app'))
  .replaceAll('@tauri-apps/api/core', import.meta.resolve('@tauri-apps/api/core'))
  .replaceAll('@tauri-apps/plugin-updater', import.meta.resolve('@tauri-apps/plugin-updater'))
const serviceUrl = `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`
const { checkForUpdate, installedVersion, installUpdate, validateUpdate } = await import(serviceUrl)

function metadata(url = 'https://github.com/chaziyu/firewall-migration-tool/releases/download/desktop-v0.2.1/Firewall.Migration.Tool_0.2.1_x64-setup.exe') {
  return { rid: 1, currentVersion: '0.2.0', version: '0.2.1', body: '<script>untrusted notes</script>',
    rawJson: { platforms: { 'windows-x86_64': { url, signature: 'signed' } } } }
}

function desktop(context) {
  globalThis.window = globalThis
  globalThis.__FWMIGRATE_DESKTOP__ = { apiBase: 'http://127.0.0.1:54321', token: 'test' }
  context.after(() => { clearMocks(); delete globalThis.window; delete globalThis.__FWMIGRATE_DESKTOP__ })
}

test('browser cannot check, read version or install; sidebar has no update control', async () => {
  delete globalThis.__FWMIGRATE_DESKTOP__
  await assert.rejects(checkForUpdate(), /unavailable in the browser/)
  await assert.rejects(installedVersion(), /unavailable in the browser/)
  await assert.rejects(installUpdate(metadata(), () => {}), /unavailable in the browser/)
  const controlSource = await readFile(new URL('../src/features/update/UpdateControl.tsx', import.meta.url), 'utf8')
  const control = ts.transpileModule(controlSource, { compilerOptions: { module: ts.ModuleKind.ESNext, jsx: ts.JsxEmit.ReactJSX } }).outputText
    .replaceAll('react/jsx-runtime', import.meta.resolve('react/jsx-runtime'))
    .replace("from 'react'", `from '${import.meta.resolve('react')}'`)
    .replace('./desktopUpdater', serviceUrl)
  const sidebarSource = await readFile(new URL('../src/components/layout/Sidebar.tsx', import.meta.url), 'utf8')
  const sidebar = ts.transpileModule(sidebarSource, { compilerOptions: { module: ts.ModuleKind.ESNext, jsx: ts.JsxEmit.ReactJSX } }).outputText
    .replaceAll('react/jsx-runtime', import.meta.resolve('react/jsx-runtime'))
    .replace('../../api/client', new URL('../src/api/client.ts', import.meta.url).href)
    .replace('../../features/update/UpdateControl', `data:text/javascript;base64,${Buffer.from(control).toString('base64')}`)
  const { Sidebar } = await import(`data:text/javascript;base64,${Buffer.from(sidebar).toString('base64')}`)
  const { createElement } = await import('react')
  const { renderToStaticMarkup } = await import('react-dom/server')
  assert.doesNotMatch(renderToStaticMarkup(createElement(Sidebar, { view: 'report', onViewChange() {} })), /Desktop updates|Check for updates/)
})

test('desktop reads installed version and distinguishes no update from available without installing', async (context) => {
  desktop(context)
  let result = null
  const commands = []
  mockIPC((command) => { commands.push(command); return command === 'plugin:app|version' ? '0.2.0' : result })
  assert.equal(await installedVersion(), '0.2.0')
  assert.equal(await checkForUpdate(), null)
  result = metadata()
  const update = await checkForUpdate()
  assert.equal(update.version, '0.2.1')
  assert.equal(update.body, '<script>untrusted notes</script>')
  assert.ok(commands.every((command) => !command.includes('install')))
  await update.close()
})

test('network errors and invalid manifests fail closed and release invalid resources', async (context) => {
  desktop(context)
  mockIPC(() => { throw new Error('network failure') })
  await assert.rejects(checkForUpdate(), /network failure/)
  let closed = false
  mockIPC((command) => {
    if (command === 'plugin:resources|close') { closed = true; return }
    return metadata('https://example.com/unsigned.exe')
  })
  await assert.rejects(checkForUpdate(), /Invalid update/)
  assert.equal(closed, true)
  for (const url of [
    'http://github.com/chaziyu/firewall-migration-tool/releases/download/desktop-v0.2.1/test-setup.exe',
    'https://github.com/other/repo/releases/download/desktop-v0.2.1/test-setup.exe',
    'https://github.com/chaziyu/firewall-migration-tool/releases/download/desktop-v0.3.0/test-setup.exe',
  ]) assert.throws(() => validateUpdate(metadata(url)), /Invalid update/)
  const missingSignature = metadata()
  missingSignature.rawJson.platforms['windows-x86_64'].signature = ''
  assert.throws(() => validateUpdate(missingSignature), /Invalid update/)
})

test('explicit installation reports bounded progress, unknown totals and verification failure permits retry', async (context) => {
  desktop(context)
  const states = []
  let attempts = 0
  const update = { ...metadata(), async downloadAndInstall(callback, options) {
    assert.equal(options.restartAfterInstall, true)
    callback({ event: 'Started', data: { contentLength: 100 } })
    callback({ event: 'Progress', data: { chunkLength: 64 } })
    callback({ event: 'Progress', data: { chunkLength: 64 } })
    callback({ event: 'Finished' })
    if (++attempts === 1) throw new Error('signature verification failed')
  } }
  await assert.rejects(installUpdate(update, (state) => states.push(state)), /signature verification failed/)
  assert.ok(states.some((state) => state.percent === 64))
  assert.ok(states.some((state) => state.percent === 100))
  assert.equal(states.at(-1).kind, 'installing')
  await installUpdate(update, () => {})
  await installUpdate({ ...metadata(), async downloadAndInstall(callback) {
    callback({ event: 'Started', data: {} })
    callback({ event: 'Progress', data: { chunkLength: 1 } })
  } }, (state) => assert.equal(state.percent, undefined))
})
