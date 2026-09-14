/* Optional browser checks: requires playwright-core and a running local app.
 * Device ingestion and Terraform routes are always intercepted below.
 */
const { chromium } = require('playwright-core');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const baseURL = process.env.FWM_QA_URL || 'http://127.0.0.1:5077';
const output = process.env.FWM_QA_OUTPUT || fs.mkdtempSync(path.join(os.tmpdir(), 'fwm-frontend-'));
fs.mkdirSync(output, { recursive: true });
const fixture = path.resolve(__dirname, '../fixtures/fortigate/nat_analysis_synthetic.conf');
const file = { name: 'synthetic-source.conf', mimeType: 'text/plain', buffer: fs.readFileSync(fixture) };
const bundleFile = { name: 'synthetic-inventory.conf', mimeType: 'text/plain', buffer: Buffer.from(`config system global
    set hostname "frontend-test"
end
config firewall address
    edit "qa-server"
        set subnet 192.0.2.10 255.255.255.255
    next
end`) };
const results = [];

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || 'C:/Program Files/Google/Chrome/Application/chrome.exe', headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce', acceptDownloads: true });
    page.setDefaultTimeout(8000);
    const errors = [];
    const actions = [];
    page.on('pageerror', error => errors.push(error.message));
    let preview = 'real';
    let exportMode = 'real';
    let finishExport;
    await page.route('**/api/**', async route => {
      const pathname = new URL(route.request().url()).pathname;
      actions.push(pathname);
      if (pathname === '/api/preview') {
        if (preview === 'error') return route.fulfill({ status: 503, json: { success: false, error: 'Synthetic preview failure' } });
        if (preview === 'bounded') return route.fulfill({ json: {
          success: true, stats: { policies: 75, addresses: 2, address_groups: 3, services: 4, service_groups: 5 },
          optimization: { shadowed_rules_count: 2, unused_addresses_count: 1 },
          policies: Array.from({ length: 50 }, (_, index) => ({ index: index + 1, id: index === 0 ? '<img src=x onerror=alert(1)>' : `policy-${index}`, action: index % 2 ? 'deny' : 'allow', disabled: index === 2, from_zone: ['inside'], to_zone: ['outside'], source: ['192.0.2.1'], destination: ['198.51.100.1'], service: ['https'] }))
        } });
        return route.continue();
      }
      if (pathname === '/api/migrate') {
        if (exportMode === 'error') return route.fulfill({ status: 503, json: { error: 'Synthetic generation failure' } });
        if (exportMode === 'delayed') {
          await new Promise(resolve => { finishExport = resolve; });
          return route.fulfill({ status: 503, json: { error: 'Old source failure' } });
        }
        return route.continue();
      }
      if (['/api/extract/excel', '/api/vendors'].includes(pathname)) return route.continue();
      if (pathname === '/api/terraform/prepare') return route.fulfill({ json: { success: true, session_id: 'synthetic-plan' } });
      if (pathname === '/api/terraform/plan') return route.fulfill({ json: { success: true, summary: { add: 2, change: 1, destroy: 0 }, plan_log: 'Synthetic plan: 2 to add, 1 to change, 0 to destroy.' } });
      if (pathname === '/api/terraform/approve') return route.fulfill({ json: { success: true } });
      if (pathname === '/api/terraform/apply/stream') return route.fulfill({ contentType: 'text/event-stream', body: 'data: {"event":"complete","success":true,"message":"Synthetic apply complete"}\n\n' });
      return route.fulfill({ status: 403, json: { success: false, error: 'Device action blocked by browser test' } });
    });
    const check = async (name, fn) => {
      try { await fn(); results.push({ name, passed: true }); console.log('PASS', name); }
      catch (error) { results.push({ name, passed: false }); console.error('FAIL', name, error.message); }
    };
    const enabled = selector => page.waitForFunction(value => !document.querySelector(value).disabled, selector);
    const shown = selector => page.locator(selector).waitFor({ state: 'visible' });
    const upload = async (source = file) => { await page.locator('#file-input').setInputFiles(source); await enabled('#btn-generate-bundle'); };
    await page.goto(baseURL);

    await check('empty state, keyboard navigation, and guide focus', async () => {
      assert(await page.locator('#btn-generate-bundle').isDisabled());
      assert(await page.locator('#btn-apply-live').isDisabled());
      assert.equal(await page.locator('#workflow-step-source').getAttribute('aria-current'), 'step');
      await page.locator('#tab-download').focus();
      await page.keyboard.press('ArrowDown');
      assert.equal(await page.locator('#tab-extract').getAttribute('aria-selected'), 'true');
      await page.keyboard.press('Home');
      await page.locator('#btn-open-guide').click();
      await page.keyboard.press('Tab');
      assert(await page.locator('#guide-modal').evaluate(element => element.contains(document.activeElement)));
      await page.keyboard.press('Escape');
      assert(await page.locator('#btn-open-guide').evaluate(element => element === document.activeElement));
    });
    await check('real source inventory, policy search, and disabled filter', async () => {
      await upload();
      assert.equal(await page.locator('#stat-total-rules').innerText(), '12');
      await page.locator('#policy-review summary').click();
      await page.locator('#policy-search').fill('Finance_Internet');
      assert.equal(await page.locator('#policy-table-body tr').count(), 1);
      await page.locator('#policy-search').fill('');
      await page.locator('#policy-filter').selectOption('disabled');
      assert.equal(await page.locator('#policy-table-body tr').count(), 2);
      await page.locator('#policy-filter').selectOption('all');
      await page.evaluate(() => { document.activeElement.blur(); window.scrollTo(0, 0); });
      await page.screenshot({ path: path.join(output, 'source-review-desktop.png'), fullPage: true });
    });
    await check('real bundle and Excel downloads with persistent results', async () => {
      // This fixture has NAT constructs that the backend requires users to review.
      await page.locator('#btn-generate-bundle').click();
      await page.waitForFunction(() => document.querySelector('#bundle-result').dataset.state === 'error');
      assert((await page.locator('#bundle-result').innerText()).includes('target-specific validation'));
      await enabled('#btn-generate-bundle');
      await upload(bundleFile);
      const zipEvent = page.waitForEvent('download');
      await page.locator('#btn-generate-bundle').click();
      const zip = await zipEvent;
      assert.equal(await zip.failure(), null);
      assert.equal(zip.suggestedFilename(), 'migration_fortigate_to_palo_alto.zip');
      await shown('#bundle-result');
      assert.equal(await page.locator('#bundle-result').getAttribute('data-state'), 'success');
      assert(await page.locator('#workflow-step-export').evaluate(element => element.classList.contains('complete')));
      await page.locator('#tab-extract').click();
      assert(!await page.locator('#optimizer-controls').isVisible());
      const excelEvent = page.waitForEvent('download');
      await page.locator('#btn-extract-excel').click();
      const excel = await excelEvent;
      assert.equal(await excel.failure(), null);
      assert(excel.suggestedFilename().endsWith('.xlsx'));
      await shown('#excel-result');
      assert.equal(await page.locator('#excel-result').getAttribute('data-state'), 'success');
      await page.locator('#tab-download').click();
      assert.equal(await page.locator('#bundle-result').getAttribute('data-state'), 'success');
      await page.locator('#opt-prune-objects').uncheck();
      assert(!await page.locator('#bundle-result').isVisible());
    });
    await check('export failures stay beside the action; stale results are discarded', async () => {
      exportMode = 'error';
      await page.locator('#btn-generate-bundle').click();
      await page.waitForFunction(() => document.querySelector('#bundle-result').dataset.state === 'error');
      assert((await page.locator('#bundle-result').innerText()).includes('Synthetic generation failure'));
      await enabled('#btn-generate-bundle');
      exportMode = 'delayed';
      await page.locator('#btn-generate-bundle').click();
      await page.waitForFunction(() => document.querySelector('#bundle-result').dataset.state === 'loading');
      await page.locator('#source-vendor-select').selectOption('palo_alto');
      finishExport();
      await page.waitForFunction(() => document.querySelector('#btn-generate-bundle').getAttribute('aria-busy') === 'false');
      assert(!await page.locator('#bundle-result').isVisible());
      assert(await page.locator('#btn-generate-bundle').isDisabled());
      exportMode = 'real';
      await page.locator('#source-vendor-select').selectOption('fortigate');
    });
    await check('failed preview retries the same source', async () => {
      preview = 'error';
      await page.locator('#file-input').setInputFiles(file);
      await shown('#btn-retry-preview');
      assert(await page.locator('#btn-generate-bundle').isDisabled());
      preview = 'real';
      await page.locator('#btn-retry-preview').click();
      await enabled('#btn-generate-bundle');
      assert(!await page.locator('#btn-retry-preview').isVisible());
      assert.equal(await page.locator('#selected-filename').innerText(), file.name);
    });
    await check('bounded preview, correct group count, safe text, and no-match state', async () => {
      preview = 'bounded';
      await upload();
      assert.equal(await page.locator('#stat-total-objects').innerText(), '14');
      assert((await page.locator('#review-findings').innerText()).includes('2 potentially shadowed rules'));
      await page.locator('#policy-review summary').click();
      assert((await page.locator('#policy-preview-scope').innerText()).includes('50 of 75'));
      assert.equal(await page.locator('#policy-table-body tr').count(), 50);
      assert.equal(await page.locator('#policy-table-body img').count(), 0);
      await page.locator('#policy-filter').selectOption('deny');
      assert.equal(await page.locator('#policy-table-body tr').count(), 25);
      await page.locator('#policy-search').fill('not-a-policy');
      await shown('#policy-empty');
      await page.locator('#policy-search').fill('');
      await page.locator('#policy-filter').selectOption('all');
    });
    await check('light and dark layouts at desktop, tablet, and mobile widths', async () => {
      for (const theme of ['light', 'dark']) {
        await page.emulateMedia({ colorScheme: theme });
        for (const width of [1440, 1024, 768, 390, 320]) {
          await page.setViewportSize({ width, height: 900 });
          for (const tab of ['download', 'extract', 'live']) {
            await page.locator(`#tab-${tab}`).click();
            const size = await page.evaluate(() => ({ viewport: innerWidth, actual: document.documentElement.scrollWidth }));
            assert(size.actual <= size.viewport, `${theme} ${tab}: ${JSON.stringify(size)}`);
            assert.equal(await page.locator('.mode-tabs').getAttribute('aria-orientation'), width <= 760 ? 'horizontal' : 'vertical');
          }
          await page.locator('#tab-download').click();
          if ([1440, 390, 320].includes(width)) await page.screenshot({ path: path.join(output, `${theme}-${width}.png`), fullPage: true });
        }
      }
      await page.setViewportSize({ width: 1440, height: 1000 });
    });
    await check('unsupported live adapters explain file-upload alternative', async () => {
      await page.locator('#btn-ingest-api').click();
      for (const vendor of ['cisco_asa', 'checkpoint', 'juniper_srx']) {
        await page.locator('#source-vendor-select').selectOption(vendor);
        assert((await page.locator('#source-api-note').innerText()).includes('not implemented'));
        assert.equal(await page.locator('#api-host').count(), 0);
        assert(await page.locator('#btn-api-extract').isDisabled());
      }
      await page.locator('#source-vendor-select').selectOption('fortigate');
      await shown('#api-host');
      await page.locator('#btn-ingest-file').click();
    });
    await check('mocked deployment retains plan, confirmation, and approval order', async () => {
      preview = 'real';
      await upload();
      await page.locator('#tab-live').click();
      assert(!await page.locator('#optimizer-controls').isVisible());
      assert(await page.locator('#target-vendor-select').isDisabled());
      assert(await page.locator('#btn-apply-live').isDisabled());
      await page.locator('#pan-host').fill('192.0.2.2');
      await page.locator('#pan-apikey').fill('synthetic-key');
      await page.locator('#btn-plan-dryrun').click();
      await enabled('#btn-apply-live');
      assert((await page.locator('#plan-status-msg').innerText()).includes('Review the execution log'));
      page.once('dialog', dialog => dialog.dismiss());
      await page.locator('#btn-apply-live').click();
      assert(!actions.includes('/api/terraform/approve'));
      page.once('dialog', dialog => dialog.accept());
      await page.locator('#btn-apply-live').click();
      await shown('#post-actions-bar');
      assert(actions.indexOf('/api/terraform/approve') < actions.indexOf('/api/terraform/apply/stream'));
      await page.locator('#pan-host').fill('192.0.2.3');
      assert(await page.locator('#btn-apply-live').isDisabled());
    });
    await check('no uncaught browser errors', async () => assert.deepEqual(errors, []));
  } finally { await browser.close(); }
  console.log(JSON.stringify({ results, output }, null, 2));
  process.exitCode = results.some(result => !result.passed) ? 1 : 0;
})().catch(error => { console.error(error); process.exitCode = 1; });
