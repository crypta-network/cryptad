/* Fixed installed browser collector. The administrator selects and binds its namespace/provider. */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { createHash } = require('node:crypto');
const LIMIT = 2 * 1024 * 1024;
const inputBytes = fs.readFileSync(0);
if (inputBytes.length > LIMIT) process.exit(2);
function need(condition) { if (!condition) throw new Error('privacy-browser-invalid'); }
async function run() {
  const { chromium } = require('/opt/cryptad-privacy-browser/lib/node_modules/playwright');
  const input = JSON.parse(inputBytes);
  need(Object.keys(input).sort().join(',') === 'appOrigin,appSession,base,nativeMemberDigest,stimuli');
  need(input.base === 'http://127.0.0.1:19402');
  const app = new URL(input.appOrigin);
  need(app.protocol === 'http:' && app.hostname === '127.0.0.1' && app.port
    && app.pathname === '/' && !app.username && !app.password && !app.search && !app.hash);
  need(typeof input.appSession === 'string' && input.appSession.length >= 16 && input.appSession.length <= 4096);
  need(/^sha256:[0-9a-f]{64}$/.test(input.nativeMemberDigest));
  need(Array.isArray(input.stimuli) && input.stimuli.length > 0 && input.stimuli.length <= 64
    && input.stimuli.every(marker => typeof marker === 'string' && marker.length >= 8 && marker.length <= 8192));
  const browser = await chromium.launch({ headless: true, executablePath: '/opt/cryptad-privacy-browser/bin/chromium' });
  const context = await browser.newContext({ acceptDownloads: true });
  const requests = [];
  const failedExports = [];
  const browserDenials = [];
  let scriptBytes = null;
  try {
    await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: input.base });
    let invalidNetwork = false;
    await context.route('**/*', route => {
      const url = new URL(route.request().url());
      if (![input.base, app.origin].includes(url.origin)) {
        invalidNetwork = true;
        return route.abort();
      }
      return route.continue();
    });
    context.on('request', request => {
      const url = new URL(request.url());
      if (![input.base, app.origin].includes(url.origin) || requests.length >= 256) {
        invalidNetwork = true;
        return;
      }
      requests.push({ origin: url.origin, path: url.pathname, method: request.method() });
    });
    const page = await context.newPage();
    const pageErrors = [];
    page.on('pageerror', () => pageErrors.push('page-error'));
    const script = page.waitForResponse(response => new URL(response.url()).pathname === '/app/node/static/web-shell.js');
    await page.goto(input.base + '/app/node/', { waitUntil: 'domcontentloaded', timeout: 15000 });
    scriptBytes = await (await script).body();
    const generate = page.locator('#support-bundle-refresh-button');
    const copy = page.locator('#support-bundle-copy-button');
    const download = page.locator('#support-bundle-download-button');
    const originalResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/operator/support-bundle');
    await generate.click();
    const response = await originalResponse;
    need(response.status() === 200);
    const browserBundleText = (await response.body()).toString('utf8');
    need(Buffer.byteLength(browserBundleText) <= LIMIT);
    const bundle = JSON.parse(browserBundleText);
    await page.waitForFunction(() => !document.getElementById('support-bundle-copy-button').disabled, null, { timeout: 10000 });
    await copy.click();
    const clipboardText = await page.evaluate(() => navigator.clipboard.readText());
    const transferred = page.waitForEvent('download');
    await download.click();
    const received = await transferred;
    const stream = await received.createReadStream();
    let size = 0;
    const chunks = [];
    for await (const chunk of stream) {
      size += chunk.length;
      need(size <= LIMIT);
      chunks.push(chunk);
    }
    const downloadText = Buffer.concat(chunks).toString('utf8');
    need(downloadText === clipboardText);
    assert.deepEqual(JSON.parse(clipboardText), bundle);
    const downloadName = received.suggestedFilename();
    need(/^cryptad-support-bundle-[a-zA-Z0-9-]+\.json$/.test(downloadName));
    // These are explicit browser-response negative fixtures, not fabricated server faults.
    for (const variant of ['failed', 'malformed', 'digest', 'redaction']) {
      await context.route(input.base + '/api/v1/operator/support-bundle', route => {
        let negative = structuredClone(bundle);
        if (variant === 'malformed') negative = { redaction: { status: 'pass' } };
        if (variant === 'digest') negative.supportDigest.digest = 'f'.repeat(64);
        if (variant === 'redaction') negative.redaction.status = 'fail';
        return route.fulfill({ status: variant === 'failed' ? 503 : 200, contentType: 'application/json',
          body: variant === 'failed' ? '{"error":{"message":"collector-negative-control"}}' : JSON.stringify(negative) });
      });
      await generate.click();
      await page.waitForFunction(() => document.getElementById('beta-dashboard-status').textContent.includes('could not be verified'));
      const row = { variant, copyDisabled: await copy.isDisabled(), downloadDisabled: await download.isDisabled(),
        statusText: await page.locator('#beta-dashboard-status').innerText(), domText: await page.locator('body').innerText() };
      need(row.copyDisabled && row.downloadDisabled);
      failedExports.push(row);
      await context.unroute(input.base + '/api/v1/operator/support-bundle');
      await generate.click();
      await page.waitForFunction(() => !document.getElementById('support-bundle-copy-button').disabled);
    }
    const domText = await page.locator('body').innerText();
    const persistence = await page.evaluate(async () => ({ local: Object.entries(localStorage),
      session: Object.entries(sessionStorage), databases: await indexedDB.databases() }));
    assert.deepEqual(persistence, { local: [], session: [], databases: [] });
    const appPage = await context.newPage();
    await appPage.goto(app.origin + '/', { waitUntil: 'domcontentloaded', timeout: 15000 });
    for (const route of ['operator/runtime-observation', 'operator/network-budgets', 'operator/support-bundle', 'operator/beta-dashboard']) {
      const observed = appPage.waitForResponse(response => response.url() === input.base + '/api/v1/' + route);
      const request = appPage.evaluate(async ({ endpoint, session }) => {
        try { await fetch(endpoint, { headers: { 'X-Crypta-App-Session': session } }); }
        catch (_) { /* Original response is retained by the private transport observer. */ }
      }, { endpoint: input.base + '/api/v1/' + route, session: input.appSession });
      const denial = await observed;
      await request;
      need([401, 403].includes(denial.status()));
      browserDenials.push({ route, status: denial.status(), body: (await denial.body()).toString('utf8') });
    }
    const appPersistence = await appPage.evaluate(async () => ({ local: Object.entries(localStorage),
      session: Object.entries(sessionStorage), databases: await indexedDB.databases() }));
    assert.deepEqual(appPersistence, { local: [], session: [], databases: [] });
    need(pageErrors.length === 0 && !invalidNetwork);
    const result = { schemaVersion: 1, kind: 'composed-budget-installed-browser-component',
      transport: 'selected-role-namespace-http', nativeMemberDigest: input.nativeMemberDigest,
      scriptDigest: 'sha256:' + createHash('sha256').update(scriptBytes).digest('hex'),
      browserBundleText, clipboardText, downloadText, downloadName, domText, persistence,
      appPersistence, failedExports, browserDenials, requests,
      faultEvidenceClass: 'browser-response-negative-fixture' };
    const raw = JSON.stringify(result);
    for (const marker of [...input.stimuli, input.appSession]) need(!raw.includes(marker));
    need(Buffer.byteLength(raw) <= LIMIT);
    process.stdout.write(raw);
  } finally {
    await context.close();
    await browser.close();
  }
}
run().catch(() => { process.stderr.write('installed-privacy-browser-failed\n'); process.exitCode = 2; });
