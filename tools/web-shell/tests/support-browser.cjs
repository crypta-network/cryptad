/* Actual Web Shell DOM and export behavior; intercepted HTTP is explicitly local test transport. */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { createHash } = require('node:crypto');
const { chromium } = require('playwright');
const root = path.resolve(__dirname, '../../..');
const staticRoot = path.join(root, 'platform-web-shell/src/main/resources/network/crypta/platform/webshell/static');
const nativePath = path.join(root, 'platform-api/build/test-results/pr320-native/privacy.json');
const fixture = process.argv.includes('--fixture');
const recovery = process.argv.includes('--recovery');
const insecure = process.argv.includes('--insecure-http');
const scriptBytes = fs.readFileSync(path.join(staticRoot, 'web-shell.js'));
const nativeBytes = fixture ? null : fs.readFileSync(nativePath);
let artifact;
if (!fixture) artifact = JSON.parse(nativeBytes);
const nativeBundle = artifact ? JSON.parse(artifact.surfaces.supportBundle) : {
  kind: 'cryptad-operator-support-bundle', schemaVersion: 2, generatedAtEpochMillis: 1,
  sections: { trustGraph: { status: 'pass', count: 1 } }, dashboard: { trustGraph: { retainedStatements: 1 } },
  diagnostics: { sectionCount: 1 }, redaction: {
    status: 'pass', rawSensitiveMaterialExcluded: true, redactionFindings: [], omittedFields: [], omittedFieldCount: 0,
  },
};
if (fixture && process.argv.includes('--unicode')) nativeBundle.diagnostics.details = 'café 漢字 🐢' + 'x'.repeat(137);
let bundleWire = artifact ? artifact.surfaces.supportBundle : JSON.stringify(nativeBundle);
if (!artifact) {
  if (process.argv.includes('--numbers')) bundleWire = bundleWire.replace('\"sectionCount\":1', '\"sectionCount\":1,\"fraction\":1.0,\"largeInteger\":9007199254740993');
  nativeBundle.supportDigest = { algorithm: 'SHA-256', digest: createHash('sha256').update(bundleWire).digest('hex') };
  bundleWire = bundleWire.slice(0, -1) + ',\"supportDigest\":' + JSON.stringify(nativeBundle.supportDigest) + '}';
}
const origin = insecure ? 'http://192.0.2.10' : 'http://localhost';
const privateDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'cryptad-support-browser-'));
(async () => {
  const browser = process.env.PW_TEST_CONNECT_WS_ENDPOINT
    ? await chromium.connect(process.env.PW_TEST_CONNECT_WS_ENDPOINT) : await chromium.launch({ headless: true });
  const context = await browser.newContext({ acceptDownloads: true });
  const requests = [];
  let state = 'valid';
  const failedExports = [];
  let clipboardText = '';
  let downloadText = '';
  let downloadName = '';
  let persistence = null;
  let domText = '';
  try {
    if (!insecure) await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin });
    await context.route('**/*', async route => {
      const url = new URL(route.request().url());
      requests.push({ origin: url.origin, path: url.pathname, method: route.request().method() });
      assert.equal(url.origin, origin, 'unexpected external request');
      if (url.pathname === '/app/node/') {
        const html = fs.readFileSync(path.join(staticRoot, 'index.html'), 'utf8').replace('__BOOTSTRAP_JSON__', JSON.stringify({ platformApiRoot: '/api/v1/', shellRoot: '/app/node/', formPassword: recovery ? 'synthetic-local-form-password' : '' }));
        return route.fulfill({ status: 200, contentType: 'text/html', body: html });
      }
      if (url.pathname.startsWith('/app/node/static/')) {
        const name = path.basename(url.pathname);
        assert(['web-shell.js', 'web-shell.css'].includes(name), 'unexpected static member');
        return route.fulfill({ status: 200, contentType: name.endsWith('.js') ? 'text/javascript' : 'text/css', body: name === 'web-shell.js' ? scriptBytes : fs.readFileSync(path.join(staticRoot, name)) });
      }
      if (recovery && url.pathname === '/api/v1/operator/rc-dashboard') {
        return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
          operatorRcRecovery: { status: 'available', actions: { support: [{ actionId: 'support-bundle.export', description: 'Local support export', targetFields: [] }] } },
        }) });
      }
      if (recovery && url.pathname === '/api/v1/operator/recovery/plan') {
        return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ plan: {
          actionId: 'support-bundle.export', status: 'ready', planToken: 'synthetic-local-plan-token',
        } }) });
      }
      if (recovery && url.pathname === '/api/v1/operator/recovery/execute') {
        const actual = state === 'digest' ? bundleWire.replace(nativeBundle.supportDigest.digest, 'f'.repeat(64)) : bundleWire;
        return route.fulfill({ status: 200, contentType: 'application/json', body:
          '{"result":{"actionId":"support-bundle.export","status":"completed","details":{"supportBundle":' + actual + '}}}' });
      }
      if (url.pathname === '/api/v1/operator/support-bundle') {
        if (state === 'failed') return route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: { message: '/private/not-for-dom token=not-for-dom' } }) });
        let bundle = JSON.parse(bundleWire);
        if (state === 'malformed') bundle = { redaction: { status: 'pass' } };
        if (state === 'digest') bundle.supportDigest.digest = 'f'.repeat(64);
        if (state === 'redaction') bundle.redaction.status = 'fail';
        return route.fulfill({ status: 200, contentType: 'application/json', body: state === 'valid' ? bundleWire : JSON.stringify(bundle) });
      }
      if (url.pathname === '/api/v1/operator/support-bundle/preview') {
        return route.fulfill({ status: 200, contentType: 'application/json', body: artifact ? artifact.surfaces.supportPreview : JSON.stringify({ status: 'pass' }) });
      }
      return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
    });
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(origin + '/app/node/');
    assert.equal(await page.evaluate(() => window.isSecureContext), !insecure);
    assert.equal(await page.evaluate(() => typeof window.crypto?.subtle), insecure ? 'undefined' : 'object');
    const generate = page.locator('#support-bundle-refresh-button');
    const copy = page.locator('#support-bundle-copy-button');
    const download = page.locator('#support-bundle-download-button');
    await generate.click();
    await page.waitForFunction(() => !document.getElementById('support-bundle-copy-button').disabled);
    let copied = bundleWire.trim() + '\n';
    if (!insecure) {
      await copy.click();
      copied = await page.evaluate(() => navigator.clipboard.readText());
      clipboardText = copied;
    }
    assert.deepEqual(JSON.parse(copied), JSON.parse(bundleWire));
    assert.equal(copied, bundleWire.trim() + '\n', 'export changed original wire number or string representation');
    const transferred = page.waitForEvent('download');
    await download.click();
    const file = await transferred;
    assert.match(file.suggestedFilename(), /^cryptad-support-bundle-[a-zA-Z0-9-]+\.json$/);
    const retained = path.join(privateDirectory, 'download.json');
    await file.saveAs(retained);
    downloadText = fs.readFileSync(retained, 'utf8');
    downloadName = file.suggestedFilename();
    assert.equal(downloadText, copied, 'download and copy exact bytes differ');
    for (const failure of ['failed', 'malformed', 'digest', 'redaction']) {
      state = failure;
      await generate.click();
      await page.waitForFunction(() => document.getElementById('beta-dashboard-status').textContent.includes('could not be verified'));
      assert(await copy.isDisabled());
      assert(await download.isDisabled());
      const failureDom = await page.locator('body').innerText();
      assert.equal(failureDom.includes('not-for-dom'), false);
      failedExports.push({ variant: failure, copyDisabled: await copy.isDisabled(),
        downloadDisabled: await download.isDisabled(), statusText: await page.locator('#beta-dashboard-status').innerText(), domText: failureDom });
      // Restore a valid cached bundle before each fault so every case tests invalidation.
      state = 'valid';
      await generate.click();
      await page.waitForFunction(() => !document.getElementById('support-bundle-copy-button').disabled);
    }
    if (recovery) {
      const form = page.locator('form[data-operator-rc-recovery-action-id="support-bundle.export"]');
      await form.locator('[data-operator-rc-recovery-submit="plan"]').click();
      await page.waitForFunction(() => document.querySelector('form[data-operator-rc-recovery-action-id="support-bundle.export"]').dataset.operatorRcRecoveryPlanned === 'true');
      const transfer = page.waitForEvent('download');
      await form.locator('[data-operator-rc-recovery-submit="execute"]').click();
      await form.getByRole('button', { name: 'Download support bundle', exact: true }).click();
      const result = await transfer;
      const saved = path.join(privateDirectory, 'recovery.json');
      await result.saveAs(saved);
      assert.equal(fs.readFileSync(saved, 'utf8'), bundleWire.trim() + '\n', 'recovery export changed wire bytes');
      state = 'digest';
      await form.locator('[data-operator-rc-recovery-submit="plan"]').click();
      await page.waitForFunction(() => document.querySelector('form[data-operator-rc-recovery-action-id="support-bundle.export"]').dataset.operatorRcRecoveryPlanned === 'true');
      await form.locator('[data-operator-rc-recovery-submit="execute"]').click();
      await page.waitForFunction(() => document.getElementById('beta-dashboard-status').textContent.includes('export is disabled'));
      assert.equal(await form.getByRole('button', { name: 'Download support bundle', exact: true }).count(), 0);
      assert.equal((await form.innerText()).includes('not-for-dom'), false);
      state = 'valid';
    }
    persistence = await page.evaluate(async () => ({
      local: Object.entries(localStorage), session: Object.entries(sessionStorage), databases: await indexedDB.databases(),
    }));
    assert.deepEqual(persistence, { local: [], session: [], databases: [] });
    domText = await page.locator('body').innerText();
    if (artifact) for (const stimulus of artifact.stimuli) {
      assert.equal(copied.includes(stimulus.marker), false, 'private stimulus in export');
      assert.equal((await page.locator('body').innerText()).includes(stimulus.marker), false, 'private stimulus in DOM');
    }
    assert.deepEqual(errors, []);
    assert(requests.some(request => request.path === '/api/v1/operator/support-bundle/preview'));
    assert(requests.some(request => request.path === '/api/v1/operator/support-bundle'));
    const retainedRoot = path.join(root, 'build/pr320-browser-private');
    fs.mkdirSync(retainedRoot, { recursive: true, mode: 0o700 });
    const attempt = fs.mkdtempSync(path.join(retainedRoot, 'attempt-'));
    fs.writeFileSync(path.join(attempt, 'browser.json'), JSON.stringify({ schemaVersion: 1,
      kind: 'composed-budget-browser-component', transport: 'intercepted-local-http',
      nativeMemberDigest: artifact ? 'sha256:' + createHash('sha256').update(nativeBytes).digest('hex') : null,
      scriptDigest: 'sha256:' + createHash('sha256').update(scriptBytes).digest('hex'),
      clipboardText, downloadText, downloadName, domText, persistence, failedExports, requests }), { mode: 0o600 });
    console.log(JSON.stringify({ browser: 'chromium', transport: 'intercepted-local-http', nativeSupport: !!artifact, recoveryExportChecked: recovery,
      secureContext: !insecure, clipboardChecked: !insecure,
      copyDownloadBytesMatched: !insecure, downloadWireBytesMatched: true,
      malformedDigestAndFailedRefreshBlocked: true, persistence: 'empty',
      installedObservation: false, protectedAuthority: false }));
  } finally {
    await context.close();
    await browser.close();
    fs.rmSync(privateDirectory, { recursive: true, force: true });
  }
})().catch(error => { fs.mkdirSync(path.join(root, 'build/pr320-browser-private'), { recursive: true, mode: 0o700 }); fs.writeFileSync(path.join(root, 'build/pr320-browser-private/failure.txt'), String(error.stack), { mode: 0o600 }); console.error('web-shell-support-browser-failed'); process.exitCode = 1; });
