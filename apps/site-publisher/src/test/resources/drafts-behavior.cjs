const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { webcrypto, createHash } = require('node:crypto');
const source = fs.readFileSync(process.argv[2], 'utf8');
const hash = (value) => createHash('sha256').update(value).digest('hex');
const context = { TextEncoder, TextDecoder, Uint8Array, atob, btoa,
  window: { crypto: webcrypto }, document: { addEventListener() {} } };
vm.createContext(context);
vm.runInContext(source, context);
const drafts = context.window.SitePublisherDrafts;
const operationId = '11111111-1111-4111-8111-111111111111';
const literal = '<script>alert("inert")</script>\r\n雪\nhttps://example.invalid/';
const draft = { id: `${operationId}-3`, operationId, sourceId: 3, name: 'Private title',
  description: '', text: literal, historicalEdition: 4, logicalPath: '../../metadata-only' };
const dataset = { schemaVersion: 1, operations: [], drafts: [draft] };
const wrapper = { format: 'crypta.sharesite-migration.v1', privacy: 'private-user-data',
  source: { repository: 'hyphanet/plugin-sharesite', revision: 'c99ad9c8e83004f904f8ee742ab2861f5751ee3b',
    profile: 'sharesite-pastebin-v1', literalTextSha256: { '3': hash(literal) }, snapshotSha256: 'b'.repeat(64), provenance: 'stopped synthetic snapshot' },
  operationId, selectedIds: [3], exclusions: { unsupported_textile: 1, prohibited_or_invalid_key: 1 },
  payload: { exportVersion: 1, appId: 'site-publisher', exportedAt: '1970-01-01T00:00:00Z', namespaceCount: 1, recordCount: 1,
    namespaces: [{ appId: 'site-publisher', namespace: 'sharesite-drafts', schemaVersion: 1, recordCount: 1,
      totalBytes: Buffer.byteLength(JSON.stringify(dataset)), createdAt: '1970-01-01T00:00:00Z', updatedAt: '1970-01-01T00:00:00Z', lastMigrationAt: null, migrationHistory: [] }],
    records: [{ namespace: 'sharesite-drafts', key: 'dataset', schemaVersion: 1, contentType: 'application/json',
      valueBytes: Buffer.byteLength(JSON.stringify(dataset)), sha256: hash(JSON.stringify(dataset)),
      createdAt: '1970-01-01T00:00:00Z', updatedAt: '1970-01-01T00:00:00Z',
      valueBase64: Buffer.from(JSON.stringify(dataset)).toString('base64') }] } };
const bytes = (value) => new TextEncoder().encode(JSON.stringify(value));
function backend() {
  let value = null;
  let pending;
  let failCommit = false;
  let guard = 1;
  let writes = 0;
  let publications = [];
  const api = { data: { status: async () => ({ sharesiteWriteGuard: guard }), records: {
    get: async () => { if (value === null) throw { code: 'app_data_record_not_found' };
      return { valueText: value, sha256: hash(value) }; },
    put: async (request) => {
      writes++;
      assert.equal(request.namespace, 'sharesite-drafts');
      assert.equal(request.key, 'dataset');
      assert.equal(request.backupReady, 'true');
      assert.equal(request.ifMatchSha256, value === null ? 'absent' : hash(value));
      if (request.writeIntent === 'preview') {
        pending = JSON.parse(JSON.stringify(request));
        return { previewId: 'opaque-preview', currentSha256: request.ifMatchSha256,
          proposedSha256: hash(request.valueJson), targetBinding: { baseline: '1.0' } };
      }
      assert.equal(request.writeIntent, 'commit');
      assert.equal(request.valueJson, pending.valueJson);
      assert.equal(request.writePreviewId, 'opaque-preview');
      pending = null;
      if (failCommit) throw { code: 'app_data_store_unavailable' };
      value = request.valueJson;
      return { sha256: hash(value) };
    } } }, content: { insertPlainText: async (request) => { publications.push(request); return {}; } } };
  return { api, value: () => value, writes: () => writes, publications,
    fail: (value) => { failCommit = value; }, guard: (value) => { guard = value; },
    mutate: (change) => { const next = JSON.parse(value); change(next); value = JSON.stringify(next); } };
}
(async () => {
  const converted = await drafts.parsePackage(bytes(wrapper));
  assert.equal(converted.dataset.drafts[0].text, literal);
  assert.equal(converted.dataset.drafts[0].logicalPath, '../../metadata-only');
  const store = backend();
  let model = drafts.controller(store.api);
  await model.load();
  await model.previewImport(converted);
  assert.equal(store.value(), null, 'preview is nonmutating');
  store.fail(true);
  await assert.rejects(() => model.commit());
  assert.equal(store.value(), null, 'interruption keeps old dataset');
  store.fail(false);
  await model.load();
  await model.previewImport(converted);
  await model.commit();
  assert.equal(store.publications.length, 0, 'import does not publish');
  model = drafts.controller(store.api);
  await model.load();
  assert.equal(model.snapshot().drafts[0].text, literal, 'restart preserves literal text');
  const beforeReplay = store.writes();
  assert.equal((await model.previewImport(converted)).replay, true);
  assert.equal(store.writes(), beforeReplay, 'exact replay never writes');
  await assert.rejects(() => model.previewImport({ ...converted, payloadSha256: 'c'.repeat(64) }));
  const privateBackup = model.backup();
  assert.equal(JSON.parse(privateBackup).privacy, 'private-user-data');
  assert.equal(JSON.parse(privateBackup).encryption.mode, 'none');
  await model.previewEdit(draft.id, '<img src=x onerror=alert(1)>');
  await model.commit();
  assert.equal(store.publications.length, 0, 'save does not publish');
  await assert.rejects(() => model.previewUndo(operationId), /manual_recovery/);
  await assert.rejects(() => model.previewRestore(new TextEncoder().encode(privateBackup)), /collision/);
  await model.publish(draft.id);
  assert.equal(store.publications.length, 1);
  assert.equal(store.publications[0].text, '<img src=x onerror=alert(1)>');
  await model.previewEdit(draft.id, literal);
  await model.commit();
  await model.previewUndo(operationId);
  await model.commit();
  assert.equal(model.snapshot().drafts.length, 0);
  assert.equal(model.snapshot().operations[0].status, 'undone');
  const cleanStore = backend();
  const restored = drafts.controller(cleanStore.api);
  await restored.load();
  await restored.previewRestore(new TextEncoder().encode(privateBackup));
  await restored.commit();
  assert.equal(restored.snapshot().drafts[0].text, literal);
  await restored.previewEdit(draft.id, 'stale');
  cleanStore.mutate((next) => { next.drafts[0].text = 'concurrent edit'; });
  await assert.rejects(() => restored.commit());
  assert.equal(JSON.parse(cleanStore.value()).drafts[0].text, 'concurrent edit');
  const old = backend(); old.guard(undefined);
  const unsupported = drafts.controller(old.api);
  await assert.rejects(() => unsupported.load(), /guarded_daemon_required/);
  await assert.rejects(() => unsupported.previewImport(converted), /guarded_daemon_required/);
  assert.equal(old.writes(), 0, 'unknown preview params never reach an old daemon');
  for (const mutate of [
    (value) => { value.payload.appId = 'feed-reader'; },
    (value) => { value.source.revision = '0'.repeat(40); },
    (value) => { value.selectedIds = [3, 3]; },
    (value) => { value.insertSSK = 'private-canary'; },
    (value) => { value.payload.records[0].namespace = 'other'; },
    (value) => { value.payload.records[0].schemaVersion = 2; },
    (value) => { value.payload.arbitrary = 'private-canary'; },
    (value) => { value.payload.records[0].arbitrary = 'private-canary'; },
    (value) => { value.payload.namespaces[0].arbitrary = 'private-canary'; },
    (value) => { value.exclusions.arbitrary = 'private-canary'; },
    (value) => { value.source.provenance = 'password=private-canary'; },
    (value) => { value.payload.namespaces[0].migrationHistory = [{ summary: 'private-canary' }]; }
  ]) {
    const invalid = structuredClone(wrapper); mutate(invalid);
    await assert.rejects(() => drafts.parsePackage(bytes(invalid)));
  }
  drafts.validateDataset({ ...dataset, drafts: [{ ...draft, description: 'a'.repeat(8192) }] });
  assert.throws(() => drafts.validateDataset({ ...dataset, drafts: [{ ...draft, description: '雪'.repeat(5462) }] }));
  assert.throws(() => drafts.validateDataset({ ...dataset, drafts: [{ ...draft, text: 'token=secret-canary' }] }));
  assert.throws(() => drafts.validateDataset({ ...dataset, drafts: [{ ...draft, text: 'Authorization: Bearer private-canary' }] }));
  assert.throws(() => drafts.validateDataset({ ...dataset, drafts: [{ ...draft, text: 'SSK@a,b,AQECAAE/site' }] }));
  assert.throws(() => drafts.validateDataset({ ...dataset, drafts: [{ ...draft, text: 'private_key: canary' }] }));
  assert.throws(() => drafts.validateDataset({ ...dataset, drafts: [{ ...draft, text: '雪'.repeat(21846) }] }));
  class Element {
    constructor() { this.listeners = {}; this.children = []; this.value = ''; this.textContent = '';
      this.checked = false; this.disabled = false; this.files = []; }
    addEventListener(name, callback) { this.listeners[name] = callback; }
    append(child) { this.children.push(child); }
    replaceChildren(...children) { this.children = children; }
    set innerHTML(_) { throw new Error('Unsafe markup rendering attempted'); }
  }
  const elements = new Map();
  const element = (id) => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
  let start;
  const uiStore = backend();
  const initial = drafts.controller(uiStore.api);
  await initial.load(); await initial.previewImport(converted); await initial.commit();
  uiStore.api.bootstrap = { load: async () => {} };
  const uiContext = { TextEncoder, TextDecoder, Uint8Array, atob, btoa, Blob, URL,
    CryptaPlatform: uiStore.api, window: { crypto: webcrypto },
    document: { addEventListener: (_, callback) => { start = callback; },
      getElementById: element, createElement: () => new Element() } };
  vm.createContext(uiContext); vm.runInContext(source, uiContext);
  await start();
  assert.equal(element('draft-preview').textContent, literal, 'markup is rendered with textContent');
  assert.equal(element('draft-list').children[0].textContent, draft.name);
  assert.equal(uiStore.publications.length, 0);
  element('draft-text').value = '<svg onload=alert(1)>literal</svg>';
  element('draft-text').listeners.input();
  assert.equal(element('draft-preview').textContent, '<svg onload=alert(1)>literal</svg>');
  assert.equal(element('draft-publish-ack').checked, false);
  await element('draft-publish').listeners.click();
  assert.equal(uiStore.publications.length, 0, 'unchecked publication consent blocks network action');
  const writesBeforeBackup = uiStore.writes();
  await element('draft-save').listeners.click();
  assert.equal(uiStore.writes(), writesBeforeBackup, 'backup readiness precedes preview');
  element('draft-backup-ack').checked = true;
  await element('draft-save').listeners.click();
  element('draft-ack').checked = true;
  await element('draft-commit').listeners.click();
  assert.equal(JSON.parse(uiStore.value()).drafts[0].text, '<svg onload=alert(1)>literal</svg>');
  assert.equal(uiStore.publications.length, 0);
  element('draft-publish-ack').checked = true;
  await element('draft-publish').listeners.click();
  assert.equal(uiStore.publications.length, 1);
  assert.equal(uiStore.publications[0].text, '<svg onload=alert(1)>literal</svg>');
  console.log('Site Publisher controller: persistence, fidelity, replay, edits, undo, restore, guards, privacy, and publication separation passed.');
})().catch((error) => { console.error(error); process.exitCode = 1; });
