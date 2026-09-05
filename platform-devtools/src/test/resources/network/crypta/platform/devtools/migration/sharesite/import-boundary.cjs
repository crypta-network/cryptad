const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const context = { TextEncoder, TextDecoder, Uint8Array, atob, btoa,
  window: { crypto: webcrypto }, document: { addEventListener() {} } };
vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), context);
(async () => {
  const drafts = context.window.SitePublisherDrafts;
  const converted = await drafts.parsePackage(new Uint8Array(fs.readFileSync(process.argv[3])));
  const inventoryCount = Number(process.argv[4] || 0);
  const selectedCount = inventoryCount ? 1 : 3;
  if (inventoryCount) {
    assert.equal(converted.package.exclusions.private_insert_identity_not_imported, inventoryCount);
    assert.equal(converted.package.exclusions.recently_deleted, inventoryCount - 512);
    assert.equal(converted.package.exclusions.unsupported_textile, 511);
    for (const count of [1025, -1, 0.5, '1024']) {
      const invalid = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
      invalid.exclusions.private_insert_identity_not_imported = count;
      await assert.rejects(drafts.parsePackage(new TextEncoder().encode(JSON.stringify(invalid))),
        /draft_validation_failed/);
    }
  }
  let previews = 0;
  const model = drafts.controller({ data: {
    status: async () => ({ sharesiteWriteGuard: 1 }),
    records: { put: async (request) => {
      previews++;
      assert.equal(request.writeIntent, 'preview');
      if (!inventoryCount) assert.equal(Buffer.byteLength(request.valueJson, 'utf8'), 196608);
      const dataset = JSON.parse(request.valueJson);
      assert.equal(dataset.operations.length, 1);
      assert.equal(dataset.drafts.length, selectedCount);
      assert.equal(dataset.operations[0].draftIds.length, selectedCount);
      assert.match(dataset.operations[0].payloadSha256, /^[0-9a-f]{64}$/);
      assert.match(dataset.operations[0].originalsSha256, /^[0-9a-f]{64}$/);
      return { previewId: 'synthetic-boundary-preview' };
    } }
  } });
  await model.previewImport(converted);
  assert.equal(previews, 1, 'the complete converted selection reaches the guarded API preview');
})().catch((error) => { console.error(error); process.exitCode = 1; });
