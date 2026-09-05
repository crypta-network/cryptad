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
  let previews = 0;
  const model = drafts.controller({ data: {
    status: async () => ({ sharesiteWriteGuard: 1 }),
    records: { put: async (request) => {
      previews++;
      assert.equal(request.writeIntent, 'preview');
      assert.equal(Buffer.byteLength(request.valueJson, 'utf8'), 196608);
      const dataset = JSON.parse(request.valueJson);
      assert.equal(dataset.operations.length, 1);
      assert.equal(dataset.drafts.length, 3);
      assert.equal(dataset.operations[0].draftIds.length, 3);
      assert.match(dataset.operations[0].payloadSha256, /^[0-9a-f]{64}$/);
      assert.match(dataset.operations[0].originalsSha256, /^[0-9a-f]{64}$/);
      return { previewId: 'synthetic-boundary-preview' };
    } }
  } });
  await model.previewImport(converted);
  assert.equal(previews, 1, 'the complete converted selection reaches the guarded API preview');
})().catch((error) => { console.error(error); process.exitCode = 1; });
