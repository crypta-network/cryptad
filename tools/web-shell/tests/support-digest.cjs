/* Actual support digest functions compared with Node's independent SHA-256 implementation. */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createHash, webcrypto } = require('node:crypto');
const source = fs.readFileSync(path.resolve(__dirname,
  '../../../platform-web-shell/src/main/resources/network/crypta/platform/webshell/static/web-shell.js'), 'utf8');
const functions = source.slice(source.indexOf('  function supportSha256Fallback('),
  source.indexOf('  async function verifySupportText('));
assert(functions.includes('async function supportDigest('));
const values = [Buffer.from(''), Buffer.from('abc'), Buffer.from('非ASCII café 😀'),
  Buffer.from('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'), Buffer.alloc(1000000, 97)];
for (const length of [1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 2048, 2 * 1024 * 1024]) {
  values.push(Buffer.from(Array.from({ length }, (_, index) => index % 256)));
}
(async () => {
  for (const crypto of [undefined, {}, webcrypto]) {
    const digest = vm.runInNewContext(functions + '\nsupportDigest', { window: { crypto } });
    for (const bytes of values) {
      assert.equal(await digest(new Uint8Array(bytes)), createHash('sha256').update(bytes).digest('hex'));
    }
  }
  console.log(JSON.stringify({ sha256Vectors: values.length, cryptoContexts: 3, allMatched: true }));
})().catch(error => { console.error(error); process.exitCode = 1; });
