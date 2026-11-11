const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

function decryptGate(gateHtml, password, iterations) {
  const match = gateHtml.match(/const encrypted = (\{[^;]+\});/);
  assert.ok(match, '密码页应包含加密载荷');

  const encrypted = JSON.parse(match[1]);
  const payload = Buffer.from(encrypted.payload, 'base64');
  const ciphertext = payload.subarray(0, -16);
  const authTag = payload.subarray(-16);
  const key = crypto.pbkdf2Sync(
    password,
    Buffer.from(encrypted.salt, 'base64'),
    iterations,
    32,
    'sha256'
  );
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(encrypted.iv, 'base64')
  );
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

test('protect-dist 应加密 HTML，并移除公开搜索索引', async () => {
  const moduleUrl = pathToFileURL(path.join(__dirname, '..', 'scripts', 'protect-dist.mjs')).href;
  const { ITERATIONS, SEARCH_INDEX_MARKER, protectDist } = await import(moduleUrl);
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'menav-protect-'));
  const password = 'correct horse battery staple';

  try {
    fs.writeFileSync(
      path.join(tempDir, 'index.html'),
      '<!doctype html><html><body><p>PRIVATE_PAGE_DATA</p></body></html>'
    );
    fs.writeFileSync(
      path.join(tempDir, 'search-index.json'),
      JSON.stringify({ schemaVersion: 1, items: [{ name: 'PRIVATE_SEARCH_DATA' }] })
    );
    fs.writeFileSync(
      path.join(tempDir, '404.html'),
      '<!doctype html><html><body>PRIVATE_404_DATA</body></html>'
    );

    protectDist({ distDir: tempDir, password });

    assert.equal(fs.existsSync(path.join(tempDir, 'search-index.json')), false);
    const gateHtml = fs.readFileSync(path.join(tempDir, 'index.html'), 'utf8');
    assert.doesNotMatch(gateHtml, /PRIVATE_(?:PAGE|SEARCH)_DATA/);

    const decrypted = decryptGate(gateHtml, password, ITERATIONS);
    assert.match(decrypted, /PRIVATE_PAGE_DATA/);
    assert.match(decrypted, /PRIVATE_SEARCH_DATA/);
    assert.match(decrypted, new RegExp(`id="${SEARCH_INDEX_MARKER}"`));

    const notFoundGate = fs.readFileSync(path.join(tempDir, '404.html'), 'utf8');
    assert.doesNotMatch(notFoundGate, /PRIVATE_404_DATA/);
    assert.match(decryptGate(notFoundGate, password, ITERATIONS), /PRIVATE_404_DATA/);
  } finally {
    const resolvedTempDir = path.resolve(tempDir);
    assert.ok(resolvedTempDir.startsWith(path.resolve(os.tmpdir()) + path.sep));
    fs.rmSync(resolvedTempDir, { recursive: true, force: true });
  }
});

test('protect-dist 应拒绝短密码', async () => {
  const moduleUrl = pathToFileURL(path.join(__dirname, '..', 'scripts', 'protect-dist.mjs')).href;
  const { protectDist } = await import(moduleUrl);
  assert.throws(
    () => protectDist({ distDir: os.tmpdir(), password: 'too-short' }),
    /至少 12 个字符/
  );
});
