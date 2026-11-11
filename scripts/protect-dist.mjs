import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ITERATIONS = 310_000;
const SEARCH_INDEX_MARKER = 'menav-embedded-search-index';

function toBase64(value) {
  return Buffer.from(value).toString('base64');
}

function encryptHtml(html, password) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(password, salt, ITERATIONS, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(html, 'utf8'), cipher.final()]);
  const payload = Buffer.concat([ciphertext, cipher.getAuthTag()]);

  return {
    salt: toBase64(salt),
    iv: toBase64(iv),
    payload: toBase64(payload),
  };
}

function escapeScriptJson(json) {
  return json
    .replace(/<\//g, '<\\/')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

function embedSearchIndex(html, searchIndexJson) {
  const marker = `<script id="${SEARCH_INDEX_MARKER}" type="application/json">${escapeScriptJson(
    searchIndexJson
  )}</script>`;
  const bodyEnd = html.lastIndexOf('</body>');
  if (bodyEnd < 0) throw new Error('dist/index.html 缺少 </body>，无法嵌入搜索索引');
  return `${html.slice(0, bodyEnd)}${marker}${html.slice(bodyEnd)}`;
}

function renderPasswordGate(encrypted) {
  return `<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="robots" content="noindex, nofollow, noarchive" />
    <title>访问 MeNav</title>
    <style>
      :root { color-scheme: dark; font-family: system-ui, sans-serif; }
      * { box-sizing: border-box; }
      body { min-height: 100vh; margin: 0; display: grid; place-items: center; background: #17181c; color: #f3f4f6; }
      main { width: min(90vw, 380px); padding: 32px; border: 1px solid #3a3d45; border-radius: 18px; background: #24262c; box-shadow: 0 20px 60px #0006; }
      h1 { margin: 0 0 8px; font-size: 24px; }
      p { margin: 0 0 24px; color: #aeb2bd; line-height: 1.6; }
      label { display: block; margin-bottom: 8px; font-size: 14px; }
      input, button { width: 100%; min-height: 44px; border-radius: 10px; font: inherit; }
      input { border: 1px solid #505460; padding: 0 12px; background: #18191d; color: inherit; }
      button { margin-top: 14px; border: 0; background: #6d8cff; color: white; cursor: pointer; font-weight: 650; }
      button:disabled { cursor: wait; opacity: .65; }
      #error { min-height: 20px; margin: 12px 0 0; color: #ff8e8e; font-size: 14px; }
    </style>
  </head>
  <body>
    <main>
      <h1>MeNav 已加密</h1>
      <p>请输入站点密码。密码只在当前页面内用于解密，不会发送到服务器。</p>
      <form id="unlock-form">
        <label for="password">站点密码</label>
        <input id="password" type="password" autocomplete="current-password" required autofocus />
        <button id="unlock" type="submit">解锁</button>
        <div id="error" role="alert" aria-live="polite"></div>
      </form>
    </main>
    <script>
      const encrypted = ${JSON.stringify(encrypted)};
      const iterations = ${ITERATIONS};
      const fromBase64 = (value) => Uint8Array.from(atob(value), (char) => char.charCodeAt(0));

      document.getElementById('unlock-form').addEventListener('submit', async (event) => {
        event.preventDefault();
        const password = document.getElementById('password').value;
        const button = document.getElementById('unlock');
        const error = document.getElementById('error');
        button.disabled = true;
        error.textContent = '';

        try {
          const material = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
          );
          const key = await crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt: fromBase64(encrypted.salt), iterations, hash: 'SHA-256' },
            material,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
          );
          const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: fromBase64(encrypted.iv) },
            key,
            fromBase64(encrypted.payload)
          );
          const html = new TextDecoder().decode(plaintext);
          document.open();
          document.write(html);
          document.close();
        } catch {
          error.textContent = '密码错误，无法解锁。';
          button.disabled = false;
          document.getElementById('password').select();
        }
      });
    </script>
  </body>
</html>`;
}

function protectDist({ distDir, password }) {
  if (!password || password.length < 12) {
    throw new Error('MENAV_SITE_PASSWORD 必须至少 12 个字符；建议使用 16 个以上随机字符');
  }

  const indexPath = path.join(distDir, 'index.html');
  const searchIndexPath = path.join(distDir, 'search-index.json');
  if (!fs.existsSync(indexPath)) throw new Error(`未找到构建产物：${indexPath}`);
  if (!fs.existsSync(searchIndexPath)) throw new Error(`未找到搜索索引：${searchIndexPath}`);

  const searchIndexJson = fs.readFileSync(searchIndexPath, 'utf8');
  const indexHtml = embedSearchIndex(fs.readFileSync(indexPath, 'utf8'), searchIndexJson);
  fs.writeFileSync(indexPath, renderPasswordGate(encryptHtml(indexHtml, password)));
  fs.rmSync(searchIndexPath);

  const notFoundPath = path.join(distDir, '404.html');
  if (fs.existsSync(notFoundPath)) {
    const notFoundHtml = fs.readFileSync(notFoundPath, 'utf8');
    fs.writeFileSync(notFoundPath, renderPasswordGate(encryptHtml(notFoundHtml, password)));
  }
}

function main() {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  protectDist({
    distDir: path.join(repoRoot, 'dist'),
    password: process.env.MENAV_SITE_PASSWORD || '',
  });
  console.log('[protect] 已加密 dist/index.html、搜索索引和 404 页面');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    console.error(`[protect] ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}

export { ITERATIONS, SEARCH_INDEX_MARKER, embedSearchIndex, encryptHtml, protectDist };
