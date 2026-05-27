/**
 * DropSecrets — Cloudflare Worker
 * Ephemeral encrypted secret sharing with auto-destruct
 *
 * Requires KV namespace binding: SECRETS_KV
 */

// ─── Crypto helpers ──────────────────────────────────────────────

async function encrypt(payload, passphrase) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600_000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(payload));

  // Combine salt + iv + ciphertext
  const combined = new Uint8Array(salt.length + iv.length + ct.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(ct), salt.length + iv.length);

  return arrayToBase64(combined);
}

async function decrypt(blobB64, passphrase) {
  const enc = new TextEncoder();
  const combined = base64ToArray(blobB64);
  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const ct = combined.slice(28);

  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600_000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new TextDecoder().decode(plaintext);
}

function arrayToBase64(arr) {
  let binary = '';
  for (let i = 0; i < arr.length; i++) binary += String.fromCharCode(arr[i]);
  return btoa(binary);
}

function base64ToArray(b64) {
  const binary = atob(b64);
  const arr = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) arr[i] = binary.charCodeAt(i);
  return arr;
}

// ─── ID generation ───────────────────────────────────────────────

function generateId() {
  const arr = new Uint8Array(9);
  crypto.getRandomValues(arr);
  return arrayToBase64(arr).replace(/[+/=]/g, '').slice(0, 12).toLowerCase();
}

// ─── HTML pages ──────────────────────────────────────────────────

const CREATE_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DropSecrets</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: #0f0f14; color: #e0e0e0; min-height: 100vh; display: flex;
         align-items: center; justify-content: center; padding: 20px; }
  .card { background: #1a1a24; border-radius: 16px; padding: 40px; max-width: 520px;
          width: 100%; box-shadow: 0 20px 60px rgba(0,0,0,0.5); border: 1px solid #2a2a3a; }
  h1 { font-size: 24px; margin-bottom: 4px; }
  .sub { color: #888; font-size: 14px; margin-bottom: 24px; }
  label { display: block; font-size: 13px; color: #aaa; margin-bottom: 6px; margin-top: 16px; }
  textarea, input, select { width: 100%; background: #0f0f14; border: 1px solid #2a2a3a;
         border-radius: 8px; padding: 12px; color: #e0e0e0; font-size: 14px;
         outline: none; transition: border 0.2s; }
  textarea:focus, input:focus, select:focus { border-color: #6c5ce7; }
  textarea { min-height: 100px; resize: vertical; font-family: monospace; }
  .row { display: flex; gap: 12px; align-items: end; }
  .row > * { flex: 1; }
  button { width: 100%; margin-top: 20px; padding: 14px; border: none; border-radius: 8px;
           background: #6c5ce7; color: #fff; font-size: 16px; font-weight: 600;
           cursor: pointer; transition: background 0.2s; }
  button:hover { background: #5a4bd1; }
  button:disabled { background: #3a3a4a; cursor: not-allowed; }
  #result { display: none; margin-top: 20px; padding: 16px; background: #0f0f14;
            border-radius: 8px; border: 1px solid #2a2a3a; word-break: break-all; }
  #result .url { font-family: monospace; font-size: 13px; color: #6c5ce7; margin: 8px 0; }
  #qrcode { text-align: center; margin: 12px 0; }
  #qrcode img { max-width: 200px; height: auto; border-radius: 8px; }
  .copy-btn { background: #2a2a3a; padding: 8px 16px; font-size: 13px; margin-top: 8px; cursor: pointer; border: none; border-radius: 6px; color: #e0e0e0; }
  .copy-btn:hover { background: #3a3a4a; }
  .note { font-size: 12px; color: #666; margin-top: 20px; text-align: center; }
  .error { color: #ef4444; font-size: 13px; margin-top: 8px; display: none; }
  .footer { margin-top: 24px; font-size: 11px; color: #444; text-align: center; }
  .footer a { color: #6c5ce7; text-decoration: none; }
</style>
</head>
<body>
<div class="card">
  <h1>🔒 DropSecrets</h1>
  <div class="sub">Encrypted secret sharing — auto-destructs after viewing</div>

  <label>Secret payload</label>
  <textarea id="payload" placeholder="Type your secret message here..."></textarea>

  <div class="row">
    <div>
      <label>Passphrase</label>
      <input type="text" id="passphrase" placeholder="e.g. correct-horse-battery">
    </div>
    <div>
      <label>Expiry</label>
      <select id="expiry">
        <option value="5">5 min</option>
        <option value="30">30 min</option>
        <option value="60" selected>1 hour</option>
        <option value="360">6 hours</option>
        <option value="1440">24 hours</option>
      </select>
    </div>
  </div>

  <button id="createBtn" onclick="createSecret()">✨ Create Secret Link</button>
  <div class="error" id="error"></div>

  <div id="result">
    <div style="font-size:13px;color:#888;margin-bottom:8px">🔗 Share this link (and the passphrase separately)</div>
    <div class="url" id="secretUrl"></div>
    <div id="qrcode"></div>
    <button class="copy-btn" onclick="copyLink()">📋 Copy Link</button>
  </div>

  <div class="note">Your secret is encrypted before it leaves your browser. The server never sees plaintext.</div>
  <div class="footer">Powered by Cloudflare Workers</div>
</div>

<script>
async function createSecret() {
  const payload = document.getElementById('payload').value.trim();
  const passphrase = document.getElementById('passphrase').value.trim();
  const expiry = parseInt(document.getElementById('expiry').value);
  const error = document.getElementById('error');
  const btn = document.getElementById('createBtn');
  const result = document.getElementById('result');

  error.style.display = 'none';
  if (!payload) { error.textContent = 'Enter a secret payload'; error.style.display = 'block'; return; }
  if (!passphrase) { error.textContent = 'Enter a passphrase'; error.style.display = 'block'; return; }

  btn.disabled = true;
  btn.textContent = '⏳ Encrypting...';

  try {
    const resp = await fetch('/api/secret', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payload, passphrase, expiry_minutes: expiry })
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Error');

    const link = window.location.origin + '/' + data.id;
    document.getElementById('secretUrl').textContent = link;
    document.getElementById('secretUrl').href = link;

    document.getElementById('qrcode').innerHTML =
      '<img src="/qr/' + data.id + '" alt="QR Code">';

    result.style.display = 'block';
    btn.textContent = '✅ Created!';
    setTimeout(() => { btn.textContent = '✨ Create Another'; btn.disabled = false; }, 2000);
  } catch (e) {
    error.textContent = e.message;
    error.style.display = 'block';
    btn.disabled = false;
    btn.textContent = '✨ Create Secret Link';
  }
}

function copyLink() {
  const url = document.getElementById('secretUrl').textContent;
  navigator.clipboard.writeText(url).then(() => alert('Link copied!')).catch(() => prompt('Copy:', url));
}
</script>
</body>
</html>`;

const VIEW_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DropSecrets - View</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: #0f0f14; color: #e0e0e0; min-height: 100vh; display: flex;
         align-items: center; justify-content: center; padding: 20px; }
  .card { background: #1a1a24; border-radius: 16px; padding: 40px; max-width: 520px;
          width: 100%; box-shadow: 0 20px 60px rgba(0,0,0,0.5); border: 1px solid #2a2a3a; }
  h1 { font-size: 24px; margin-bottom: 4px; }
  .sub { color: #888; font-size: 14px; margin-bottom: 24px; }
  label { display: block; font-size: 13px; color: #aaa; margin-bottom: 6px; margin-top: 16px; }
  input { width: 100%; background: #0f0f14; border: 1px solid #2a2a3a;
         border-radius: 8px; padding: 12px; color: #e0e0e0; font-size: 14px;
         outline: none; }
  input:focus { border-color: #6c5ce7; }
  button { width: 100%; margin-top: 20px; padding: 14px; border: none; border-radius: 8px;
           background: #6c5ce7; color: #fff; font-size: 16px; font-weight: 600;
           cursor: pointer; transition: background 0.2s; }
  button:hover { background: #5a4bd1; }
  button:disabled { background: #3a3a4a; cursor: not-allowed; }
  #secret { display: none; margin-top: 20px; padding: 16px; background: #0f0f14;
            border-radius: 8px; border: 1px solid #2a2a3a; }
  #secret pre { white-space: pre-wrap; word-break: break-word; font-family: monospace;
                font-size: 14px; color: #a78bfa; }
  .error { color: #ef4444; font-size: 13px; margin-top: 8px; display: none; }
  .warn { color: #f59e0b; font-size: 13px; margin-top: 8px; }
  .destroyed { text-align: center; padding: 40px 0; }
  .destroyed h2 { color: #ef4444; margin-bottom: 8px; }
  .destroyed p { color: #888; }
  .footer { margin-top: 24px; font-size: 11px; color: #444; text-align: center; }
</style>
</head>
<body>
<div class="card">
  <div id="loading">
    <h1>🔍 Retrieving secret...</h1>
    <div class="sub">One moment please</div>
  </div>

  <div id="unlock" style="display:none">
    <h1>🔓 Encrypted Secret</h1>
    <div class="sub">Enter the passphrase to decrypt <span class="warn">(one-time view only)</span></div>
    <label>Passphrase</label>
    <input type="text" id="passphrase" placeholder="Enter passphrase" autofocus>
    <button onclick="decrypt()">🔑 Decrypt</button>
    <div class="error" id="error"></div>
  </div>

  <div id="secret">
    <h2>📜 Your Secret</h2>
    <pre id="secretContent"></pre>
    <div style="margin-top:12px;font-size:12px;color:#ef4444;">⚠️ This message has been destroyed on the server.</div>
    <button style="margin-top:12px;background:#2a2a3a" onclick="window.location.href='/'">✨ Send Another</button>
  </div>

  <div id="destroyed" style="display:none" class="destroyed">
    <h2>💥 Gone</h2>
    <p>This secret has expired or was already viewed.</p>
    <button style="margin-top:16px;background:#2a2a3a" onclick="window.location.href='/'">✨ Send a Secret</button>
  </div>
</div>

<script>
const SECRET_ID = location.pathname.slice(1);
let encryptedData = null;

async function init() {
  try {
    const resp = await fetch('/read/' + SECRET_ID);
    if (resp.status === 410) { showDestroyed(); return; }
    if (!resp.ok) { showDestroyed(); return; }
    const data = await resp.json();
    encryptedData = data.encrypted;
    document.getElementById('loading').style.display = 'none';
    document.getElementById('unlock').style.display = 'block';
  } catch (e) { showDestroyed(); }
}

function showDestroyed() {
  document.getElementById('loading').style.display = 'none';
  document.getElementById('destroyed').style.display = 'block';
}

async function decrypt() {
  const passphrase = document.getElementById('passphrase').value.trim();
  const error = document.getElementById('error');
  error.style.display = 'none';

  if (!passphrase) { error.textContent = 'Enter the passphrase'; error.style.display = 'block'; return; }

  try {
    const resp = await fetch('/decrypt/' + SECRET_ID, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ passphrase })
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Wrong passphrase');

    document.getElementById('unlock').style.display = 'none';
    document.getElementById('secret').style.display = 'block';
    document.getElementById('secretContent').textContent = data.plaintext;
  } catch (e) {
    error.textContent = e.message;
    error.style.display = 'block';
  }
}

init();
</script>
</body>
</html>`;

// ─── Router ───────────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // ── Human routes ──

      // GET / — create page
      if (path === '/' || path === '') {
        return new Response(CREATE_PAGE, {
          headers: { 'Content-Type': 'text/html; charset=utf-8', ...corsHeaders }
        });
      }

      // GET /:id — view page
      const id = path.slice(1);
      if (/^[a-z0-9]{8,16}$/.test(id) && !id.startsWith('api')) {
        return new Response(VIEW_PAGE, {
          headers: { 'Content-Type': 'text/html; charset=utf-8', ...corsHeaders }
        });
      }

      // ── Bot API routes (prefixed with /api) ──

      if (path === '/api/secret' && request.method === 'POST') {
        return await handleCreate(request, env, url, corsHeaders);
      }

      if (path.startsWith('/api/secret/')) {
        const secretId = path.slice(12);
        if (!/^[a-z0-9]{8,16}$/.test(secretId)) {
          return jsonResponse({ error: 'Invalid secret ID' }, 400, corsHeaders);
        }
        if (request.method === 'GET') {
          return await handleRead(secretId, env, corsHeaders);
        }
        if (request.method === 'POST') {
          return await handleDecrypt(secretId, request, env, corsHeaders);
        }
      }

      // ── Legacy bot routes (backward compat) ──

      if (path === '/create' && request.method === 'POST') {
        return await handleCreate(request, env, url, corsHeaders);
      }

      if (path.startsWith('/read/') && request.method === 'GET') {
        return await handleRead(path.slice(6), env, corsHeaders);
      }

      if (path.startsWith('/decrypt/') && request.method === 'POST') {
        return await handleDecrypt(path.slice(9), request, env, corsHeaders);
      }

      if (path.startsWith('/qr/') && request.method === 'GET') {
        return handleQR(path.slice(4), url);
      }

      // GET /api — show bot API reference
      if (path === '/api' && request.method === 'GET') {
        return handleAPIReference(url, corsHeaders);
      }


    } catch (e) {
      return new Response(JSON.stringify({ error: e.message }), {
        status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
};

// ─── Handlers ────────────────────────────────────────────────────

function jsonResponse(data, status = 200, corsHeaders) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders }
  });
}

async function handleCreate(request, env, url, corsHeaders) {
  const { payload, passphrase, expiry_minutes = 60 } = await request.json();

  if (!payload || !passphrase) {
    return jsonResponse({ error: 'Payload and passphrase required' }, 400, corsHeaders);
  }
  if (payload.length > 50000) {
    return jsonResponse({ error: 'Payload too large (max 50KB)' }, 400, corsHeaders);
  }

  const id = generateId();
  const encrypted = await encrypt(payload, passphrase);
  const ttl = Math.min(Math.max(parseInt(expiry_minutes) || 60, 1), 1440) * 60;
  const link = url.origin + '/' + id;
  const qrUrl = url.origin + '/qr/' + id;

  await env.SECRETS_KV.put(id, encrypted, { expirationTtl: ttl });

  return jsonResponse({
    id,
    link,
    qr_url: qrUrl,
    expires_in_seconds: ttl,
    expires_in_minutes: Math.round(ttl / 60),
    // Bot-friendly: provide the passphrase hint — share link + passphrase separately
    hint: 'Send the link and qr_url to the recipient. Share the passphrase separately (not in the same channel).'
  }, 200, corsHeaders);
}

async function handleRead(id, env, corsHeaders) {
  const encrypted = await env.SECRETS_KV.get(id);
  if (!encrypted) {
    return jsonResponse({ error: 'Secret not found or expired' }, 404, corsHeaders);
  }
  return jsonResponse({ id, encrypted, hint: 'Use POST /api/secret/' + id + ' with {"passphrase":"..."} to decrypt.' }, 200, corsHeaders);
}

async function handleDecrypt(id, request, env, corsHeaders) {
  const { passphrase } = await request.json();
  if (!passphrase) {
    return jsonResponse({ error: 'Passphrase required' }, 400, corsHeaders);
  }

  const encrypted = await env.SECRETS_KV.get(id);
  if (!encrypted) {
    return jsonResponse({ error: 'Secret not found or expired' }, 404, corsHeaders);
  }

  try {
    const plaintext = await decrypt(encrypted, passphrase);
    // Auto-destruct: delete after successful decryption
    await env.SECRETS_KV.delete(id);
    return jsonResponse({ id, plaintext, destroyed: true }, 200, corsHeaders);
  } catch (e) {
    return jsonResponse({ error: 'Wrong passphrase' }, 403, corsHeaders);
  }
}

function handleQR(id, url) {
  const link = url.origin + '/' + id;
  const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(link)}`;
  return Response.redirect(qrUrl, 302);
}

function handleAPIReference(baseUrl, corsHeaders) {
  const api = {
    service: 'DropSecrets',
    version: '1.0.0',
    description: 'Ephemeral encrypted secret sharing for humans and bots',
    encryption: 'AES-256-GCM + PBKDF2 (600K iterations)',
    storage: 'Cloudflare Workers KV with TTL expiry',
    auto_destruct: 'Secret is deleted from server after successful decryption',
    base_url: baseUrl.origin,
    endpoints: [
      {
        method: 'POST',
        path: '/api/secret',
        description: 'Create an encrypted secret',
        request_body: {
          payload: 'string (required) — the secret message (max 50KB)',
          passphrase: 'string (required) — passphrase to encrypt/decrypt',
          expiry_minutes: 'number (optional, default 60, min 1, max 1440)'
        },
        response: {
          id: 'string — unique secret ID',
          link: 'string — full URL to view the secret',
          qr_url: 'string — QR code image URL',
          expires_in_seconds: 'number — TTL'
        },
        example: `curl -X POST ${baseUrl.origin}/api/secret \\
  -H "Content-Type: application/json" \\
  -d '{"payload":"Hello agent!","passphrase":"hunter2","expiry_minutes":60}'`
      },
      {
        method: 'GET',
        path: '/api/secret/{id}',
        description: 'Read encrypted blob (does NOT destroy)',
        response: {
          id: 'string',
          encrypted: 'string (base64) — AES-256-GCM encrypted payload'
        }
      },
      {
        method: 'POST',
        path: '/api/secret/{id}',
        description: 'Decrypt and retrieve secret (DESTROYS after success)',
        request_body: {
          passphrase: 'string (required) — the passphrase used during creation'
        },
        response: {
          id: 'string',
          plaintext: 'string — the decrypted secret',
          destroyed: 'boolean — always true'
        },
        example: `curl -X POST ${baseUrl.origin}/api/secret/abc123def456 \\
  -H "Content-Type: application/json" \\
  -d '{"passphrase":"hunter2"}'`
      }
    ],
    // Legacy endpoints (backward compatible):
    legacy_endpoints: [
      { method: 'POST', path: '/create', same_as: 'POST /api/secret' },
      { method: 'GET', path: '/read/{id}', same_as: 'GET /api/secret/{id}' },
      { method: 'POST', path: '/decrypt/{id}', same_as: 'POST /api/secret/{id}' },
      { method: 'GET', path: '/qr/{id}', description: 'Redirect to QR code image' }
    ],
    // Human pages:
    pages: [
      { path: '/', description: 'Create page (human)' },
      { path: '/{id}', description: 'View page (human)' }
    ]
  };
  return jsonResponse(api, 200, corsHeaders);
}
