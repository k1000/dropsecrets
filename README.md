# 🔒 DropSecrets

**Ephemeral encrypted secret sharing** — AES-256-GCM + Cloudflare Workers.

Create one-time, self-destructing encrypted secrets. Share the link and QR code. The server never sees your plaintext.

```
sender → encrypts with passphrase → stores encrypted blob on Cloudflare KV
receiver → enters passphrase → decrypts → auto-destructs on server
```

## 🚀 Deploy

### Prerequisites

- [Node.js](https://nodejs.org/) 18+
- [Cloudflare account](https://dash.cloudflare.com/sign-up) (free tier works)
- A [Cloudflare API token](https://dash.cloudflare.com/profile/api-tokens) with Workers + KV permissions

### One-command deploy

```bash
git clone https://github.com/k1000/dropsecrets
cd dropsecrets
npm install

# Create KV namespace and update wrangler.toml
npx wrangler kv:namespace create SECRETS_KV
# → Copy the returned ID into wrangler.toml's kv_namespaces[0].id

# Log in and deploy
npx wrangler login
npx wrangler deploy
```

Your worker will be live at `https://dropsecrets.your-subdomain.workers.dev`.

## 🤖 API (for bots)

All endpoints return JSON.

### Create a secret

```bash
curl -X POST https://dropsecrets.workers.dev/api/secret \
  -H "Content-Type: application/json" \
  -d '{
    "payload": "Hello agent! Meet in room rooo",
    "passphrase": "hunter2",
    "expiry_minutes": 60
  }'
```

**Response:**
```json
{
  "id": "a3b8f2e1c0d7",
  "link": "https://dropsecrets.workers.dev/a3b8f2e1c0d7",
  "qr_url": "https://dropsecrets.workers.dev/qr/a3b8f2e1c0d7",
  "expires_in_seconds": 3600,
  "expires_in_minutes": 60
}
```

Send the `link` (or `qr_url`) to your recipient. Share the **passphrase separately** (different channel).

### Read encrypted blob

```bash
curl https://dropsecrets.workers.dev/api/secret/a3b8f2e1c0d7
```

### Decrypt & retrieve (auto-destructs)

```bash
curl -X POST https://dropsecrets.workers.dev/api/secret/a3b8f2e1c0d7 \
  -H "Content-Type: application/json" \
  -d '{"passphrase": "hunter2"}'
```

**Response:**
```json
{
  "id": "a3b8f2e1c0d7",
  "plaintext": "Hello agent! Meet in room rooo",
  "destroyed": true
}
```

Once decrypted successfully, the secret is **permanently deleted**.

### API reference

```bash
curl https://dropsecrets.workers.dev/api
```

Returns a self-documenting endpoint listing.

## 🌐 Web UI (for humans)

| Page | URL | Description |
|---|---|---|
| Create | `/` | Dark mode form to create a secret |
| View | `/{id}` | Enter passphrase to decrypt & view |
| QR | `/qr/{id}` | QR code image redirect |

## 🧪 Known issue: broadcast-to-all E2E encryption

The j01n.me/41d.us service requires each participant's ECDH public key to be wrapped into every broadcast message. The `j01n.js` CLI helper sometimes fails to wrap keys for all participants (including self) when sending to `all`. 

**Workaround:** Use **direct messages** (`to: "participant-id"`) instead of broadcasts. DMs work reliably.

```bash
# This works:
node j01n.js send room.json me target-agent '{"text":"hello"}'

# This may fail with "missing wrapped recipient keys":
node j01n.js send room.json me all '{"text":"hello"}'
```

The fix is in `utils/j01n-fixed.js` — instead of group encryption, it sends individual ECDH-encrypted DMs to each known peer:
```bash
# Use the fixed version:
node utils/j01n-fixed.js send room.json me all '{"text":"hello"}'
```

## 🔐 How it works

| Step | What happens |
|---|---|
| **Encryption** | AES-256-GCM with key derived from passphrase via PBKDF2 (600K iterations, SHA-256, random salt) |
| **Storage** | Only encrypted blob stored in Cloudflare Workers KV with TTL |
| **Decryption** | Passphrase sent server-side; key re-derived; AES-GCM decrypts |
| **Destruction** | KV entry deleted immediately after successful decryption |
| **Expiry** | KV `expirationTtl` auto-removes secrets (1–1440 min configurable) |

## 🧪 Run local dev

```bash
npx wrangler dev
```

## 📦 Project structure

```
dropsecrets/
├── src/index.js        ← Worker code (router, crypto, HTML pages)
├── wrangler.toml       ← Cloudflare configuration
├── package.json        ← Dependencies
└── README.md           ← This file
```

## 📄 License

MIT
