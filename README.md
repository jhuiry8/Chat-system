
# Cloudflare Workers — Chat + Voice (Discord-like) Starter

This is a **starter** project that runs on **Cloudflare Workers** and uses:
- **Durable Objects** for real-time channels and presence (with WebSocket Hibernation).
- **D1** for accounts, guilds/servers, channels, memberships, invites, and message history.
- **R2** with **presigned URLs** for file/image uploads.
- **Cloudflare Realtime SFU** (WebRTC) for **voice channels**.

> Inspired by Cloudflare's workers chat demo and modern Realtime docs. Replace placeholders in `wrangler.toml` and `.dev.vars` before running.

## Features in this starter
- Create account / login (email+password, PBKDF2 hashing).
- Create guilds (servers) and channels (text/voice).
- Generate invite links, accept invites.
- Real-time text chat via WebSockets (Durable Object per channel).
- Image/file upload flow via R2 presigned URLs.
- Voice rooms via Cloudflare Realtime SFU (client has a simple connect UI).

## Quick start

1) **Install wrangler** and enable D1/DO/R2/Realtime in your account.
```bash
npm i -g wrangler
```

2) **Configure** `wrangler.toml` and create the required resources:
```bash
# D1
wrangler d1 create chat_d1

# Durable Objects
# (Wrangler will create them on publish)

# R2 bucket
wrangler r2 bucket create chat-uploads

# Bind Realtime (if required by your account plan; see docs)
# Many Realtime features are available via API without explicit binding.
```

3) **Local dev**:
```bash
cp .dev.vars.example .dev.vars
# Fill the secrets: JWT_SECRET, REALTIME_API_KEY (if applicable), R2 access keys if using presign from worker

npm install
npm run dev
```

4) **Init DB**:
```bash
wrangler d1 execute chat_d1 --file=./schema.sql --local
```

5) **Open app**:
- Dev server: http://localhost:8787 (serves the static client + APIs)
- Try creating an account, a guild, a channel, then open two tabs to chat.
- Create a voice channel, join it, grant mic permissions to see the SFU working.

> This starter is intentionally minimal. Harden auth, add rate limits, and validate inputs before production.


## Configure Cloudflare Realtime (SFU)

This starter now includes a **server-side negotiator** for Cloudflare Realtime (SFU). You only need to provide two things:

1. **REALTIME_API_KEY** — an API token with permissions for Realtime/Calls in your Cloudflare account.
2. **REALTIME_CONNECT_URL** — the **Connection API** endpoint to create a session and exchange SDP. It looks like:

```
https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/realtime/apps/<APP_ID>/sessions
```

> Find the exact endpoint in the Cloudflare Realtime **Connection API** docs, then copy it to your `.dev.vars` (and to dashboard secrets for production).

When a client joins a voice channel, the worker will:
- Create a local SDP **offer** in the browser.
- POST that offer to your `REALTIME_CONNECT_URL` with `Authorization: Bearer ${REALTIME_API_KEY}`.
- Return the SFU's SDP **answer** to the browser and complete the WebRTC setup.
