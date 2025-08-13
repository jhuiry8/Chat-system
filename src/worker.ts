
import { encode as b64encode } from './x/b64.js';

export interface Env {
  DB: D1Database;
  R2: R2Bucket;
  ChannelRoom: DurableObjectNamespace;
  VoiceSignal: DurableObjectNamespace;
  JWT_SECRET: string;
  CLIENT_ORIGIN: string;
  R2_PUBLIC_BASE: string;
  REALTIME_API_KEY?: string;
  // Optional R2 S3 creds for presign (not required if using public R2.dev bucket domain with write-only)
  R2_ACCESS_KEY_ID?: string;
  R2_SECRET_ACCESS_KEY?: string;
  R2_ACCOUNT_ID?: string;
  R2_BUCKET?: string;
}

export default {
  fetch(req: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(req.url);
    // Static client
    if (url.pathname === '/') return serveFile('public/index.html');
    if (url.pathname.startsWith('/public/')) return serveFile(url.pathname.slice(1));
    if (url.pathname.startsWith('/ws/channel/')) return handleChannelWS(req, env);
    if (url.pathname.startsWith('/api/')) return api(req, env, ctx);
    // fallback: SPA assets
    return serveFile('public/index.html');
  }
};

async function serveFile(path: string) {
  try {
    const map = await (await fetch('file://' + path)).arrayBuffer();
    let type = 'text/plain';
    if (path.endsWith('.html')) type = 'text/html';
    if (path.endsWith('.js')) type = 'text/javascript';
    if (path.endsWith('.css')) type = 'text/css';
    return new Response(map, { headers: { 'content-type': type } });
  } catch {
    return new Response('Not found', { status: 404 });
  }
}

// --- Simple utilities ---
function json(data: any, init: any = {}) {
  return new Response(JSON.stringify(data), { headers: { 'content-type':'application/json' }, ...init });
}

function uid() { return crypto.randomUUID(); }

async function hashPassword(pw: string): Promise<string> {
  const enc = new TextEncoder().encode(pw);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc, 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name:'PBKDF2', hash:'SHA-256', salt, iterations: 100_000 }, key, 256);
  const combined = new Uint8Array(16 + 32);
  combined.set(salt,0); combined.set(new Uint8Array(bits),16);
  return b64encode(combined);
}

async function verifyPassword(pw: string, stored: string): Promise<boolean> {
  const raw = Uint8Array.from(atob(stored), c => c.charCodeAt(0));
  const salt = raw.slice(0,16);
  const hash = raw.slice(16);
  const enc = new TextEncoder().encode(pw);
  const key = await crypto.subtle.importKey('raw', enc, 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name:'PBKDF2', hash:'SHA-256', salt, iterations: 100_000 }, key, 256);
  const got = new Uint8Array(bits);
  if (got.length !== hash.length) return false;
  let ok = 1; for (let i=0;i<got.length;i++) ok &= (got[i] === hash[i]) ? 1 : 0;
  return !!ok;
}

// JWT (HS256 minimal)
async function signJWT(payload: any, secret: string, expSec = 86400) {
  const header = { alg:'HS256', typ:'JWT' };
  const iat = Math.floor(Date.now()/1000);
  const body = { ...payload, iat, exp: iat + expSec };
  const enc = (obj:any)=> btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(obj)))).replace(/=+$/,'');
  const base = enc(header)+'.'+enc(body);
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(base));
  const sig = btoa(String.fromCharCode(...new Uint8Array(mac))).replace(/=+$/,'');
  return base+'.'+sig;
}

async function verifyJWT(token: string, secret: string) {
  const [h,p,s] = token.split('.');
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(h+'.'+p));
  const sig = btoa(String.fromCharCode(...new Uint8Array(mac))).replace(/=+$/,'');
  if (sig !== s) return null;
  const body = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(p), c=>c.charCodeAt(0))));
  if (body.exp && Math.floor(Date.now()/1000) > body.exp) return null;
  return body;
}

// --- API Router ---
async function api(req: Request, env: Env, ctx: ExecutionContext) {
  const url = new URL(req.url);
  const path = url.pathname.replace('/api','');
  const method = req.method;

  // Public endpoints
  if (path === '/register' && method === 'POST') return register(req, env);
  if (path === '/login' && method === 'POST') return login(req, env);

  // Auth
  const auth = req.headers.get('authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const user = token ? await verifyJWT(token, env.JWT_SECRET) : null;
  if (!user) return json({ error: 'unauthorized' }, { status: 401 });

  // Guilds
  if (path === '/guilds' && method === 'GET') return listGuilds(env, user.sub);
  if (path === '/guilds' && method === 'POST') return createGuild(req, env, user.sub);
  if (path.match(/^\/guilds\/([^\/]+)\/channels$/) && method === 'GET') return listChannels(env, path.split('/')[2], user.sub);
  if (path.match(/^\/guilds\/([^\/]+)\/channels$/) && method === 'POST') return createChannel(req, env, path.split('/')[2], user.sub);

  // Invites
  if (path.match(/^\/guilds\/([^\/]+)\/invites$/) && method === 'POST') return createInvite(env, path.split('/')[2], user.sub);
  if (path.match(/^\/invites\/([^\/]+)\/accept$/) && method === 'POST') return acceptInvite(env, path.split('/')[2], user.sub);

  // Messages + attachments
  if (path.match(/^\/channels\/([^\/]+)\/attachments\/presign$/) && method === 'POST') return presignAttachment(req, env, path.split('/')[2], user.sub);
  if (path.match(/^\/channels\/([^\/]+)\/messages$/) && method === 'POST') return createMessage(req, env, path.split('/')[2], user.sub);

  // Voice
  if (path.match(/^\/voice\/([^\/]+)\/token$/) && method === 'GET') return voiceToken(env, path.split('/')[2], user.sub);
  if (path.match(/^\/voice\/([^\/]+)\/negotiate$/) && method === 'POST') return voiceNegotiate(req, env, path.split('/')[2], user.sub);

  return json({ error: 'not found' }, { status: 404 });
}

// --- Endpoint impls ---
async function register(req: Request, env: Env) {
  const body = await req.json();
  const id = crypto.randomUUID();
  const hash = await hashPassword(body.password);
  await env.DB.prepare('INSERT INTO users (id,email,password_hash,display_name,created_at) VALUES (?,?,?,?,?)')
    .bind(id, body.email, hash, body.display_name || 'user', Date.now()).run();
  return json({ ok: true });
}

async function login(req: Request, env: Env) {
  const body = await req.json();
  const row = await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(body.email).first();
  if (!row) return json({ error: 'invalid' }, { status: 400 });
  const ok = await verifyPassword(body.password, row.password_hash);
  if (!ok) return json({ error: 'invalid' }, { status: 400 });
  const token = await signJWT({ sub: row.id, email: row.email }, env.JWT_SECRET);
  return json({ token });
}

async function listGuilds(env: Env, userId: string) {
  const { results } = await env.DB.prepare(
    'SELECT g.id, g.name FROM guilds g JOIN memberships m ON g.id=m.guild_id WHERE m.user_id=?'
  ).bind(userId).all();
  return json({ guilds: results || [] });
}

async function createGuild(req: Request, env: Env, userId: string) {
  const { name } = await req.json();
  const id = uid();
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare('INSERT INTO guilds (id, owner_id, name, created_at) VALUES (?,?,?,?)').bind(id, userId, name, now),
    env.DB.prepare('INSERT INTO memberships (user_id, guild_id, role) VALUES (?,?,?)').bind(userId, id, 'owner'),
  ]);
  // default text channel
  await env.DB.prepare('INSERT INTO channels (id, guild_id, name, kind, created_at) VALUES (?,?,?,?,?)')
    .bind(uid(), id, 'general', 'text', now).run();
  return json({ id });
}

async function listChannels(env: Env, guildId: string, userId: string) {
  const member = await env.DB.prepare('SELECT 1 FROM memberships WHERE user_id=? AND guild_id=?').bind(userId, guildId).first();
  if (!member) return json({ error: 'forbidden' }, { status: 403 });
  const { results } = await env.DB.prepare('SELECT id,name,kind FROM channels WHERE guild_id=?').bind(guildId).all();
  return json({ channels: results || [] });
}

async function createChannel(req: Request, env: Env, guildId: string, userId: string) {
  const member = await env.DB.prepare('SELECT role FROM memberships WHERE user_id=? AND guild_id=?').bind(userId, guildId).first();
  if (!member) return json({ error: 'forbidden' }, { status: 403 });
  const { name, kind } = await req.json();
  const id = uid();
  await env.DB.prepare('INSERT INTO channels (id,guild_id,name,kind,created_at) VALUES (?,?,?,?,?)').bind(id, guildId, name, kind, Date.now()).run();
  return json({ id });
}

async function createInvite(env: Env, guildId: string, userId: string) {
  const member = await env.DB.prepare('SELECT role FROM memberships WHERE user_id=? AND guild_id=?').bind(userId, guildId).first();
  if (!member) return json({ error: 'forbidden' }, { status: 403 });
  const code = uid().split('-')[0];
  await env.DB.prepare('INSERT INTO invites (code,guild_id,inviter_id,created_at) VALUES (?,?,?,?)').bind(code, guildId, userId, Date.now()).run();
  return json({ code });
}

async function acceptInvite(env: Env, code: string, userId: string) {
  const inv = await env.DB.prepare('SELECT * FROM invites WHERE code=?').bind(code).first();
  if (!inv) return json({ error: 'invalid' }, { status: 404 });
  // Simple: add membership
  await env.DB.prepare('INSERT OR IGNORE INTO memberships (user_id,guild_id,role) VALUES (?,?,?)').bind(userId, inv.guild_id, 'member').run();
  await env.DB.prepare('UPDATE invites SET uses=COALESCE(uses,0)+1 WHERE code=?').bind(code).run();
  return json({ ok: true, guild_id: inv.guild_id });
}

// Presign using R2 native signed URL (simple PUT). For advanced S3 v4, replace with full signer if needed.
async function presignAttachment(req: Request, env: Env, channelId: string, userId: string) {
  const { filename, type } = await req.json();
  const key = `${channelId}/${Date.now()}-${filename}`;
  const put = await env.R2.createPresignedUrl({
    method: 'PUT',
    key,
    // expirySeconds: 600, // optional
    customHeaders: [['content-type', type || 'application/octet-stream']]
  });
  const publicUrl = `${env.R2_PUBLIC_BASE}/${key}`;
  return json({ url: put.url.toString(), headers: Object.fromEntries(put.headers), publicUrl });
}

async function createMessage(req: Request, env: Env, channelId: string, userId: string) {
  const { content, attachment_url } = await req.json();
  const id = uid();
  await env.DB.prepare('INSERT INTO messages (id,channel_id,author_id,content,attachment_url,created_at) VALUES (?,?,?,?,?,?)')
    .bind(id, channelId, userId, content || null, attachment_url || null, Date.now()).run();
  // Fanout to room
  const stub = env.ChannelRoom.get(env.ChannelRoom.idFromName(channelId));
  await stub.fetch('https://do/send', { method:'POST', body: JSON.stringify({ type:'chat', author: userId, content, attachment_url }) });
  return json({ id });
}


// Voice token (optional). You can mint per-room policy tokens if your setup requires it.
async function voiceToken(env: Env, channelId: string, userId: string) {
  // If your Realtime setup needs scoped tokens, mint them here.
  return json({ token: 'ok' });
}

// SDP negotiation with Cloudflare Realtime HTTPS Connection API
// Expects env.REALTIME_CONNECT_URL and env.REALTIME_API_KEY to be set.
async function voiceNegotiate(req: Request, env: Env, channelId: string, userId: string) {
  const body = await req.json(); // { sdp, type, token? }
  if (!env.REALTIME_CONNECT_URL || !env.REALTIME_API_KEY) {
    return json({ error: 'Realtime not configured' }, { status: 500 });
  }
  const offer = {
    sdp: body.sdp,
    type: body.type || 'offer',
    // Optional: you can attach metadata to identify the channel/room
    metadata: { channelId, userId }
  };
  const r = await fetch(env.REALTIME_CONNECT_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'authorization': `Bearer ${env.REALTIME_API_KEY}`
    },
    body: JSON.stringify(offer)
  });
  if (!r.ok) {
    const txt = await r.text();
    return json({ error: 'realtime negotiate failed', status: r.status, detail: txt }, { status: 502 });
  }
  const answer = await r.json(); // should be { type: 'answer', sdp: '...' }
  return json(answer);
}

// WebSocket for channel (Durable Object handles hibernation & broadcast)
async function handleChannelWS(req: Request, env: Env) {
  const id = req.url.split('/').pop() as string;
  const stub = env.ChannelRoom.get(env.ChannelRoom.idFromName(id));
  return stub.fetch(req);
}

// --- Durable Object: ChannelRoom ---
export class ChannelRoom {
  state: DurableObjectState;
  storage: DurableObjectStorage;
  sessions: Map<string, WebSocket> = new Map();

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.storage = state.storage;
  }

  async fetch(req: Request) {
    const url = new URL(req.url);
    if (url.pathname.startsWith('/ws/channel/')) {
      const { 0: client, 1: server } = new WebSocketPair();
      const token = url.searchParams.get('token') || '';
      this.state.acceptWebSocket(server, ['json'], { keepAlive: 55 });
      // Store token on socket metadata for auth (optional: verify JWT here)
      (this.state as any).socketToken = token;
      return new Response(null, { status: 101, webSocket: client });
    }
    if (url.pathname === '/send' && req.method === 'POST') {
      const msg = await req.json();
      // broadcast to all
      for (const ws of (this.state as any).webSockets || []) {
        try { ws.send(JSON.stringify(msg)); } catch {}
      }
      return new Response('ok');
    }
    return new Response('not found', { status: 404 });
  }

  // Hibernation events
  webSocketMessage(ws: WebSocket, message: ArrayBuffer | string) {
    try {
      const data = JSON.parse(typeof message === 'string' ? message : new TextDecoder().decode(message as ArrayBuffer));
      const author = (this.state as any).socketToken || 'anon';
      const payload = { type:'chat', author, content: data.content || '' };
      for (const sock of (this.state as any).webSockets || []) sock.send(JSON.stringify(payload));
    } catch {}
  }

  webSocketClose(ws: WebSocket) {}
  webSocketError(ws: WebSocket, err: any) {}

  webSocketAccept(ws: WebSocket) {
    (this.state as any).webSockets = (this.state as any).webSockets || [];
    (this.state as any).webSockets.push(ws);
    ws.send(JSON.stringify({ type:'system', text:'welcome' }));
  }
}

// --- Durable Object: VoiceSignal (optional placeholder for future signaling) ---
export class VoiceSignal {
  constructor(readonly state: DurableObjectState, readonly env: Env) {}
  async fetch(req: Request) { return new Response('ok'); }
}
