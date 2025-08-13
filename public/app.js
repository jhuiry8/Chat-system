
const API = location.origin;
let token = localStorage.getItem('token') || '';
let currentGuild = null;
let currentChannel = null;
let ws = null;

// Auth
async function register() {
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  const r = await fetch(API + '/api/register', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({email, password, display_name: email.split('@')[0]}) });
  const j = await r.json();
  if (j.ok) alert('Registered, now Login');
  else alert(j.error || 'register failed');
}

async function login() {
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  const r = await fetch(API + '/api/login', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({email, password}) });
  const j = await r.json();
  if (j.token) {
    token = j.token;
    localStorage.setItem('token', token);
    await refreshGuilds();
    alert('Logged in');
  } else alert(j.error || 'login failed');
}

// Guilds & Channels
async function refreshGuilds() {
  const r = await fetch(API + '/api/guilds', { headers: { 'authorization': 'Bearer ' + token } });
  const j = await r.json();
  const ul = document.getElementById('guilds'); ul.innerHTML = '';
  j.guilds.forEach(g => {
    const li = document.createElement('li');
    li.textContent = g.name;
    li.onclick = () => { currentGuild = g.id; refreshChannels(); };
    ul.appendChild(li);
  });
}

async function createGuild() {
  const name = document.getElementById('guildName').value;
  const r = await fetch(API + '/api/guilds', { method:'POST', headers: {'content-type':'application/json','authorization':'Bearer '+token}, body: JSON.stringify({name}) });
  await refreshGuilds();
}

async function refreshChannels() {
  const r = await fetch(API + `/api/guilds/${currentGuild}/channels`, { headers: { 'authorization':'Bearer '+token } });
  const j = await r.json();
  const ul = document.getElementById('channels'); ul.innerHTML = '';
  j.channels.forEach(c => {
    const li = document.createElement('li');
    li.textContent = `${c.name} (${c.kind})`;
    li.onclick = () => enterChannel(c.id, c.kind);
    ul.appendChild(li);
  });
}

async function createChannel() {
  const name = document.getElementById('channelName').value;
  const kind = document.getElementById('channelKind').value;
  await fetch(API + `/api/guilds/${currentGuild}/channels`, { method:'POST', headers:{'content-type':'application/json','authorization':'Bearer '+token}, body: JSON.stringify({name, kind}) });
  refreshChannels();
}

// Invites
async function makeInvite() {
  const r = await fetch(API + `/api/guilds/${currentGuild}/invites`, { method:'POST', headers:{'authorization':'Bearer '+token}});
  const j = await r.json();
  prompt('Invite code (share this):', j.code);
}

async function joinInvite() {
  const code = document.getElementById('inviteCode').value.trim();
  await fetch(API + `/api/invites/${code}/accept`, { method:'POST', headers:{'authorization':'Bearer '+token}});
  await refreshGuilds();
}

// Text chat
function log(msg, cls='') {
  const div = document.createElement('div');
  div.className = 'msg ' + cls;
  div.textContent = msg;
  document.getElementById('messages').appendChild(div);
  div.scrollIntoView();
}

async function enterChannel(channelId, kind) {
  currentChannel = channelId;
  document.getElementById('currentChannel').textContent = channelId;
  if (ws) { ws.close(); ws = null; }
  if (kind === 'text') {
    const url = API.replace('http','ws') + `/ws/channel/${channelId}` + `?token=${encodeURIComponent(token)}`;
    ws = new WebSocket(url);
    ws.onopen = () => log('[connected]', 'system');
    ws.onmessage = (ev) => {
      const data = JSON.parse(ev.data);
      if (data.type === 'chat') log(`${data.author}: ${data.content}`);
      if (data.type === 'system') log(`[${data.text}]`, 'system');
    };
    ws.onclose = () => log('[disconnected]', 'system');
  }
}

async function sendMessage() {
  if (!ws) return;
  const content = document.getElementById('content').value;
  ws.send(JSON.stringify({ type:'chat', content }));
  document.getElementById('content').value='';
}

// File upload via presigned URL
async function sendFile() {
  const f = document.getElementById('fileInput').files[0];
  if (!f || !currentChannel) return alert('choose file & channel');
  const r = await fetch(API + `/api/channels/${currentChannel}/attachments/presign`, {
    method:'POST',
    headers: {'authorization':'Bearer '+token, 'content-type':'application/json'},
    body: JSON.stringify({ filename: f.name, type: f.type })
  });
  const j = await r.json();
  await fetch(j.url, { method: 'PUT', headers: {'content-type': f.type}, body: f });
  // notify message with URL
  await fetch(API + `/api/channels/${currentChannel}/messages`, {
    method:'POST', headers:{'content-type':'application/json','authorization':'Bearer '+token},
    body: JSON.stringify({ attachment_url: j.publicUrl })
  });
}

// Simple voice via Realtime SFU
let pc = null;
async function joinVoice() {
  if (!currentChannel) return alert('select a voice channel');
  // Get token for SFU room from backend (placeholder)
  const r = await fetch(API + `/api/voice/${currentChannel}/token`, { headers: { 'authorization':'Bearer '+token }});
  const j = await r.json();
  // Create RTCPeerConnection towards Cloudflare Realtime SFU
  pc = new RTCPeerConnection();
  const micSelect = document.getElementById('micSelect');
  const devices = await navigator.mediaDevices.enumerateDevices();
  micSelect.innerHTML = '';
  devices.filter(d => d.kind==='audioinput').forEach(d => {
    const opt = document.createElement('option');
    opt.value = d.deviceId; opt.textContent = d.label || 'Mic';
    micSelect.appendChild(opt);
  });
  const stream = await navigator.mediaDevices.getUserMedia({ audio: { deviceId: micSelect.value || undefined } });
  stream.getTracks().forEach(t => pc.addTrack(t, stream));

  const remoteAudio = document.getElementById('remoteAudio');
  pc.ontrack = (ev) => { remoteAudio.srcObject = ev.streams[0]; };

  // Data channel (optional presence)
  pc.createDataChannel('presence');

  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);

  // Send SDP to backend which talks to Realtime SFU
  const sfu = await fetch(API + `/api/voice/${currentChannel}/negotiate`, {
    method:'POST', headers:{'content-type':'application/json','authorization':'Bearer '+token},
    body: JSON.stringify({ sdp: offer.sdp, type: offer.type, token: j.token })
  }).then(r => r.json());

  await pc.setRemoteDescription(sfu);
}

function leaveVoice() {
  if (pc) { pc.close(); pc = null; }
}

document.getElementById('register').onclick = register;
document.getElementById('login').onclick = login;
document.getElementById('createGuild').onclick = createGuild;
document.getElementById('createChannel').onclick = createChannel;
document.getElementById('makeInvite').onclick = makeInvite;
document.getElementById('joinInvite').onclick = joinInvite;
document.getElementById('send').onclick = sendMessage;
document.getElementById('sendFile').onclick = sendFile;
document.getElementById('joinVoice').onclick = joinVoice;
document.getElementById('leaveVoice').onclick = leaveVoice;
