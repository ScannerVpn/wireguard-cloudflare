// ═══════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════

const WARP_API      = 'https://api.cloudflareclient.com';
const WARP_VER      = 'v0a2158';
const SERVER_PUBKEY = 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=';
const DEFAULT_EP    = '162.159.192.1:2408';

// Only WARP-specific subnets — broader CDN ranges (104.x, 172.64.x) don't serve WARP UDP
const CF_RANGES = [
  { id:'r1',  cidr:'162.159.192.0/24', total:254, warp:true  },
  { id:'r2',  cidr:'162.159.193.0/24', total:254, warp:true  },
  { id:'r3',  cidr:'162.159.195.0/24', total:254, warp:true  },
  { id:'r4',  cidr:'162.159.197.0/24', total:254, warp:true  },
  { id:'r5',  cidr:'162.159.204.0/24', total:254, warp:true  },
  { id:'r6',  cidr:'188.114.96.0/24',  total:254, warp:true  },
  { id:'r7',  cidr:'188.114.97.0/24',  total:254, warp:true  },
  { id:'r8',  cidr:'188.114.98.0/24',  total:254, warp:true  },
  { id:'r9',  cidr:'188.114.99.0/24',  total:254, warp:true  },
  { id:'r10', cidr:'162.159.160.0/24', total:254, warp:true  },
  { id:'r11', cidr:'172.64.0.0/24',    total:254, warp:false },
  { id:'r12', cidr:'172.65.0.0/24',    total:254, warp:false },
  { id:'r13', cidr:'104.16.0.0/24',    total:254, warp:false },
  { id:'r14', cidr:'104.17.0.0/24',    total:254, warp:false },
  { id:'r15', cidr:'104.18.0.0/24',    total:254, warp:false },
];

const CF_PORTS = [
  { port:2408,  label:'WireGuard',      udp:true  },
  { port:443,   label:'HTTPS',          udp:false },
  { port:8443,  label:'HTTPS Alt',      udp:false },
  { port:2096,  label:'CloudFlare Alt', udp:false },
  { port:1701,  label:'L2TP',           udp:false },
  { port:500,   label:'IKE/IPsec',      udp:false },
  { port:4500,  label:'IPsec NAT-T',    udp:false },
  { port:7156,  label:'Warp Alt',       udp:false },
  { port:51820, label:'WG Default',     udp:true  },
];

// ═══════════════════════════════════════════════════════════════════
// CRYPTO
// ═══════════════════════════════════════════════════════════════════

function toB64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
function toB64URL(b64) {
  return b64.replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
async function generateKeyPair() {
  const kp    = await crypto.subtle.generateKey({ name:'X25519' }, true, ['deriveKey','deriveBits']);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
  const pub   = new Uint8Array(await crypto.subtle.exportKey('raw',   kp.publicKey));
  return { privateKey: toB64(pkcs8.slice(-32)), publicKey: toB64(pub) };
}

// ═══════════════════════════════════════════════════════════════════
// WARP API
// ═══════════════════════════════════════════════════════════════════

async function warpRegister(publicKey) {
  const iid = crypto.randomUUID().replace(/-/g,'').slice(0,22);
  const res  = await fetch(`${WARP_API}/${WARP_VER}/reg`, {
    method: 'POST',
    headers: { 'Content-Type':'application/json', 'User-Agent':'okhttp/3.12.1' },
    body: JSON.stringify({ key:publicKey, install_id:iid, fcm_token:'',
      tos:new Date().toISOString(), model:'PC', serial_number:iid, locale:'en_US' }),
  });
  if (!res.ok) throw new Error(`WARP: ${res.status} — ${await res.text()}`);
  return res.json();
}

async function warpApplyLicense(deviceId, token, license) {
  const res = await fetch(`${WARP_API}/${WARP_VER}/reg/${deviceId}/account`, {
    method: 'PUT',
    headers: { 'Content-Type':'application/json', 'Authorization':`Bearer ${token}`, 'User-Agent':'okhttp/3.12.1' },
    body: JSON.stringify({ license }),
  });
  if (!res.ok) throw new Error(`License: ${res.status} — ${await res.text()}`);
  return res.json();
}

// ═══════════════════════════════════════════════════════════════════
// CONFIG BUILDERS
// ═══════════════════════════════════════════════════════════════════

function epParts(ep) {
  const i = ep.lastIndexOf(':');
  return i > 0 ? { host:ep.slice(0,i), port:parseInt(ep.slice(i+1))||2408 } : { host:ep, port:2408 };
}

// Decode base64 client_id → [b0, b1, b2] for reserved bytes
function clientIdToBytes(clientId) {
  if (!clientId) return [0, 0, 0];
  try {
    const raw = atob(clientId);
    return [raw.charCodeAt(0)||0, raw.charCodeAt(1)||0, raw.charCodeAt(2)||0];
  } catch { return [0, 0, 0]; }
}

function buildWG(cfg, ep) {
  const reserved = cfg.clientId ? `\n# WARP-Reserved = ${cfg.clientId}` : '';
  return `[Interface]
PrivateKey = ${cfg.privateKey}
Address = ${cfg.ipv4}/32, ${cfg.ipv6}
DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111
MTU = 1280${reserved}

[Peer]
PublicKey = ${cfg.serverPublicKey || SERVER_PUBKEY}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${ep || cfg.endpoint || DEFAULT_EP}
PersistentKeepalive = 25
`;
}

function buildAmnezia(cfg, ep) {
  const reserved = cfg.clientId ? `\nReserved = ${cfg.clientId}` : '';
  return `[Interface]
PrivateKey = ${cfg.privateKey}
Address = ${cfg.ipv4}/32, ${cfg.ipv6}
DNS = 1.1.1.1, 1.0.0.1
MTU = 1280
Jc = 120
Jmin = 23
Jmax = 47
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4${reserved}

[Peer]
PublicKey = ${cfg.serverPublicKey || SERVER_PUBKEY}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${ep || cfg.endpoint || DEFAULT_EP}
PersistentKeepalive = 25
`;
}

function buildSingBox(cfg, ep) {
  const { host, port } = epParts(ep || cfg.endpoint || DEFAULT_EP);
  const reserved = clientIdToBytes(cfg.clientId);
  return JSON.stringify({
    outbounds: [{ type:'wireguard', tag:'WARP',
      address:[`${cfg.ipv4}/32`, cfg.ipv6], private_key:cfg.privateKey,
      peers:[{ server:host, server_port:port,
        public_key:cfg.serverPublicKey||SERVER_PUBKEY,
        allowed_ips:['0.0.0.0/0','::/0'], reserved }],
      mtu:1280 }],
  }, null, 2);
}

function buildURI(cfg, ep, name = 'WARP') {
  const { host, port } = epParts(ep || cfg.endpoint || DEFAULT_EP);
  const prv  = toB64URL(cfg.privateKey);
  const pub  = toB64URL(cfg.serverPublicKey || SERVER_PUBKEY);
  const addr = encodeURIComponent(`${cfg.ipv4}/32,${cfg.ipv6}`);
  // reserved is critical for WARP — v2rayNG/xray reads this
  const rsv  = cfg.clientId ? `&reserved=${encodeURIComponent(cfg.clientId)}` : '';
  return `wireguard://${prv}@${host}:${port}?publickey=${pub}&address=${addr}&dns=1.1.1.1&mtu=1280${rsv}#${encodeURIComponent(name)}`;
}

// ═══════════════════════════════════════════════════════════════════
// CONFIG PARSER (for import)
// ═══════════════════════════════════════════════════════════════════

function parseWGConfig(text) {
  const r = { privateKey:'', serverPublicKey:'', endpoint:'', ipv4:'', ipv6:'' };
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('[')) continue;
    const eqIdx = line.indexOf('=');
    if (eqIdx < 0) continue;
    const key = line.slice(0, eqIdx).trim();
    const val = line.slice(eqIdx + 1).trim();
    if (key === 'PrivateKey') r.privateKey = val;
    if (key === 'PublicKey')  r.serverPublicKey = val;
    if (key === 'Endpoint')   r.endpoint = val;
    if (key === 'Address') {
      for (const a of val.split(',')) {
        const t = a.trim();
        if (t.includes('.')) r.ipv4 = t.split('/')[0];
        else r.ipv6 = t;
      }
    }
  }
  return r;
}

// ═══════════════════════════════════════════════════════════════════
// STORAGE
// ═══════════════════════════════════════════════════════════════════

async function kvSave(env, record) {
  if (!env.CONFIGS) return;
  await env.CONFIGS.put(`cfg:${record.id}`, JSON.stringify(record), { expirationTtl:86400*30 });
  let list = [];
  try { list = JSON.parse(await env.CONFIGS.get('__list') || '[]'); } catch {}
  list = list.filter(x => x.id !== record.id);
  list.unshift({ id:record.id, name:record.name, accountType:record.accountType, createdAt:record.createdAt });
  await env.CONFIGS.put('__list', JSON.stringify(list.slice(0,100)));
}

async function dbSave(env, r) {
  if (!env.DB) return;
  try {
    const ct = buildWG(r, r.endpoint || DEFAULT_EP);
    await env.DB.prepare(`
      INSERT INTO configs (id,config_text,private_key,public_key,ipv4,ipv6,warp_account_id,created_at,
        name,device_id,device_token,server_public_key,endpoint,account_type,license_key,updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET config_text=excluded.config_text,name=excluded.name,
        device_token=excluded.device_token,server_public_key=excluded.server_public_key,
        endpoint=excluded.endpoint,account_type=excluded.account_type,
        license_key=excluded.license_key,updated_at=excluded.updated_at
    `).bind(r.id,ct,r.privateKey,r.publicKey,r.ipv4,r.ipv6,r.deviceId||'',r.createdAt,
            r.name||'',r.deviceId||'',r.deviceToken||'',r.serverPublicKey||'',
            r.endpoint||DEFAULT_EP,r.accountType||'Free',r.licenseKey||'',r.updatedAt||r.createdAt).run();
  } catch(e) { console.error('D1 save error (non-fatal):', e.message); }
}

async function saveConfig(env, record) {
  await kvSave(env, record);   // KV is primary — must succeed
  await dbSave(env, record);   // D1 is backup — errors are non-fatal
}

async function loadConfig(env, id) {
  if (env.CONFIGS) {
    const raw = await env.CONFIGS.get(`cfg:${id}`);
    if (raw) return JSON.parse(raw);
  }
  if (env.DB) {
    const row = await env.DB.prepare('SELECT * FROM configs WHERE id=?').bind(id).first();
    if (row) return rowToRecord(row);
  }
  return null;
}

async function listConfigs(env) {
  if (env.CONFIGS) {
    const raw = await env.CONFIGS.get('__list');
    if (raw) {
      const list = JSON.parse(raw);
      if (list.length > 0) return list;
    }
    // Rebuild list from KV prefix scan
    try {
      const { keys } = await env.CONFIGS.list({ prefix:'cfg:', limit:100 });
      if (keys.length > 0) {
        const items = [];
        for (const k of keys) {
          const r = await env.CONFIGS.get(k.name);
          if (r) {
            const p = JSON.parse(r);
            items.push({ id:p.id, name:p.name, accountType:p.accountType, createdAt:p.createdAt });
          }
        }
        items.sort((a,b) => b.createdAt - a.createdAt);
        await env.CONFIGS.put('__list', JSON.stringify(items));
        return items;
      }
    } catch(e) { console.error('KV list rebuild failed:', e.message); }
  }
  if (env.DB) {
    const { results } = await env.DB.prepare(
      'SELECT id,name,account_type,created_at FROM configs ORDER BY created_at DESC LIMIT 100'
    ).all();
    return results.map(r => ({ id:r.id, name:r.name||'WARP Profile', accountType:r.account_type||'Free', createdAt:r.created_at }));
  }
  return [];
}

async function deleteConfig(env, id) {
  if (env.CONFIGS) {
    await env.CONFIGS.delete(`cfg:${id}`);
    await env.CONFIGS.delete(`cleanips:${id}`);
    let list = [];
    try { list = JSON.parse(await env.CONFIGS.get('__list') || '[]'); } catch {}
    await env.CONFIGS.put('__list', JSON.stringify(list.filter(x => x.id !== id)));
  }
  if (env.DB) await env.DB.prepare('DELETE FROM configs WHERE id=?').bind(id).run().catch(()=>{});
}

function rowToRecord(r) {
  return {
    id:r.id, name:r.name||'WARP Profile', deviceId:r.device_id||'', deviceToken:r.device_token||'',
    privateKey:r.private_key, publicKey:r.public_key||'', serverPublicKey:r.server_public_key||SERVER_PUBKEY,
    ipv4:r.ipv4||'172.16.0.2', ipv6:r.ipv6||'fd01:5ca1:ab1e::2/128', endpoint:r.endpoint||DEFAULT_EP,
    accountType:r.account_type||'Free', licenseKey:r.license_key||'',
    createdAt:r.created_at, updatedAt:r.updated_at||r.created_at,
  };
}

// ═══════════════════════════════════════════════════════════════════
// ROUTER
// ═══════════════════════════════════════════════════════════════════

const CORS = {
  'Access-Control-Allow-Origin':'*',
  'Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers':'Content-Type',
};

export default {
  async fetch(request, env) {
    const { pathname:p, searchParams } = new URL(request.url);
    const m = request.method;
    if (m === 'OPTIONS') return new Response(null, { headers:CORS });

    try {
      // SPA
      if (p === '/' && m === 'GET') return html(getSPA(CF_RANGES, CF_PORTS));

      // GET /api/configs
      if (p === '/api/configs' && m === 'GET') return ok(await listConfigs(env));

      // POST /api/generate
      if (p === '/api/generate' && m === 'POST') {
        const { privateKey, publicKey } = await generateKeyPair();
        const wd   = await warpRegister(publicKey);
        const res  = wd.result ?? wd;
        const cfg  = res.config ?? {};
        const peer = (cfg.peers??[])[0]??{};
        const addr = cfg.interface?.addresses??{};
        const list = await listConfigs(env);
        const id   = crypto.randomUUID().replace(/-/g,'').slice(0,14);
        const rec  = {
          id, name:`WARP-Profile-${list.length+1} (Free)`,
          deviceId:res.id??'', deviceToken:res.token??'',
          privateKey, publicKey,
          serverPublicKey:peer.public_key??SERVER_PUBKEY,
          clientId:cfg.client_id??'',   // reserved bytes for WireGuard handshake
          ipv4:(addr.v4??'172.16.0.2').split('/')[0],
          ipv6:addr.v6??'fd01:5ca1:ab1e::2/128',
          endpoint:peer.endpoint?.host??DEFAULT_EP,
          accountType:'Free', licenseKey:'',
          createdAt:Date.now(), updatedAt:Date.now(),
        };
        await saveConfig(env, rec);
        return ok({ id, name:rec.name, success:true });
      }

      // POST /api/import
      if (p === '/api/import' && m === 'POST') {
        const { configText, name } = await request.json();
        const parsed = parseWGConfig(configText || '');
        if (!parsed.privateKey) return err('کانفیگ معتبر نیست — PrivateKey یافت نشد', 400);
        const list = await listConfigs(env);
        const id   = crypto.randomUUID().replace(/-/g,'').slice(0,14);
        const rec  = {
          id, name:name||`Imported-Profile-${list.length+1}`,
          deviceId:'', deviceToken:'',
          privateKey:parsed.privateKey, publicKey:'',
          serverPublicKey:parsed.serverPublicKey||SERVER_PUBKEY,
          ipv4:parsed.ipv4||'172.16.0.2',
          ipv6:parsed.ipv6||'fd01:5ca1:ab1e::2/128',
          endpoint:parsed.endpoint||DEFAULT_EP,
          accountType:'Imported', licenseKey:'',
          createdAt:Date.now(), updatedAt:Date.now(),
        };
        await saveConfig(env, rec);
        return ok({ id, name:rec.name, success:true });
      }

      // GET /sub/:id  — multi-config subscription
      const subMatch = p.match(/^\/sub\/([a-zA-Z0-9]+)$/);
      if (subMatch && m === 'GET') {
        const rec = await loadConfig(env, subMatch[1]);
        if (!rec) return err('not found', 404);
        let cleanIPs = [];
        if (env.CONFIGS) {
          const raw = await env.CONFIGS.get(`cleanips:${subMatch[1]}`);
          if (raw) cleanIPs = JSON.parse(raw);
        }
        let uris;
        if (cleanIPs.length > 0) {
          uris = cleanIPs.map((ci, i) =>
            buildURI(rec, `${ci.ip}:${ci.port}`, `${rec.name}-${i+1}`)
          );
        } else {
          uris = [buildURI(rec, rec.endpoint||DEFAULT_EP, rec.name)];
        }
        const encoded = btoa(uris.join('\n'));
        return new Response(encoded, { headers:{ ...CORS, 'Content-Type':'text/plain; charset=utf-8',
          'Profile-Title': encodeURIComponent(rec.name) } });
      }

      // /api/config/:id/*
      const idMatch = p.match(/^\/api\/config\/([a-zA-Z0-9]+)(?:\/(.+))?$/);
      if (idMatch) {
        const [, id, sub] = idMatch;

        if (!sub && m === 'DELETE') { await deleteConfig(env, id); return ok({ success:true }); }
        if (!sub && m === 'GET') { const r=await loadConfig(env,id); return r?ok(r):err('not found',404); }

        if (sub && m === 'GET') {
          const rec = await loadConfig(env, id);
          if (!rec) return err('not found', 404);
          const ep = searchParams.get('ep') || rec.endpoint || DEFAULT_EP;
          if (sub==='wg')       return txt(buildWG(rec,ep));
          if (sub==='amnezia')  return txt(buildAmnezia(rec,ep));
          if (sub==='singbox')  return txt(buildSingBox(rec,ep),'application/json');
          if (sub==='uri')      return ok({ uri:buildURI(rec,ep,rec.name) });
          if (sub==='download') return new Response(buildWG(rec,ep), {
            headers:{...CORS,'Content-Type':'text/plain',
              'Content-Disposition':`attachment; filename="warp-${id}.conf"`}});
          if (sub==='cleanips') {
            const raw = env.CONFIGS ? await env.CONFIGS.get(`cleanips:${id}`) : null;
            return ok(raw ? JSON.parse(raw) : []);
          }
        }

        if (sub==='endpoint' && m==='PUT') {
          const { endpoint } = await request.json();
          const rec = await loadConfig(env, id);
          if (!rec) return err('not found', 404);
          rec.endpoint = endpoint; rec.updatedAt = Date.now();
          await saveConfig(env, rec);
          return ok({ success:true, endpoint });
        }

        if (sub==='rename' && m==='PUT') {
          const { name } = await request.json();
          const rec = await loadConfig(env, id);
          if (!rec) return err('not found', 404);
          rec.name = name; rec.updatedAt = Date.now();
          await saveConfig(env, rec);
          return ok({ success:true });
        }

        if (sub==='license' && m==='POST') {
          const { license } = await request.json();
          const rec = await loadConfig(env, id);
          if (!rec) return err('not found', 404);
          if (!rec.deviceId||!rec.deviceToken) return err('device info missing', 400);
          const result  = await warpApplyLicense(rec.deviceId, rec.deviceToken, license);
          const acct    = (result.result??result).account??{};
          rec.licenseKey  = license;
          rec.accountType = acct.account_type==='plus'?'Plus':'Free';
          rec.name        = rec.name.replace(/\((Free|Plus|Imported)\)/,`(${rec.accountType})`);
          rec.updatedAt   = Date.now();
          await saveConfig(env, rec);
          return ok({ success:true, accountType:rec.accountType, name:rec.name });
        }

        if (sub==='cleanips' && m==='POST') {
          const { ips } = await request.json();
          if (env.CONFIGS) {
            await env.CONFIGS.put(`cleanips:${id}`, JSON.stringify(ips), { expirationTtl:86400*30 });
          }
          return ok({ success:true, count:ips.length });
        }
      }

      return err('not found', 404);
    } catch(e) {
      console.error(e.stack??e.message);
      return err(e.message, 500);
    }
  },
};

const html = b => new Response(b, { headers:{...CORS,'Content-Type':'text/html;charset=utf-8'} });
const txt  = (b,ct='text/plain') => new Response(b, { headers:{...CORS,'Content-Type':ct} });
const ok   = d => new Response(JSON.stringify(d), { headers:{...CORS,'Content-Type':'application/json'} });
const err  = (msg,s=500) => new Response(JSON.stringify({error:msg}), { status:s, headers:{...CORS,'Content-Type':'application/json'} });

// ═══════════════════════════════════════════════════════════════════
// SPA
// ═══════════════════════════════════════════════════════════════════

function getSPA(ranges, ports) {
  const R = JSON.stringify(ranges);
  const P = JSON.stringify(ports);
  return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>پنل WireGuard WARP</title>
<style>
:root{--bg:#0d0d1a;--bg2:#131325;--bg3:#1a1a30;--border:#252540;--accent:#f97316;--accent2:#ea580c;--blue:#3b82f6;--green:#22c55e;--red:#ef4444;--yellow:#eab308;--text:#e2e8f0;--text2:#94a3b8;--text3:#64748b;--r:10px}
*{box-sizing:border-box;margin:0;padding:0;scrollbar-width:thin;scrollbar-color:var(--border) var(--bg)}
body{font-family:'Segoe UI',Tahoma,Arial,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;font-size:14px}
a{color:var(--accent);text-decoration:none}
.header{background:var(--bg2);border-bottom:1px solid var(--border);padding:10px 20px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.header-brand{display:flex;align-items:center;gap:10px}
.brand-title{font-size:1rem;font-weight:700;color:var(--text)}
.brand-sub{font-size:.72rem;color:var(--text3)}
.header-links{display:flex;gap:14px;align-items:center}
.header-links a{color:var(--text2);font-size:.8rem;display:flex;align-items:center;gap:4px;transition:.2s}
.header-links a:hover{color:var(--accent)}
.main{max-width:1000px;margin:0 auto;padding:20px 14px;display:flex;flex-direction:column;gap:16px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r);overflow:hidden}
.card-head{padding:12px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
.card-head h2{font-size:.9rem;font-weight:600;display:flex;align-items:center;gap:8px}
.card-body{padding:16px}
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border:none;border-radius:7px;cursor:pointer;font-size:.83rem;font-family:inherit;transition:.15s;white-space:nowrap;text-decoration:none}
.btn:disabled{opacity:.5;cursor:default}
.btn-accent{background:var(--accent);color:#fff}.btn-accent:hover:not(:disabled){background:var(--accent2)}
.btn-blue{background:var(--blue);color:#fff}.btn-blue:hover:not(:disabled){background:#2563eb}
.btn-green{background:var(--green);color:#fff}.btn-green:hover:not(:disabled){background:#16a34a}
.btn-red{background:var(--red);color:#fff}.btn-red:hover:not(:disabled){background:#dc2626}
.btn-ghost{background:transparent;border:1px solid var(--border);color:var(--text2)}.btn-ghost:hover:not(:disabled){border-color:var(--accent);color:var(--accent)}
.btn-sm{padding:5px 10px;font-size:.78rem}.btn-xs{padding:3px 8px;font-size:.73rem}
.inp{width:100%;padding:8px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:.85rem;font-family:inherit;outline:none;transition:.15s}
.inp:focus{border-color:var(--accent)}
.inp-row{display:flex;gap:8px;align-items:stretch}
.inp-row .inp{flex:1}
.lbl{display:block;font-size:.78rem;color:var(--text2);margin-bottom:4px}
.account-list{display:flex;flex-direction:column;gap:6px}
.account-item{display:flex;align-items:center;gap:10px;padding:10px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:8px;cursor:pointer;transition:.15s}
.account-item:hover{border-color:var(--accent)}
.account-item.active{border-color:var(--accent);background:#f9731610}
.account-name{flex:1;font-size:.85rem;font-weight:500}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.68rem;font-weight:600}
.badge-free{background:#1e293b;color:var(--text2)}.badge-plus{background:var(--accent);color:#fff}.badge-imp{background:#1e3a5f;color:#60a5fa}
.acct-actions{display:flex;gap:6px;opacity:0;transition:.15s}
.account-item:hover .acct-actions{opacity:1}
.ep-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
@media(max-width:540px){.ep-grid{grid-template-columns:1fr}}
.ep-btn{padding:8px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;cursor:pointer;text-align:right;transition:.15s;font-family:inherit;color:var(--text)}
.ep-btn:hover,.ep-btn.active{border-color:var(--accent);background:#f9731610;color:var(--accent)}
.ep-host{font-size:.85rem;font-weight:600}.ep-port{font-size:.72rem;color:var(--text3);margin-top:2px}
.tabs{display:flex;gap:0;border-bottom:1px solid var(--border);overflow-x:auto}
.tab{padding:9px 16px;cursor:pointer;font-size:.82rem;color:var(--text2);border-bottom:2px solid transparent;margin-bottom:-1px;transition:.15s;white-space:nowrap}
.tab:hover{color:var(--text)}.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.config-pre{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;font-size:.78rem;color:#86efac;font-family:'Courier New',monospace;white-space:pre;overflow-x:auto;min-height:100px;line-height:1.7}
.config-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.config-meta{margin-top:8px;font-size:.75rem;color:var(--text3)}
.setting-row{display:flex;align-items:center;gap:12px;padding:8px 0}
.setting-row+.setting-row{border-top:1px solid var(--border)}
.setting-label{width:80px;font-size:.8rem;color:var(--text2);flex-shrink:0}
.dns-opts{display:flex;gap:8px;flex-wrap:wrap}
.dns-opt{padding:5px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:6px;cursor:pointer;font-size:.78rem;color:var(--text2);transition:.15s}
.dns-opt.active{border-color:var(--blue);color:var(--blue);background:#3b82f610}
input[type=range]{flex:1;accent-color:var(--accent);cursor:pointer}
.range-val{min-width:36px;text-align:center;font-size:.8rem;color:var(--accent);font-weight:600}
.scan-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:600px){.scan-grid{grid-template-columns:1fr}}
.check-list{display:flex;flex-direction:column;gap:5px;max-height:280px;overflow-y:auto}
.check-item{display:flex;align-items:center;gap:8px;padding:6px 10px;background:var(--bg3);border:1px solid var(--border);border-radius:6px;cursor:pointer;transition:.15s;user-select:none}
.check-item:hover{border-color:var(--accent)}
.check-item.checked{border-color:var(--accent);background:#f9731610}
.check-mark{width:16px;height:16px;border:2px solid var(--border);border-radius:4px;display:flex;align-items:center;justify-content:center;flex-shrink:0;transition:.15s}
.check-item.checked .check-mark{background:var(--accent);border-color:var(--accent)}
.check-mark::after{content:'✓';color:#fff;font-size:10px;line-height:1;display:none}
.check-item.checked .check-mark::after{display:block}
.check-text{font-size:.8rem;flex:1;line-height:1.4}
.check-sub{font-size:.7rem;color:var(--text3);display:block}
.scan-controls{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:12px}
.sel-btns{display:flex;gap:4px}
.results-wrap{overflow-x:auto;margin-top:14px}
.results-table{width:100%;border-collapse:collapse;font-size:.8rem}
.results-table th{background:var(--bg3);padding:8px 10px;text-align:right;color:var(--text2);font-weight:600;border-bottom:2px solid var(--border);white-space:nowrap}
.results-table td{padding:7px 10px;border-bottom:1px solid var(--border)}
.results-table tr:hover td{background:#ffffff06}
.latency-bar{display:flex;align-items:center;gap:8px}
.latency-num{min-width:52px;font-weight:600;font-size:.8rem}
.latency-bg{flex:1;background:var(--bg3);border-radius:4px;height:5px;min-width:60px}
.latency-fill{height:100%;border-radius:4px}
.lat-good{color:var(--green)}.lat-mid{color:var(--yellow)}.lat-bad{color:var(--red)}
.status-dot{width:8px;height:8px;border-radius:50%;display:inline-block;flex-shrink:0}
.dot-ok{background:var(--green)}.dot-err{background:var(--red)}
.scan-progress{margin-top:10px;background:var(--bg3);border-radius:6px;height:6px;overflow:hidden}
.scan-progress-fill{height:100%;background:var(--accent);border-radius:6px;transition:width .2s}
.sub-url-box{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px 14px;font-family:monospace;font-size:.8rem;color:var(--blue);word-break:break-all;direction:ltr;text-align:left}
.modal-overlay{display:none;position:fixed;inset:0;background:#00000099;z-index:200;align-items:center;justify-content:center}
.modal-overlay.show{display:flex}
.modal{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:24px;max-width:380px;width:92%}
.modal h3{font-size:.95rem;margin-bottom:16px}
#qr-canvas{background:#fff;padding:8px;border-radius:8px;display:inline-block;margin:0 auto;display:flex;justify-content:center}
.spin{display:inline-block;width:14px;height:14px;border:2px solid currentColor;border-top-color:transparent;border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle;flex-shrink:0}
@keyframes spin{to{transform:rotate(360deg)}}
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#1e293b;color:var(--text);padding:10px 22px;border-radius:8px;font-size:.83rem;z-index:300;border:1px solid var(--border);transition:.25s;opacity:0;pointer-events:none;white-space:nowrap}
.toast.show{opacity:1}
.empty{text-align:center;color:var(--text3);padding:24px;font-size:.85rem}
.info-badge{display:inline-flex;align-items:center;gap:4px;padding:3px 8px;background:var(--bg3);border:1px solid var(--border);border-radius:6px;font-size:.75rem;color:var(--text2)}
.divider{border:none;border-top:1px solid var(--border);margin:12px 0}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.hidden{display:none!important}
.scan-counter{font-size:.82rem;color:var(--text2);font-weight:500;padding:6px 10px;background:var(--bg3);border-radius:6px;min-width:160px}
textarea.inp{min-height:160px;resize:vertical;font-family:monospace;font-size:.78rem}
</style>
</head>
<body>

<div class="header">
  <div class="header-brand">
    <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#f97316" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    <div>
      <div class="brand-title">پنل کانفیگ وایرگارد کلادفلر WARP</div>
      <div class="brand-sub">تولید سریع و مدیریت کانفیگ‌های وایرگارد با استفاده از کلادفلر</div>
    </div>
  </div>
  <div class="header-links">
    <a href="https://github.com/ScannerVpn/wireguard-cloudflare" target="_blank">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.44 9.8 8.2 11.39.6.11.82-.26.82-.58l-.01-2.03c-3.34.72-4.04-1.61-4.04-1.61-.55-1.39-1.34-1.76-1.34-1.76-1.09-.75.08-.73.08-.73 1.2.08 1.84 1.24 1.84 1.24 1.07 1.83 2.8 1.3 3.49 1 .1-.78.42-1.3.76-1.6-2.67-.3-5.47-1.33-5.47-5.93 0-1.31.47-2.38 1.24-3.22-.13-.3-.54-1.52.12-3.18 0 0 1.01-.32 3.3 1.23A11.5 11.5 0 0 1 12 5.8c1.02 0 2.04.14 3 .4 2.28-1.55 3.29-1.23 3.29-1.23.66 1.66.25 2.88.12 3.18.77.84 1.24 1.91 1.24 3.22 0 4.61-2.81 5.63-5.48 5.92.43.37.81 1.1.81 2.22l-.01 3.29c0 .32.21.7.82.58C20.56 21.8 24 17.31 24 12c0-6.63-5.37-12-12-12z"/></svg>
      GitHub
    </a>
    <a href="#" onclick="toggleDir();return false" id="dirBtn">English</a>
  </div>
</div>

<div class="main">

  <!-- ACCOUNTS -->
  <div class="card">
    <div class="card-head">
      <h2>👤 مدیریت حساب‌ها</h2>
      <div class="row">
        <button class="btn btn-accent" id="genBtn" onclick="generateAccount()">
          <span id="genSpin" class="spin hidden"></span>
          + تولید اکانت جدید
        </button>
        <button class="btn btn-ghost" onclick="openImport()">
          ↓ وارد کردن اکانت
        </button>
      </div>
    </div>
    <div class="card-body">
      <div id="accountList" class="account-list">
        <div class="empty"><span class="spin"></span> در حال بارگذاری…</div>
      </div>
    </div>
  </div>

  <!-- WARP+ LICENSE -->
  <div class="card">
    <div class="card-head">
      <h2>⭐ ارتقا به WARP Plus</h2>
      <span class="info-badge" id="acctTypeBadge">انتخاب حساب</span>
    </div>
    <div class="card-body">
      <label class="lbl">دریافت لایسنس پلاس:</label>
      <div class="inp-row">
        <input class="inp" id="licenseInput" placeholder="XXXXX-XXXXX-XXXXX" style="direction:ltr;letter-spacing:1px">
        <button class="btn btn-accent" onclick="applyLicense()">
          <span id="licSpin" class="spin hidden"></span>
          اعمال لایسنس
        </button>
      </div>
      <p style="font-size:.75rem;color:var(--text3);margin-top:6px">لایسنس WARP+ را از اپ Cloudflare 1.1.1.1 دریافت کنید (Referral)</p>
    </div>
  </div>

  <!-- ENDPOINT -->
  <div class="card">
    <div class="card-head">
      <h2>📍 انتخاب نقطه پایانی (Endpoint)</h2>
      <span class="info-badge" id="curEpBadge">—</span>
    </div>
    <div class="card-body">
      <div class="ep-grid" id="epGrid"></div>
      <hr class="divider">
      <label class="lbl">آی‌پی / Endpoint سفارشی:</label>
      <div class="inp-row">
        <input class="inp" id="customEp" placeholder="162.159.192.1:2408" style="direction:ltr">
        <button class="btn btn-blue" onclick="applyCustomEp()">
          <span id="epSpin" class="spin hidden"></span>
          اعمال آی‌پی
        </button>
      </div>
    </div>
  </div>

  <!-- DNS & MTU -->
  <div class="card">
    <div class="card-head"><h2>⚙️ تنظیمات پیشرفته (DNS & MTU)</h2></div>
    <div class="card-body">
      <div class="setting-row">
        <span class="setting-label">سرور DNS</span>
        <div class="dns-opts">
          <div class="dns-opt active" data-dns="1.1.1.1, 1.0.0.1, 2606:4700:4700::1111" onclick="setDns(this)">Cloudflare (1.1.1.1)</div>
          <div class="dns-opt" data-dns="8.8.8.8, 8.8.4.4" onclick="setDns(this)">Google (8.8.8.8)</div>
          <div class="dns-opt" data-dns="9.9.9.9, 149.112.112.112" onclick="setDns(this)">Quad9</div>
          <div class="dns-opt" data-dns="94.140.14.14, 94.140.15.15" onclick="setDns(this)">AdGuard</div>
        </div>
      </div>
      <div class="setting-row">
        <span class="setting-label">MTU Size</span>
        <input type="range" min="1000" max="1500" value="1280" step="10" id="mtuSlider" oninput="mtuVal.textContent=this.value;renderConfig()">
        <span class="range-val" id="mtuVal">1280</span>
      </div>
    </div>
  </div>

  <!-- CONFIG OUTPUT -->
  <div class="card">
    <div class="card-head">
      <h2>🔑 کانفیگ‌های آماده شده</h2>
      <span class="info-badge" id="configStatus">بدون انتخاب</span>
    </div>
    <div class="tabs" id="fmtTabs">
      <div class="tab active" data-fmt="wg"      onclick="switchFmt(this)">WireGuard Standard</div>
      <div class="tab"       data-fmt="amnezia"  onclick="switchFmt(this)">AmneziaWG (DPI Bypass)</div>
      <div class="tab"       data-fmt="singbox"  onclick="switchFmt(this)">Sing-Box JSON</div>
      <div class="tab"       data-fmt="sub"      onclick="switchFmt(this)">ساب‌اسکریپشن / URI</div>
    </div>
    <div class="card-body">
      <div id="noConfigMsg" class="empty">ابتدا یک حساب انتخاب یا تولید کنید</div>
      <div id="configOutput" class="hidden">
        <pre class="config-pre" id="configPre">—</pre>
        <div class="config-actions" id="configActions">
          <button class="btn btn-green btn-sm"  onclick="copyConfig()">📋 کپی</button>
          <button class="btn btn-blue btn-sm"   onclick="downloadConfig()">⬇ دانلود .conf</button>
          <button class="btn btn-ghost btn-sm"  onclick="showQR()">📱 QR کد</button>
          <button class="btn btn-ghost btn-sm"  onclick="copyURI()" id="copyURIBtn">🔗 کپی URI</button>
        </div>
        <div class="config-meta" id="configMeta"></div>
        <!-- Sub URL box (shown only in sub tab) -->
        <div id="subBox" class="hidden" style="margin-top:12px">
          <label class="lbl">لینک اشتراک (Subscription URL) — در اپ وارد کنید:</label>
          <div class="sub-url-box" id="subURL"></div>
          <div class="row" style="margin-top:10px">
            <button class="btn btn-green btn-sm" onclick="copySubURL()">📋 کپی لینک اشتراک</button>
            <button class="btn btn-ghost btn-sm" onclick="saveToSub()">💾 ذخیره آی‌پی‌های اسکن‌شده در ساب</button>
            <span id="subIPCount" style="font-size:.75rem;color:var(--text3)"></span>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- IP SCANNER -->
  <div class="card">
    <div class="card-head">
      <h2>🔍 اسکن آی‌پی تمیز کلادفلر</h2>
      <span id="scanCounter" class="scan-counter hidden">۰ / ۰</span>
    </div>
    <div class="card-body">
      <div class="scan-grid">
        <!-- Ports LEFT -->
        <div>
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <span style="font-size:.8rem;color:var(--text2);font-weight:600">انتخاب پورت‌ها:</span>
            <div class="sel-btns">
              <button class="btn btn-ghost btn-xs" onclick="selectAllPorts(true)">همه</button>
              <button class="btn btn-ghost btn-xs" onclick="selectAllPorts(false)">هیچ</button>
            </div>
          </div>
          <div class="check-list" id="portList"></div>
        </div>
        <!-- Ranges RIGHT -->
        <div>
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <span style="font-size:.8rem;color:var(--text2);font-weight:600">انتخاب رنج‌های IP کلادفلر:</span>
            <div class="sel-btns">
              <button class="btn btn-ghost btn-xs" onclick="selectAllRanges(true)">همه</button>
              <button class="btn btn-ghost btn-xs" onclick="selectAllRanges(false)">هیچ</button>
            </div>
          </div>
          <div class="check-list" id="rangeList"></div>
        </div>
      </div>

      <div class="setting-row" style="margin-top:12px">
        <span class="setting-label" style="width:130px">تعداد آی‌پی هر رنج:</span>
        <input type="range" min="1" max="50" value="15" id="ipCount" oninput="ipCountVal.textContent=this.value">
        <span class="range-val" id="ipCountVal">15</span>
      </div>

      <div class="scan-controls">
        <button class="btn btn-accent" id="scanBtn" onclick="toggleScan()">
          🚀 شروع فرایند اسکن پیشرفته
        </button>
        <button class="btn btn-ghost btn-sm" onclick="clearScanResults()">🗑 پاک کردن نتایج</button>
      </div>

      <div class="scan-progress hidden" id="scanProgress" style="margin-top:10px">
        <div class="scan-progress-fill" id="scanFill" style="width:0%"></div>
      </div>

      <div class="results-wrap">
        <div class="empty" id="noResults" style="margin-top:12px">نتایج اسکن اینجا نمایش داده می‌شوند.</div>
        <table class="results-table hidden" id="resultsTable">
          <thead>
            <tr>
              <th style="width:20px"></th>
              <th>آدرس IP</th>
              <th>پورت</th>
              <th>تاخیر</th>
              <th>وضعیت</th>
              <th>عملیات</th>
            </tr>
          </thead>
          <tbody id="resultsBody"></tbody>
        </table>
      </div>
    </div>
  </div>

</div>

<!-- QR Modal -->
<div class="modal-overlay" id="qrModal" onclick="if(event.target===this)closeQR()">
  <div class="modal" style="text-align:center">
    <h3 style="margin-bottom:14px">اسکن کد QR کانفیگ</h3>
    <div id="qr-canvas"></div>
    <div style="font-size:.75rem;color:var(--text3);margin-top:8px" id="qrSub"></div>
    <div style="margin-top:14px;display:flex;gap:8px;justify-content:center">
      <button class="btn btn-ghost btn-sm" id="qrAmnezia" onclick="qrToggle('amnezia')">Amnezia</button>
      <button class="btn btn-ghost btn-sm" id="qrStd" onclick="qrToggle('standard')">Standard</button>
      <button class="btn btn-red btn-sm" onclick="closeQR()">بستن</button>
    </div>
  </div>
</div>

<!-- Import Modal -->
<div class="modal-overlay" id="importModal" onclick="if(event.target===this)closeImport()">
  <div class="modal">
    <h3>وارد کردن کانفیگ WireGuard</h3>
    <label class="lbl" style="margin-top:8px">نام پروفایل (اختیاری):</label>
    <input class="inp" id="importName" placeholder="مثال: WARP-Custom" style="margin-bottom:10px">
    <label class="lbl">متن کانفیگ WireGuard را اینجا paste کنید:</label>
    <textarea class="inp" id="importText" placeholder="[Interface]&#10;PrivateKey = ...&#10;..."></textarea>
    <div style="display:flex;gap:8px;margin-top:14px">
      <button class="btn btn-accent" onclick="doImport()" style="flex:1">
        <span id="importSpin" class="spin hidden"></span>
        وارد کردن
      </button>
      <button class="btn btn-ghost" onclick="closeImport()">لغو</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const CF_RANGES = ${R};
const CF_PORTS  = ${P};

// ─── STATE ────────────────────────────────────────────────────────────────────
const S = {
  configs: [],
  current: null,
  fmt: 'wg',
  ep: '',
  dns: '1.1.1.1, 1.0.0.1, 2606:4700:4700::1111',
  mtu: 1280,
  selectedRanges: new Set(CF_RANGES.filter(r => r.warp).map(r => r.id)),
  selectedPorts:  new Set([443, 8443, 2096]),
  scanning: false,
  scanResults: [],   // all ok results
  allScanResults: [], // for sub saving
};

// ─── INIT ─────────────────────────────────────────────────────────────────────
(async () => {
  buildPortList();
  buildRangeList();
  buildEpGrid();
  await loadConfigs();
  if (S.configs.length > 0) await selectConfig(S.configs[0].id);
})();

// ─── ACCOUNTS ─────────────────────────────────────────────────────────────────
async function loadConfigs() {
  const data = await api('/api/configs');
  S.configs = Array.isArray(data) ? data : [];
  renderAccountList();
}

function renderAccountList() {
  const el = document.getElementById('accountList');
  if (!S.configs.length) {
    el.innerHTML = '<div class="empty">هیچ حسابی یافت نشد — یک حساب جدید تولید کنید</div>';
    return;
  }
  el.innerHTML = S.configs.map(c => {
    const bClass = c.accountType==='Plus'?'badge-plus':c.accountType==='Imported'?'badge-imp':'badge-free';
    return \`<div class="account-item \${S.current?.id===c.id?'active':''}" onclick="selectConfig('\${c.id}')">
      <div class="account-name">\${esc(c.name||'WARP Profile')}</div>
      <span class="badge \${bClass}">\${c.accountType||'Free'}</span>
      <div class="acct-actions" onclick="event.stopPropagation()">
        <button class="btn btn-ghost btn-xs" onclick="renameConfig('\${c.id}','\${esc(c.name||'')}')">✏️</button>
        <button class="btn btn-red btn-xs"   onclick="deleteConfig('\${c.id}')">🗑</button>
      </div>
    </div>\`;
  }).join('');
}

async function generateAccount() {
  const btn  = document.getElementById('genBtn');
  const spin = document.getElementById('genSpin');
  btn.disabled = true; spin.classList.remove('hidden');
  try {
    const d = await api('/api/generate', 'POST');
    if (d.error) return toast('خطا: ' + d.error, true);
    toast('✅ ' + d.name + ' ساخته شد');
    await loadConfigs();
    await selectConfig(d.id);
  } catch(e) { toast('خطا: ' + e.message, true); }
  finally { btn.disabled=false; spin.classList.add('hidden'); }
}

async function selectConfig(id) {
  const rec = await api('/api/config/' + id);
  if (rec.error) return toast('بارگذاری ناموفق: ' + rec.error, true);
  S.current = rec;
  S.ep = rec.endpoint || DEFAULT_EP;
  document.getElementById('curEpBadge').textContent = S.ep;
  document.getElementById('customEp').value = S.ep;
  document.getElementById('acctTypeBadge').textContent =
    rec.accountType==='Plus' ? '⭐ WARP Plus' : rec.accountType==='Imported' ? '📂 Imported' : 'رایگان (Free)';
  renderAccountList();
  updateEpGrid();
  await renderConfig();
  document.getElementById('configStatus').textContent = rec.name;
}

async function deleteConfig(id) {
  if (!confirm('این حساب حذف شود؟')) return;
  await api('/api/config/' + id, 'DELETE');
  if (S.current?.id === id) {
    S.current = null;
    document.getElementById('configOutput').classList.add('hidden');
    document.getElementById('noConfigMsg').classList.remove('hidden');
    document.getElementById('configStatus').textContent = 'بدون انتخاب';
  }
  await loadConfigs();
  toast('حساب حذف شد');
}

async function renameConfig(id, old) {
  const name = prompt('نام جدید:', old);
  if (!name || name === old) return;
  await api('/api/config/' + id + '/rename', 'PUT', { name });
  await loadConfigs();
  if (S.current?.id === id) { S.current.name = name; await renderConfig(); }
  toast('نام تغییر کرد');
}

// ─── IMPORT ───────────────────────────────────────────────────────────────────
function openImport() {
  document.getElementById('importText').value = '';
  document.getElementById('importName').value = '';
  document.getElementById('importModal').classList.add('show');
}
function closeImport() { document.getElementById('importModal').classList.remove('show'); }

async function doImport() {
  const text = document.getElementById('importText').value.trim();
  const name = document.getElementById('importName').value.trim();
  if (!text) return toast('متن کانفیگ را وارد کنید', true);
  const spin = document.getElementById('importSpin');
  spin.classList.remove('hidden');
  try {
    const d = await api('/api/import', 'POST', { configText: text, name });
    if (d.error) return toast('خطا: ' + d.error, true);
    closeImport();
    toast('✅ کانفیگ وارد شد: ' + d.name);
    await loadConfigs();
    await selectConfig(d.id);
  } catch(e) { toast('خطا: ' + e.message, true); }
  finally { spin.classList.add('hidden'); }
}

// ─── LICENSE ──────────────────────────────────────────────────────────────────
async function applyLicense() {
  if (!S.current) return toast('ابتدا یک حساب انتخاب کنید', true);
  const key  = document.getElementById('licenseInput').value.trim();
  if (!key)   return toast('لایسنس را وارد کنید', true);
  const spin = document.getElementById('licSpin');
  spin.classList.remove('hidden');
  try {
    const res = await api('/api/config/' + S.current.id + '/license', 'POST', { license: key });
    if (res.error) return toast('خطا: ' + res.error, true);
    S.current.accountType = res.accountType; S.current.name = res.name;
    document.getElementById('acctTypeBadge').textContent = res.accountType==='Plus'?'⭐ WARP Plus':'رایگان';
    await loadConfigs(); toast('✅ لایسنس اعمال شد — ' + res.accountType);
  } catch(e) { toast('خطا: ' + e.message, true); }
  finally { spin.classList.add('hidden'); }
}

// ─── ENDPOINT ─────────────────────────────────────────────────────────────────
const PRESETS = [
  {host:'162.159.192.1',port:2408},{host:'162.159.193.1',port:2408},
  {host:'162.159.195.1',port:2408},{host:'188.114.96.1', port:2408},
  {host:'162.159.192.1',port:443}, {host:'162.159.193.1',port:443},
  {host:'162.159.192.1',port:8443},{host:'188.114.96.1', port:2096},
];
function buildEpGrid() {
  document.getElementById('epGrid').innerHTML = PRESETS.map(ep =>
    \`<button class="ep-btn" onclick="applyPresetEp('\${ep.host}:\${ep.port}')">
      <div class="ep-host">\${ep.host}</div><div class="ep-port">:\${ep.port}</div>
    </button>\`
  ).join('');
}
function updateEpGrid() {
  document.querySelectorAll('.ep-btn').forEach(b => {
    const e = b.querySelector('.ep-host').textContent + ':' + b.querySelector('.ep-port').textContent.slice(1);
    b.classList.toggle('active', e === S.ep);
  });
  document.getElementById('customEp').value = S.ep;
}
async function applyPresetEp(ep) { await doApplyEp(ep); }
async function applyCustomEp() { await doApplyEp(document.getElementById('customEp').value.trim()); }
async function doApplyEp(ep) {
  if (!S.current || !ep) return;
  const spin = document.getElementById('epSpin');
  spin.classList.remove('hidden');
  try {
    await api('/api/config/' + S.current.id + '/endpoint', 'PUT', { endpoint: ep });
    S.ep = ep; S.current.endpoint = ep;
    document.getElementById('curEpBadge').textContent = ep;
    updateEpGrid(); await renderConfig(); toast('Endpoint اعمال شد');
  } catch(e) { toast('خطا: ' + e.message, true); }
  finally { spin.classList.add('hidden'); }
}

// ─── DNS/MTU ──────────────────────────────────────────────────────────────────
function setDns(el) {
  document.querySelectorAll('.dns-opt').forEach(d => d.classList.remove('active'));
  el.classList.add('active'); S.dns = el.dataset.dns; renderConfig();
}

// ─── CONFIG OUTPUT ────────────────────────────────────────────────────────────
function switchFmt(el) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  el.classList.add('active'); S.fmt = el.dataset.fmt; renderConfig();
}

const DEFAULT_EP = '162.159.192.1:2408';

async function renderConfig() {
  if (!S.current) return;
  document.getElementById('configOutput').classList.remove('hidden');
  document.getElementById('noConfigMsg').classList.add('hidden');
  document.getElementById('configStatus').textContent = S.current.name;

  const pre     = document.getElementById('configPre');
  const subBox  = document.getElementById('subBox');
  const actBtns = document.getElementById('configActions');
  const ep      = S.ep || S.current.endpoint || DEFAULT_EP;
  const fmt     = S.fmt;

  subBox.classList.add('hidden');
  actBtns.classList.remove('hidden');

  if (fmt === 'sub') {
    pre.textContent = '';
    subBox.classList.remove('hidden');
    actBtns.classList.add('hidden');
    const subUrl = location.origin + '/sub/' + S.current.id;
    document.getElementById('subURL').textContent = subUrl;
    // Show saved clean IP count
    const saved = await api('/api/config/' + S.current.id + '/cleanips');
    document.getElementById('subIPCount').textContent =
      Array.isArray(saved) && saved.length ? saved.length + ' آی‌پی تمیز ذخیره شده' : 'هنوز آی‌پی تمیز ذخیره نشده';
    document.getElementById('configMeta').textContent = 'این URL را در اپ VPN به عنوان Subscription وارد کنید';
    return;
  }

  const url = \`/api/config/\${S.current.id}/\${fmt}?ep=\${encodeURIComponent(ep)}\`;
  let text = await fetch(url).then(r => r.text());
  // Apply DNS and MTU overrides
  text = text.replace(/^DNS = .+/m, 'DNS = ' + S.dns).replace(/^MTU = .+/m, 'MTU = ' + S.mtu);
  pre.textContent = text;
  document.getElementById('configMeta').textContent =
    \`IPv4: \${S.current.ipv4}  |  IPv6: \${(S.current.ipv6||'').split('/')[0]}  |  Endpoint: \${ep}\`;
}

async function copyConfig() {
  await navigator.clipboard.writeText(document.getElementById('configPre').textContent);
  toast('✅ کپی شد');
}
async function copyURI() {
  if (!S.current) return;
  const ep  = S.ep || S.current.endpoint || DEFAULT_EP;
  const res = await api('/api/config/' + S.current.id + '/uri?ep=' + encodeURIComponent(ep));
  await navigator.clipboard.writeText(res.uri || '');
  toast('✅ URI کپی شد');
}
function copySubURL() {
  const url = location.origin + '/sub/' + (S.current?.id || '');
  navigator.clipboard.writeText(url);
  toast('✅ لینک اشتراک کپی شد');
}
async function saveToSub() {
  if (!S.current) return toast('ابتدا یک حساب انتخاب کنید', true);
  const good = S.allScanResults.filter(r => r.ok);
  if (!good.length) return toast('ابتدا اسکن را اجرا کنید و آی‌پی‌های تمیز پیدا کنید', true);
  const ips = good.map(r => ({ ip: r.ip, port: r.port }));
  const res = await api('/api/config/' + S.current.id + '/cleanips', 'POST', { ips });
  if (res.error) return toast('خطا: ' + res.error, true);
  document.getElementById('subIPCount').textContent = ips.length + ' آی‌پی تمیز ذخیره شده';
  toast('✅ ' + ips.length + ' آی‌پی تمیز در ساب ذخیره شد');
}
function downloadConfig() {
  if (!S.current) return;
  const ep  = S.ep || S.current.endpoint || DEFAULT_EP;
  const a   = document.createElement('a');
  a.href    = '/api/config/' + S.current.id + '/download?ep=' + encodeURIComponent(ep);
  a.download= 'warp-' + S.current.id + '.conf';
  a.click();
}

// ─── QR ───────────────────────────────────────────────────────────────────────
let qrMode = 'standard';
async function showQR() {
  if (!S.current) return toast('ابتدا یک حساب انتخاب کنید', true);
  document.getElementById('qrModal').classList.add('show');
  await renderQR();
}
async function renderQR() {
  const ep = S.ep || S.current.endpoint || DEFAULT_EP;
  const fmt = qrMode === 'amnezia' ? 'amnezia' : 'wg';
  const text = await fetch('/api/config/' + S.current.id + '/' + fmt + '?ep=' + encodeURIComponent(ep)).then(r => r.text());
  const el = document.getElementById('qr-canvas');
  el.innerHTML = '';
  document.getElementById('qrSub').textContent = qrMode === 'amnezia' ? 'AmneziaWG — برای اپ Amnezia' : 'WireGuard Standard';
  try {
    new QRCode(el, { text, width:200, height:200, correctLevel:QRCode.CorrectLevel.M });
  } catch { el.innerHTML = '<p style="color:red;font-size:.8rem">متن کانفیگ خیلی طولانی است</p>'; }
}
function qrToggle(mode) {
  qrMode = mode;
  document.getElementById('qrAmnezia').classList.toggle('btn-accent', mode==='amnezia');
  document.getElementById('qrStd').classList.toggle('btn-accent', mode==='standard');
  renderQR();
}
function closeQR() { document.getElementById('qrModal').classList.remove('show'); }

// ─── SCANNER ──────────────────────────────────────────────────────────────────
function ipToNum(ip) {
  return ip.split('.').reduce((a,o) => (a*256 + parseInt(o,10))>>>0, 0);
}
function numToIp(n) {
  return [(n>>>24)&255,(n>>>16)&255,(n>>>8)&255,n&255].join('.');
}
function cidrIPs(cidr, count) {
  const [base, pStr] = cidr.split('/');
  const hBits = 32 - parseInt(pStr,10);
  const size  = Math.pow(2, hBits) - 2;
  const baseN = ipToNum(base);
  const set   = new Set();
  let   tries = 0;
  while (set.size < Math.min(count, size) && tries < count*5) {
    tries++;
    set.add(numToIp(((baseN + Math.floor(Math.random()*size) + 1)>>>0)));
  }
  return [...set];
}

function buildPortList() {
  document.getElementById('portList').innerHTML = CF_PORTS.map(p =>
    \`<div class="check-item \${S.selectedPorts.has(p.port)?'checked':''}" id="port_\${p.port}" onclick="togglePort(\${p.port})">
      <div class="check-mark"></div>
      <div class="check-text">
        <span>\${p.label}</span>
        <span class="check-sub" style="direction:ltr">\${p.port} \${p.udp?'⚡UDP':'TCP'}</span>
      </div>
    </div>\`
  ).join('');
}
function buildRangeList() {
  document.getElementById('rangeList').innerHTML = CF_RANGES.map(r =>
    \`<div class="check-item \${S.selectedRanges.has(r.id)?'checked':''}" id="range_\${r.id}" onclick="toggleRange('\${r.id}')">
      <div class="check-mark"></div>
      <div class="check-text">
        <span style="direction:ltr;display:inline-block">\${r.cidr}
          \${r.warp?'<span style="color:var(--accent);font-size:.65rem;margin-right:4px">WARP✓</span>':''}
        </span>
        <span class="check-sub" style="direction:ltr">\${r.total.toLocaleString()} IPs</span>
      </div>
    </div>\`
  ).join('');
}
function toggleRange(id) {
  S.selectedRanges.has(id) ? S.selectedRanges.delete(id) : S.selectedRanges.add(id);
  document.getElementById('range_'+id)?.classList.toggle('checked', S.selectedRanges.has(id));
}
function togglePort(port) {
  S.selectedPorts.has(port) ? S.selectedPorts.delete(port) : S.selectedPorts.add(port);
  document.getElementById('port_'+port)?.classList.toggle('checked', S.selectedPorts.has(port));
}
function selectAllRanges(v) {
  CF_RANGES.forEach(r => { v?S.selectedRanges.add(r.id):S.selectedRanges.delete(r.id); document.getElementById('range_'+r.id)?.classList.toggle('checked',v); });
}
function selectAllPorts(v) {
  CF_PORTS.forEach(p => { v?S.selectedPorts.add(p.port):S.selectedPorts.delete(p.port); document.getElementById('port_'+p.port)?.classList.toggle('checked',v); });
}

let scanAborted = false;

async function toggleScan() {
  if (S.scanning) {
    scanAborted = true;
    S.scanning  = false;
    document.getElementById('scanBtn').textContent = '🚀 شروع فرایند اسکن پیشرفته';
    document.getElementById('scanProgress').classList.add('hidden');
    document.getElementById('scanCounter').classList.add('hidden');
    return;
  }

  const ranges = CF_RANGES.filter(r => S.selectedRanges.has(r.id));
  const ports  = CF_PORTS.filter(p => S.selectedPorts.has(p.port));
  const count  = parseInt(document.getElementById('ipCount').value, 10);

  if (!ranges.length) return toast('حداقل یک رنج IP انتخاب کنید', true);
  if (!ports.length)  return toast('حداقل یک پورت انتخاب کنید', true);

  // Build tasks
  const tasks = [];
  for (const range of ranges) {
    for (const ip of cidrIPs(range.cidr, count)) {
      for (const p of ports) tasks.push({ ip, port:p.port, udp:p.udp });
    }
  }

  S.scanning      = true;
  scanAborted     = false;
  S.scanResults   = [];
  S.allScanResults= [];

  document.getElementById('scanBtn').textContent    = '⏹ توقف اسکن';
  document.getElementById('scanProgress').classList.remove('hidden');
  document.getElementById('scanFill').style.width   = '0%';
  document.getElementById('scanCounter').classList.remove('hidden');
  document.getElementById('scanCounter').textContent= '0 / ' + tasks.length;
  document.getElementById('noResults').classList.add('hidden');
  document.getElementById('resultsTable').classList.remove('hidden');
  document.getElementById('resultsBody').innerHTML  = '';

  let done = 0;
  const CONCURRENCY = 12;
  const queue = [...tasks];

  async function worker() {
    while (queue.length && !scanAborted) {
      const task = queue.shift();
      if (!task) break;

      const res = await probeIP(task.ip, task.port, task.udp);
      S.allScanResults.push(res);
      if (res.ok) S.scanResults.push(res);
      done++;

      // Update progress
      document.getElementById('scanFill').style.width = Math.round(done/tasks.length*100) + '%';
      document.getElementById('scanCounter').textContent =
        done + ' / ' + tasks.length + ' — ' + S.scanResults.length + ' فعال';

      if (res.ok) addResultRow(res);
    }
  }

  await Promise.all(Array.from({length:CONCURRENCY}, worker));

  S.scanning = false;
  document.getElementById('scanBtn').textContent    = '🚀 شروع فرایند اسکن پیشرفته';
  document.getElementById('scanProgress').classList.add('hidden');

  if (S.scanResults.length === 0) {
    document.getElementById('noResults').textContent  = 'هیچ آی‌پی فعالی یافت نشد. پورت‌های HTTPS (443, 8443, 2096) را انتخاب کنید.';
    document.getElementById('noResults').classList.remove('hidden');
  }
  sortResults();
  toast('✅ اسکن پایان یافت — ' + S.scanResults.length + ' آی‌پی فعال از ' + done + ' اسکن‌شده');
}

// Probe using XMLHttpRequest — works across all browsers without AbortSignal issues
function probeIP(ip, port, isUDP) {
  const testPort = isUDP ? 443 : port;
  const useHttps = [443, 8443, 2096, 7156].includes(testPort);
  const proto    = useHttps ? 'https' : 'http';
  const url      = proto + '://' + ip + ':' + testPort + '/cdn-cgi/trace';

  return new Promise(resolve => {
    const xhr   = new XMLHttpRequest();
    const start = performance.now();
    let done    = false;

    const finish = (ok) => {
      if (done) return;
      done = true;
      xhr.abort();
      const lat = Math.round(performance.now() - start);
      resolve({ ip, port, latency:ok?lat:(lat<50?lat:9999), ok });
    };

    const timer = setTimeout(() => finish(false), 3000);

    xhr.open('GET', url, true);
    xhr.timeout = 3000;

    xhr.onload = () => { clearTimeout(timer); finish(true); };
    xhr.onerror = () => {
      clearTimeout(timer);
      const elapsed = Math.round(performance.now() - start);
      // Fast error = server responded (TLS mismatch, HTTP error) = IP reachable
      // Slow error = timeout / no route = IP blocked
      finish(elapsed < 2400);
    };
    xhr.ontimeout = () => { clearTimeout(timer); finish(false); };

    try { xhr.send(); } catch(e) { clearTimeout(timer); finish(false); }
  });
}

function addResultRow(r) {
  const latClass = r.latency < 100 ? 'lat-good' : r.latency < 400 ? 'lat-mid' : 'lat-bad';
  const barW     = Math.min(100, Math.round(r.latency / 500 * 100));
  const barColor = r.latency < 100 ? '#22c55e' : r.latency < 400 ? '#eab308' : '#ef4444';
  const tr       = document.createElement('tr');
  tr.innerHTML   = \`
    <td><span class="status-dot dot-ok"></span></td>
    <td style="font-family:monospace;direction:ltr">\${r.ip}</td>
    <td style="direction:ltr">\${r.port}</td>
    <td>
      <div class="latency-bar">
        <span class="latency-num \${latClass}">\${r.latency}ms</span>
        <div class="latency-bg"><div class="latency-fill" style="width:\${barW}%;background:\${barColor}"></div></div>
      </div>
    </td>
    <td><span style="color:var(--green);font-size:.8rem">✓ فعال</span></td>
    <td>
      <button class="btn btn-blue btn-xs" onclick="applyScannedIP('\${r.ip}',\${r.port})">اعمال</button>
      <button class="btn btn-ghost btn-xs" onclick="copySingle('\${r.ip}',\${r.port})">کپی</button>
    </td>\`;
  document.getElementById('resultsBody').appendChild(tr);
}

function sortResults() {
  const tbody = document.getElementById('resultsBody');
  [...tbody.querySelectorAll('tr')].sort((a,b) => {
    const la = parseInt(a.querySelector('.latency-num')?.textContent)||9999;
    const lb = parseInt(b.querySelector('.latency-num')?.textContent)||9999;
    return la - lb;
  }).forEach(r => tbody.appendChild(r));
}

async function applyScannedIP(ip, port) {
  await doApplyEp(ip + ':' + port);
  toast('✅ ' + ip + ':' + port + ' اعمال شد');
}
function copySingle(ip, port) {
  navigator.clipboard.writeText(ip + ':' + port);
  toast('کپی شد: ' + ip + ':' + port);
}
function clearScanResults() {
  S.scanResults = []; S.allScanResults = [];
  document.getElementById('resultsBody').innerHTML = '';
  document.getElementById('resultsTable').classList.add('hidden');
  document.getElementById('noResults').textContent = 'نتایج اسکن اینجا نمایش داده می‌شوند.';
  document.getElementById('noResults').classList.remove('hidden');
  document.getElementById('scanCounter').classList.add('hidden');
}

// ─── UTILS ────────────────────────────────────────────────────────────────────
async function api(url, method='GET', body) {
  const opts = { method, headers:{'Content-Type':'application/json'} };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  return res.json();
}
function esc(s) { return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function toast(msg, isErr=false) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.background = isErr ? '#7f1d1d' : '#1e293b';
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3000);
}
function toggleDir() {
  const h = document.documentElement;
  h.dir = h.dir==='rtl'?'ltr':'rtl';
  document.getElementById('dirBtn').textContent = h.dir==='rtl'?'English':'فارسی';
}
</script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js" crossorigin="anonymous"></script>
</body>
</html>`;
}
