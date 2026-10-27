import { createServer } from 'node:http';
import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { mkdir, readFile, rename, writeFile, chmod } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scrypt = promisify(scryptCallback);
const here = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(here, 'public');
const dataDir = path.resolve(process.env.DATA_DIR || path.join(here, 'data'));
const usersPath = path.join(dataDir, 'users.json');
const samplesPath = path.join(dataDir, 'samples.json');
const port = Number(process.env.PORT || 3000);
const production = process.env.NODE_ENV === 'production';
const maxBodyBytes = 40 * 1024 * 1024;
const sessionTtlMs = 8 * 60 * 60 * 1000;
const sessions = new Map();
const loginAttempts = new Map();
let users = {};
let sampleStore = {};
let writeQueue = Promise.resolve();

function json(res, status, value, extraHeaders = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...extraHeaders });
  res.end(JSON.stringify(value));
}

function text(res, status, value, extraHeaders = {}) {
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...extraHeaders });
  res.end(value);
}

async function readJson(file, fallback) {
  try { return JSON.parse(await readFile(file, 'utf8')); }
  catch (err) { if (err.code === 'ENOENT') return fallback; throw err; }
}

async function writeJsonAtomic(file, value) {
  await mkdir(path.dirname(file), { recursive: true });
  const temp = `${file}.${process.pid}.${randomBytes(5).toString('hex')}.tmp`;
  await writeFile(temp, JSON.stringify(value), { encoding: 'utf8', mode: 0o600 });
  try { await chmod(temp, 0o600); } catch {}
  await rename(temp, file);
}

async function saveSamples() {
  writeQueue = writeQueue.then(() => writeJsonAtomic(samplesPath, sampleStore));
  return writeQueue;
}

async function passwordRecord(password) {
  const salt = randomBytes(16);
  const passwordHash = await scrypt(password, salt, 64);
  return { salt: salt.toString('hex'), passwordHash: Buffer.from(passwordHash).toString('hex') };
}

async function init() {
  await mkdir(dataDir, { recursive: true });
  users = await readJson(usersPath, {});
  sampleStore = await readJson(samplesPath, {});
  if (!users || typeof users !== 'object' || Array.isArray(users)) throw new Error('data/users.json 格式错误');
  if (!sampleStore || typeof sampleStore !== 'object' || Array.isArray(sampleStore)) throw new Error('data/samples.json 格式错误');
  const seedUsername = String(process.env.SEED_USERNAME || '').trim();
  const seedPassword = String(process.env.SEED_PASSWORD || '');
  if (seedUsername && seedPassword && !users[seedUsername]) {
    users[seedUsername] = await passwordRecord(seedPassword);
    await writeJsonAtomic(usersPath, users);
    console.log(`已创建初始账号：${seedUsername}`);
  }
  if (!Object.keys(users).length) console.warn('没有可登录账号。设置 SEED_USERNAME 与 SEED_PASSWORD 后重启服务器。');
}

function secureRequest(req) {
  return Boolean(req.socket.encrypted || req.headers['x-forwarded-proto'] === 'https');
}

function cookieValue(req, name) {
  const cookie = req.headers.cookie || '';
  for (const pair of cookie.split(';')) {
    const [key, ...value] = pair.trim().split('=');
    if (key === name) return decodeURIComponent(value.join('='));
  }
  return '';
}

function sessionUser(req) {
  const token = cookieValue(req, 'sample_progress_session');
  const record = sessions.get(token);
  if (!record) return null;
  if (record.expiresAt <= Date.now()) { sessions.delete(token); return null; }
  record.expiresAt = Date.now() + sessionTtlMs;
  return { username: record.username, token };
}

function sessionCookie(token, req) {
  const secure = production || secureRequest(req);
  return `sample_progress_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(sessionTtlMs / 1000)}${secure ? '; Secure' : ''}`;
}

function clearSessionCookie(req) {
  return `sample_progress_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${production || secureRequest(req) ? '; Secure' : ''}`;
}

function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    const parsed = new URL(origin);
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    const expectedProtocol = secureRequest(req) ? 'https:' : 'http:';
    return parsed.host === host && parsed.protocol === expectedProtocol;
  } catch { return false; }
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBodyBytes) throw Object.assign(new Error('请求内容过大'), { statusCode: 413 });
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw Object.assign(new Error('请求数据格式错误'), { statusCode: 400 }); }
}

function limited(ip) {
  const now = Date.now();
  const item = loginAttempts.get(ip) || { count: 0, until: now + 15 * 60 * 1000 };
  if (item.until <= now) { item.count = 0; item.until = now + 15 * 60 * 1000; }
  if (item.count >= 8) return true;
  item.count++;
  loginAttempts.set(ip, item);
  return false;
}

async function sendLogin(res) {
  const content = await readFile(path.join(publicDir, 'login.html'));
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin', 'X-Frame-Options': 'DENY' });
  res.end(content);
}

async function sendDashboard(res, req, username) {
  const file = await readFile(path.join(publicDir, 'dashboard.html'), 'utf8');
  const samples = Array.isArray(sampleStore[username]) ? sampleStore[username] : [];
  const safeJson = JSON.stringify(samples).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
  const script = `<script>window.__SAMPLE_PROGRESS_REMOTE__=true;window.__SAMPLE_PROGRESS_INITIAL_DATA__=${safeJson};window.__SAMPLE_PROGRESS_USERNAME__=${JSON.stringify(username)};window.__SAMPLE_PROGRESS_SYNC__=(()=>{let timer;return payload=>{clearTimeout(timer);const badge=document.getElementById('remoteSyncStatus');if(badge)badge.textContent='同步中…';timer=setTimeout(async()=>{try{const r=await fetch('/api/samples',{method:'PUT',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:payload});if(r.status===401){if(badge)badge.textContent='登录已过期';return}if(!r.ok)throw Error('sync failed');if(badge)badge.textContent='已同步'}catch(e){console.error(e);if(badge)badge.textContent='同步失败，请检查连接'}},400)}})();</script>`;
  const html = file.replace('</head>', '<style>.remote-sync{display:inline-flex;align-items:center;gap:7px;margin-left:10px;color:#7c97a9;font-size:11px}.remote-sync:before{content:"";width:7px;height:7px;border-radius:50%;background:#75c6a2}</style></head>')
    .replace('</header>', `<span class="remote-sync">在线：${username} · <span id="remoteSyncStatus">已连接</span> · <a href="/logout" style="color:#df7656">退出</a></span></header>`)
    .replace('<script>', `${script}<script>`);
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store, private', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin', 'X-Frame-Options': 'DENY', 'Content-Security-Policy': "default-src 'self' data: blob:; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" });
  res.end(html);
}

async function handle(req, res) {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;
  if (production && !secureRequest(req)) return text(res, 400, '生产环境必须通过 HTTPS 访问。');

  if (req.method === 'GET' && (pathname === '/' || pathname === '/login')) {
    const session = sessionUser(req);
    if (session) { res.writeHead(302, { Location: '/dashboard', 'Cache-Control': 'no-store' }); return res.end(); }
    return sendLogin(res);
  }

  if (req.method === 'POST' && pathname === '/api/login') {
    if (!sameOrigin(req)) return json(res, 403, { error: '请求来源无效' });
    if (limited(req.socket.remoteAddress || 'unknown')) return json(res, 429, { error: '尝试次数过多' });
    let body;
    try { body = await readBody(req); } catch (err) { return json(res, err.statusCode || 400, { error: err.message }); }
    const username = typeof body.username === 'string' ? body.username.trim() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    const record = users[username];
    let valid = false;
    if (record && typeof record.salt === 'string' && typeof record.passwordHash === 'string') {
      try {
        const actual = Buffer.from(await scrypt(password, Buffer.from(record.salt, 'hex'), 64));
        const expected = Buffer.from(record.passwordHash, 'hex');
        valid = actual.length === expected.length && timingSafeEqual(actual, expected);
      } catch { valid = false; }
    } else {
      await scrypt(password || 'invalid', Buffer.alloc(16, 1), 64);
    }
    if (!valid) return json(res, 401, { error: '账号或密码不正确' });
    const token = randomBytes(32).toString('base64url');
    sessions.set(token, { username, expiresAt: Date.now() + sessionTtlMs });
    loginAttempts.delete(req.socket.remoteAddress || 'unknown');
    return json(res, 200, { username }, { 'Set-Cookie': sessionCookie(token, req) });
  }

  if (req.method === 'POST' && pathname === '/api/logout') {
    if (!sameOrigin(req)) return json(res, 403, { error: '请求来源无效' });
    const session = sessionUser(req);
    if (session) sessions.delete(session.token);
    return json(res, 200, { ok: true }, { 'Set-Cookie': clearSessionCookie(req) });
  }

  const session = sessionUser(req);
  if (req.method === 'GET' && pathname === '/dashboard') {
    if (!session) { res.writeHead(302, { Location: '/login', 'Cache-Control': 'no-store' }); return res.end(); }
    return sendDashboard(res, req, session.username);
  }

  if (pathname.startsWith('/api/')) {
    if (!session) return json(res, 401, { error: '请先登录' });
    if (req.method !== 'GET' && !sameOrigin(req)) return json(res, 403, { error: '请求来源无效' });
    if (req.method === 'GET' && pathname === '/api/me') return json(res, 200, { username: session.username });
    if (req.method === 'GET' && pathname === '/api/samples') return json(res, 200, { samples: sampleStore[session.username] || [] });
    if (req.method === 'PUT' && pathname === '/api/samples') {
      let body;
      try { body = await readBody(req); } catch (err) { return json(res, err.statusCode || 400, { error: err.message }); }
      const samples = Array.isArray(body) ? body : body?.samples;
      if (!Array.isArray(samples) || samples.some(x => !x || typeof x !== 'object' || Array.isArray(x))) return json(res, 400, { error: '样品数据格式错误' });
      sampleStore[session.username] = samples;
      try { await saveSamples(); } catch (err) { console.error('样品数据保存失败', err); return json(res, 500, { error: '服务器保存失败' }); }
      return json(res, 200, { ok: true, count: samples.length });
    }
    return json(res, 404, { error: '接口不存在' });
  }

  if (req.method === 'GET' && pathname === '/logout') {
    if (session) sessions.delete(session.token);
    res.writeHead(302, { Location: '/login', 'Set-Cookie': clearSessionCookie(req), 'Cache-Control': 'no-store' });
    return res.end();
  }
  return text(res, 404, 'Not found');
}

await init();
const server = createServer((req, res) => {
  handle(req, res).catch(err => { console.error('请求处理失败', err); if (!res.headersSent) json(res, 500, { error: '服务器内部错误' }); else res.destroy(); });
});
server.listen(port, '0.0.0.0', () => console.log(`样品进度服务已启动，端口 ${port}`));

setInterval(() => { const now = Date.now(); for (const [token, session] of sessions) if (session.expiresAt <= now) sessions.delete(token); }, 10 * 60 * 1000).unref();

