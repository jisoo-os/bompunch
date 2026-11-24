'use strict';
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.SECRET || crypto.randomBytes(32).toString('hex'); // 미설정 시 재시작하면 로그인이 풀림
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const PUBLIC = path.join(__dirname, 'public');
const TOKEN_TTL = 14 * 24 * 3600 * 1000;

let pool = null;
if (process.env.DATABASE_URL) {
  const { Pool } = require('pg');
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.PGSSL === 'off' ? false : { rejectUnauthorized: false },
  });
}

/* ---------- 비밀번호/토큰 ---------- */
const hashPin = pin => { const s = crypto.randomBytes(8).toString('hex'); return `${s}$${crypto.scryptSync(String(pin), s, 32).toString('hex')}`; };
const checkPin = (pin, h) => {
  const [s, x] = String(h || '').split('$'); if (!s || !x) return false;
  const a = crypto.scryptSync(String(pin), s, 32), b = Buffer.from(x, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const b64 = b => Buffer.from(b).toString('base64url');
const sign = p => { const body = b64(JSON.stringify(p)); return `${body}.${crypto.createHmac('sha256', SECRET).update(body).digest('base64url')}`; };
function verify(t) {
  const [body, sig] = String(t || '').split('.'); if (!body || !sig) return null;
  const ok = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (sig.length !== ok.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(ok))) return null;
  try { const p = JSON.parse(Buffer.from(body, 'base64url')); return p.exp > Date.now() ? p : null; } catch { return null; }
}

/* ---------- 데이터 ---------- */
let db;
async function loadDb() {
  let d = null;
  if (pool) {
    await pool.query('create table if not exists kv (k text primary key, v jsonb not null)');
    const r = await pool.query("select v from kv where k='db'"); d = r.rows[0] && r.rows[0].v;
  } else if (fs.existsSync(DATA_FILE)) d = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  db = d || { settings: { name: '봄찬', lat: null, lng: null, radius: 150, minWage: 10320, adminPin: hashPin(process.env.ADMIN_PIN || '0000') }, workers: [], records: [] };
  if (!db.settings.tasks) { db.settings.tasks = DEFAULT_TASKS.map(newTask); save(); } // 기존 데이터에도 기본 작업 목록 추가
}
let chain = Promise.resolve();
function save() {
  const json = JSON.stringify(db);
  chain = chain.then(() => pool
    ? pool.query("insert into kv(k,v) values('db',$1) on conflict(k) do update set v=$1", [json])
    : fs.promises.writeFile(DATA_FILE, json)).catch(e => console.error('save failed', e));
  return chain;
}

/* ---------- 유틸 ---------- */
const kstDate = ts => new Date(ts + 9 * 3600e3).toISOString().slice(0, 10);
const dist = (a, b, c, d) => { const R = 6371000, t = x => x * Math.PI / 180, dl = t(c - a), dn = t(d - b);
  const h = Math.sin(dl / 2) ** 2 + Math.cos(t(a)) * Math.cos(t(c)) * Math.sin(dn / 2) ** 2; return 2 * R * Math.asin(Math.sqrt(h)); };
const E = (status, msg) => Object.assign(new Error(msg), { status });
const fails = new Map();
function throttle(ip) { const f = fails.get(ip); if (f && f.n >= 10 && Date.now() - f.t < 15 * 60e3) throw E(429, '시도가 너무 많습니다. 15분 뒤 다시 해주세요.'); }
function fail(ip) { const f = fails.get(ip); if (!f || Date.now() - f.t > 15 * 60e3) fails.set(ip, { n: 1, t: Date.now() }); else f.n++; }
const pubWorker = w => ({ id: w.id, name: w.name, wage: w.wage });
const validPin = p => /^\d{4,8}$/.test(String(p));
const DEFAULT_TASKS = ['롯데출고', '대신출고', '선작업', '용차/밀크런 출고', '밀크런', '밀크런 이슈', '쉽먼트', '용차 준비', '입고', '운영관리', '현장정비'];
const BREAK = { id: 'break', name: '휴게' };
const newTask = name => ({ id: 't' + crypto.randomBytes(5).toString('hex'), name });
const closeSeg = (r, t) => { const s = (r.segments || []).find(x => !x.end); if (s) s.end = t; };

function state(auth) {
  const s = db.settings;
  if (auth.role === 'admin') return { role: 'admin', settings: { name: s.name, radius: s.radius, minWage: s.minWage, hasLoc: s.lat != null }, tasks: s.tasks, workers: db.workers.map(pubWorker), records: db.records };
  const me = db.workers.find(w => w.id === auth.wid); if (!me) throw E(401, '계정을 찾을 수 없습니다.');
  return { role: 'worker', settings: { name: s.name, radius: s.radius, hasLoc: s.lat != null }, tasks: s.tasks, me: pubWorker(me), records: db.records.filter(r => r.wid === me.id) };
}

/* ---------- API ---------- */
async function api(req, url, body, ip) {
  const route = `${req.method} ${url.pathname}`;
  if (route === 'POST /api/login') {
    throttle(ip);
    let ok = null;
    if (body.admin) { if (checkPin(body.pin, db.settings.adminPin)) ok = { role: 'admin' }; }
    else { const w = db.workers.find(x => x.name === String(body.name || '').trim()); if (w && checkPin(body.pin, w.pin)) ok = { role: 'worker', wid: w.id }; }
    if (!ok) { fail(ip); throw E(401, '이름 또는 PIN이 올바르지 않습니다.'); }
    return { token: sign({ ...ok, exp: Date.now() + TOKEN_TTL }) };
  }
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || ''); const auth = m && verify(m[1]);
  if (!auth) throw E(401, '로그인이 필요합니다.');
  if (route === 'GET /api/state') return state(auth);

  if (route === 'POST /api/punch') {
    if (auth.role !== 'worker') throw E(403, '직원 계정만 사용할 수 있습니다.');
    const s = db.settings; let loc = null;
    if (s.lat != null) {
      const lat = Number(body.lat), lng = Number(body.lng);
      if (!isFinite(lat) || !isFinite(lng)) throw E(400, '위치 정보가 필요합니다.');
      const d = dist(lat, lng, s.lat, s.lng), acc = Math.min(Number(body.acc) || 0, 50);
      if (d - acc > s.radius) throw E(403, `근무지에서 ${Math.round(d)}m 떨어져 있어요. (허용 ${s.radius}m)`);
      loc = { lat, lng, d: Math.round(d) };
    }
    const now = Date.now(), open = db.records.find(r => r.wid === auth.wid && !r.out);
    if (body.kind === 'in') {
      if (open) throw E(409, '이미 출근 상태입니다.');
      db.records.push({ id: 'r' + crypto.randomBytes(6).toString('hex'), wid: auth.wid, date: kstDate(now), in: now, out: null, inLoc: loc, outLoc: null, manual: false, segments: [] });
    } else if (body.kind === 'out') {
      if (!open) throw E(409, '출근 기록이 없습니다.');
      closeSeg(open, now); open.out = now; open.outLoc = loc;
    } else throw E(400, '잘못된 요청입니다.');
    await save(); return { at: now };
  }

  if (route === 'POST /api/task') { // 작업 시작/전환 (taskId 'stop' 이면 작업 종료)
    if (auth.role !== 'worker') throw E(403, '직원 계정만 사용할 수 있습니다.');
    const open = db.records.find(r => r.wid === auth.wid && !r.out);
    if (!open) throw E(409, '먼저 출근해 주세요.');
    open.segments = open.segments || [];
    const cur = open.segments.find(x => !x.end), now = Date.now();
    if (body.taskId === 'stop') { if (!cur) throw E(409, '진행 중인 작업이 없습니다.'); closeSeg(open, now); await save(); return { at: now }; }
    const t = body.taskId === 'break' ? BREAK : db.settings.tasks.find(x => x.id === body.taskId);
    if (!t) throw E(404, '작업을 찾을 수 없습니다.');
    if (cur && cur.task === t.id) throw E(409, `이미 ${t.name} 중입니다.`);
    closeSeg(open, now); open.segments.push({ task: t.id, name: t.name, start: now, end: null });
    await save(); return { at: now };
  }

  if (auth.role !== 'admin') throw E(403, '권한이 없습니다.');
  let mm;
  if (route === 'POST /api/admin/tasks') {
    const name = String(body.name || '').trim();
    if (!name || name.length > 20 || name === BREAK.name) throw E(400, '작업 이름을 확인하세요. (20자 이내, "휴게"는 기본 제공)');
    if (db.settings.tasks.length >= 30) throw E(400, '작업은 최대 30개까지 만들 수 있습니다.');
    if (db.settings.tasks.some(t => t.name === name)) throw E(409, '같은 이름의 작업이 이미 있습니다.');
    db.settings.tasks.push(newTask(name)); await save(); return {};
  }
  if ((mm = /^DELETE \/api\/admin\/tasks\/(\w+)$/.exec(route))) {
    db.settings.tasks = db.settings.tasks.filter(t => t.id !== mm[1]); await save(); return {}; // 지난 기록은 작업 이름이 남아 있어 그대로 보임
  }
  if (route === 'POST /api/admin/workers') {
    const name = String(body.name || '').trim(), wage = parseInt(body.wage, 10);
    if (!name || name.length > 20 || !validPin(body.pin) || !(wage > 0)) throw E(400, '이름, PIN(숫자 4~8자리), 시급을 확인하세요.');
    if (db.workers.some(w => w.name === name)) throw E(409, '같은 이름의 직원이 이미 있습니다.');
    db.workers.push({ id: 'w' + crypto.randomBytes(6).toString('hex'), name, wage, pin: hashPin(body.pin) });
    await save(); return {};
  }
  if ((mm = /^(PATCH|DELETE) \/api\/admin\/workers\/(\w+)$/.exec(route))) {
    const w = db.workers.find(x => x.id === mm[2]); if (!w) throw E(404, '직원을 찾을 수 없습니다.');
    if (mm[1] === 'DELETE') { db.workers = db.workers.filter(x => x !== w); db.records = db.records.filter(r => r.wid !== w.id); }
    else {
      if (body.pin != null) { if (!validPin(body.pin)) throw E(400, 'PIN은 숫자 4~8자리입니다.'); w.pin = hashPin(body.pin); }
      if (body.wage != null) { const x = parseInt(body.wage, 10); if (!(x > 0)) throw E(400, '시급을 확인하세요.'); w.wage = x; }
    }
    await save(); return {};
  }
  if (route === 'POST /api/admin/records') { // 누락된 기록 수동 입력
    const w = db.workers.find(x => x.id === body.wid); if (!w) throw E(404, '직원을 선택하세요.');
    if (!/^\d{4}-\d{2}-\d{2}$/.test(body.date) || !/^\d{2}:\d{2}$/.test(body.in) || !/^\d{2}:\d{2}$/.test(body.out)) throw E(400, '날짜와 시간을 확인하세요.');
    const a = Date.parse(`${body.date}T${body.in}:00+09:00`); let b = Date.parse(`${body.date}T${body.out}:00+09:00`);
    if (isNaN(a) || isNaN(b)) throw E(400, '날짜와 시간을 확인하세요.'); if (b <= a) b += 86400e3;
    db.records.push({ id: 'r' + crypto.randomBytes(6).toString('hex'), wid: w.id, date: body.date, in: a, out: b, inLoc: null, outLoc: null, manual: true, segments: [] });
    await save(); return {};
  }
  if ((mm = /^DELETE \/api\/admin\/records\/(\w+)$/.exec(route))) {
    db.records = db.records.filter(r => r.id !== mm[1]); await save(); return {};
  }
  if (route === 'PUT /api/admin/settings') {
    const s = db.settings;
    if (body.name != null) s.name = String(body.name).trim().slice(0, 30) || '봄찬';
    if (body.radius != null) s.radius = Math.max(20, Math.min(5000, parseInt(body.radius, 10) || 150));
    if (body.minWage != null) s.minWage = parseInt(body.minWage, 10) || s.minWage;
    if (body.adminPin) { if (!validPin(body.adminPin)) throw E(400, '관리자 PIN은 숫자 4~8자리입니다.'); s.adminPin = hashPin(body.adminPin); }
    if (body.lat != null && body.lng != null && isFinite(body.lat) && isFinite(body.lng)) { s.lat = Number(body.lat); s.lng = Number(body.lng); }
    await save(); return {};
  }
  throw E(404, 'not found');
}

/* ---------- HTTP ---------- */
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.json': 'application/json', '.svg': 'image/svg+xml', '.css': 'text/css' };
function serveStatic(req, res, url) {
  let p = decodeURIComponent(url.pathname); if (p === '/') p = '/index.html';
  const f = path.join(PUBLIC, path.normalize(p));
  if (!f.startsWith(PUBLIC + path.sep) || !fs.existsSync(f) || !fs.statSync(f).isFile()) { res.writeHead(404); return res.end('Not found'); }
  res.writeHead(200, { 'content-type': TYPES[path.extname(f)] || 'application/octet-stream', 'cache-control': p === '/sw.js' ? 'no-cache' : 'public, max-age=300' });
  fs.createReadStream(f).pipe(res);
}
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  res.setHeader('x-content-type-options', 'nosniff');
  if (!url.pathname.startsWith('/api/')) return serveStatic(req, res, url);
  const send = (c, o) => { res.writeHead(c, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }); res.end(JSON.stringify(o)); };
  try {
    let raw = ''; for await (const c of req) { raw += c; if (raw.length > 1e5) throw E(413, '요청이 너무 큽니다.'); }
    let body = {}; if (raw) { try { body = JSON.parse(raw); } catch { throw E(400, '잘못된 요청입니다.'); } }
    const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress).split(',')[0].trim();
    send(200, await api(req, url, body, ip));
  } catch (e) {
    if (!e.status) console.error(e);
    send(e.status || 500, { error: e.status ? e.message : '서버 오류가 발생했습니다.' });
  }
});
loadDb().then(() => server.listen(PORT, () => console.log('bompunch on :' + PORT, pool ? '(postgres)' : '(file)')))
  .catch(e => { console.error(e); process.exit(1); });
