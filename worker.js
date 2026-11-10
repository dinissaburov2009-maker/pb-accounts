/* Петушиные бои: сервер аккаунтов (Cloudflare Worker + D1).
   Хранит профиль игрока целиком. Вход: токен устройства (выдаётся при создании аккаунта или входе по коду восстановления).
   Версия профиля rev растёт на 1 при каждом сохранении; сохранение с устаревшим baseRev отклоняется (409), чтобы два телефона не затирали друг друга. */

const MAX_BYTES = 1000000;      // максимум размера профиля (символов JSON)
const MAX_SESSIONS = 10;        // устройств на один аккаунт
const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 32 символа, без похожих 0/O, 1/I
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization,Content-Type',
  'Access-Control-Max-Age': '86400',
};

const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...CORS },
});
const fail = (status, code) => json({ error: code }, status);

function rand(len) {
  const b = crypto.getRandomValues(new Uint8Array(len));
  let s = '';
  for (let i = 0; i < len; i++) s += ALPHA[b[i] & 31];
  return s;
}
async function sha(text) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, '0')).join('');
}
const fmtRecovery = (c) => c.match(/.{4}/g).join('-');
const normRecovery = (t) => String(t || '').toUpperCase().replace(/[^A-Z0-9]/g, '');

// Запрещённые ключи на любой глубине и слишком глубокая вложенность
function badShape(v, depth) {
  if (!v || typeof v !== 'object') return false;
  if (depth > 12) return true;
  if (Array.isArray(v)) return v.some((x) => badShape(x, depth + 1));
  return Object.keys(v).some((k) => k === '__proto__' || k === 'constructor' || k === 'prototype' || badShape(v[k], depth + 1));
}
// Возвращает { text, nick } или null
function checkProfile(p) {
  if (!p || typeof p !== 'object' || Array.isArray(p) || badShape(p, 0)) return null;
  const text = JSON.stringify(p);
  if (text.length > MAX_BYTES) return null;
  const mm = (v) => { v = Math.round(Number(v)); return Number.isFinite(v) ? Math.min(100000, Math.max(0, v)) : 0; };
  return { text, nick: String(p.nickname || '').slice(0, 24), m1: mm(p.mmr1v1), m2: mm(p.mmr2v2) };
}
async function body(req) {
  try { const t = await req.text(); if (t.length > MAX_BYTES + 5000) return null; const o = JSON.parse(t); return o && typeof o === 'object' ? o : null; } catch (e) { return null; }
}

async function newSession(env, acc) {
  const token = rand(32), now = Date.now();
  await env.DB.batch([
    env.DB.prepare('INSERT INTO sessions (hash, acc, created, last) VALUES (?, ?, ?, ?)').bind(await sha(token), acc, now, now),
    env.DB.prepare('DELETE FROM sessions WHERE acc = ? AND hash NOT IN (SELECT hash FROM sessions WHERE acc = ? ORDER BY last DESC LIMIT ?)').bind(acc, acc, MAX_SESSIONS),
  ]);
  return acc + '.' + token;
}
// Заголовок Authorization: Bearer <id>.<token> → { acc, hash } или null
async function auth(req, env) {
  const h = req.headers.get('Authorization') || '';
  const m = /^Bearer ([A-Z0-9]{8})\.([A-Z0-9]{32})$/.exec(h);
  if (!m) return null;
  const hash = await sha(m[2]);
  const row = await env.DB.prepare('SELECT acc, last FROM sessions WHERE hash = ?').bind(hash).first();
  if (!row || row.acc !== m[1]) return null;
  const now = Date.now();
  if (now - row.last > 3600000) await env.DB.prepare('UPDATE sessions SET last = ? WHERE hash = ?').bind(now, hash).run();
  return { acc: row.acc, hash };
}

async function register(req, env) {
  const b = await body(req), p = b && checkProfile(b.profile);
  if (!p) return fail(400, 'bad_profile');
  const now = Date.now(), recovery = rand(16), recHash = await sha(recovery);
  let id = '';
  for (let i = 0; i < 5; i++) {
    id = rand(8);
    try {
      await env.DB.prepare('INSERT INTO accounts (id, recovery_hash, profile, rev, nick, m1, m2, created, updated) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)')
        .bind(id, recHash, p.text, p.nick, p.m1, p.m2, now, now).run();
      break;
    } catch (e) { id = ''; }
  }
  if (!id) return fail(500, 'try_again');
  return json({ id, token: await newSession(env, id), recovery: fmtRecovery(recovery), rev: 1 });
}
async function login(req, env) {
  const b = await body(req), code = normRecovery(b && b.recovery);
  if (code.length !== 16) return fail(400, 'bad_code');
  const row = await env.DB.prepare('SELECT id, rev, profile FROM accounts WHERE recovery_hash = ?').bind(await sha(code)).first();
  if (!row) return fail(404, 'no_account');
  return json({ id: row.id, token: await newSession(env, row.id), rev: row.rev, profile: JSON.parse(row.profile) });
}
async function getProfile(env, a, url) {
  const row = await env.DB.prepare('SELECT rev, profile FROM accounts WHERE id = ?').bind(a.acc).first();
  if (!row) return fail(404, 'no_account');
  if (url.searchParams.get('rev') === String(row.rev)) return json({ id: a.acc, rev: row.rev, same: true });
  return json({ id: a.acc, rev: row.rev, profile: JSON.parse(row.profile) });
}
async function putProfile(req, env, a) {
  const b = await body(req), p = b && checkProfile(b.profile);
  if (!p || !Number.isInteger(b.baseRev)) return fail(400, 'bad_profile');
  const r = await env.DB.prepare('UPDATE accounts SET profile = ?, rev = rev + 1, nick = ?, m1 = ?, m2 = ?, updated = ? WHERE id = ? AND rev = ?')
    .bind(p.text, p.nick, p.m1, p.m2, Date.now(), a.acc, b.baseRev).run();
  const row = await env.DB.prepare('SELECT rev FROM accounts WHERE id = ?').bind(a.acc).first();
  if (!r.meta || r.meta.changes !== 1) return json({ error: 'conflict', rev: row ? row.rev : 0 }, 409);
  return json({ rev: row.rev });
}
// Общий топ живых игроков: ник и MMR (1v1 или 2v2). Только для вошедших; аккаунты без ника и неактивные 30 дней не показываются
const TOP_FRESH_MS = 30 * 86400000;
async function top(env, url) {
  const col = url.searchParams.get('mode') === '2v2' ? 'm2' : 'm1';
  const lim = Math.min(100, Math.max(5, parseInt(url.searchParams.get('limit'), 10) || 50));
  const rs = await env.DB.prepare('SELECT id, nick, ' + col + ' AS m FROM accounts WHERE ' + col + " > 0 AND nick != '' AND updated > ? ORDER BY " + col + ' DESC LIMIT ?')
    .bind(Date.now() - TOP_FRESH_MS, lim).all();
  return json({ rows: (rs.results || []).map((x) => ({ i: x.id, n: x.nick, m: x.m })) });
}
async function rotate(env, a) {
  const recovery = rand(16);
  await env.DB.prepare('UPDATE accounts SET recovery_hash = ? WHERE id = ?').bind(await sha(recovery), a.acc).run();
  return json({ recovery: fmtRecovery(recovery) });
}
async function logout(env, a) {
  await env.DB.prepare('DELETE FROM sessions WHERE hash = ?').bind(a.hash).run();
  return json({ ok: true });
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    const url = new URL(req.url), path = url.pathname.replace(/\/+$/, '') || '/', m = req.method;
    try {
      if (path === '/' && m === 'GET') return new Response('petushinye-boi accounts: ok', { headers: { 'Content-Type': 'text/plain; charset=utf-8', ...CORS } });
      if (path === '/api/register' && m === 'POST') return await register(req, env);
      if (path === '/api/login' && m === 'POST') return await login(req, env);
      if (path.startsWith('/api/')) {
        const a = await auth(req, env);
        if (!a) return fail(401, 'unauthorized');
        if (path === '/api/profile' && m === 'GET') return await getProfile(env, a, url);
        if (path === '/api/profile' && m === 'PUT') return await putProfile(req, env, a);
        if (path === '/api/top' && m === 'GET') return await top(env, url);
        if (path === '/api/recovery/rotate' && m === 'POST') return await rotate(env, a);
        if (path === '/api/logout' && m === 'POST') return await logout(env, a);
      }
      return fail(404, 'not_found');
    } catch (e) {
      return fail(500, 'server_error');
    }
  },
};
