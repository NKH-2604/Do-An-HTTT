const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
require('dotenv').config({ quiet: true });
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');

const PORT = process.env.PORT || 3000;
const DB = {
  host: process.env.DB_HOST || '127.0.0.1',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'studymanage',
};

function loadSecret() {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  const dir = path.join(__dirname, 'data');
  fs.mkdirSync(dir, { recursive: true });
  const f = path.join(dir, 'secret.key');
  if (!fs.existsSync(f)) fs.writeFileSync(f, crypto.randomBytes(48).toString('hex'), { mode: 0o600 });
  return fs.readFileSync(f, 'utf8').trim();
}
const SECRET = loadSecret();
const COOKIE = 'sm_token';
const MAX_AGE_MS = 7 * 24 * 3600 * 1000;

let pool;

async function initDb() {
  const { database, ...conn } = DB;
  const boot = await mysql.createConnection(conn);
  await boot.query(`CREATE DATABASE IF NOT EXISTS \`${database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
  await boot.end();
  pool = mysql.createPool({ ...DB, connectionLimit: 10, charset: 'utf8mb4' });
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      username      VARCHAR(24)  NOT NULL,
      username_key  VARCHAR(24)  NOT NULL,
      password_hash VARCHAR(100) NOT NULL,
      created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uq_username_key (username_key)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_data (
      user_id    INT UNSIGNED NOT NULL,
      k          VARCHAR(64)  NOT NULL,
      v          LONGTEXT     NOT NULL,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (user_id, k),
      CONSTRAINT fk_user_data_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
}

const fails = new Map();
function tooMany(k) {
  const now = Date.now();
  const arr = (fails.get(k) || []).filter(t => now - t < 10 * 60 * 1000);
  fails.set(k, arr);
  return arr.length >= 8;
}
const addFail = k => fails.set(k, [...(fails.get(k) || []), Date.now()]);

const USER_RE = /^[\p{L}\p{N}_-]{3,24}$/u;
const KEY_RE = /^[A-Za-z0-9_]{1,64}$/;
const MAX_VALUE = 12 * 1024 * 1024;
const MAX_KEYS = 100;

function setSession(res, user) {
  const token = jwt.sign({ uid: user.id }, SECRET, { expiresIn: '7d' });
  res.cookie(COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: MAX_AGE_MS,
  });
}

async function auth(req, res, next) {
  try {
    const { uid } = jwt.verify(req.cookies[COOKIE] || '', SECRET);
    const [rows] = await pool.query('SELECT id, username FROM users WHERE id = ?', [uid]);
    if (!rows.length) throw new Error('no user');
    req.user = rows[0];
    next();
  } catch {
    res.status(401).json({ error: 'Chưa đăng nhập.' });
  }
}

const app = express();
app.disable('x-powered-by');
app.use(cookieParser());
app.use('/api/data', express.json({ limit: '40mb' }));
app.use(express.json({ limit: '10kb' }));

app.post('/api/register', async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  if (!USER_RE.test(username)) return res.status(400).json({ error: 'Tên đăng nhập cần 3–24 ký tự: chữ, số, _ hoặc -.' });
  if (password.length < 4 || password.length > 72) return res.status(400).json({ error: 'Mật khẩu cần từ 4 đến 72 ký tự.' });
  const key = username.toLowerCase();
  const hash = await bcrypt.hash(password, 10);
  try {
    const [r] = await pool.query('INSERT INTO users (username, username_key, password_hash) VALUES (?, ?, ?)', [username, key, hash]);
    setSession(res, { id: r.insertId });
    res.json({ user: { username } });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Tên đăng nhập này đã tồn tại.' });
    throw e;
  }
});

app.post('/api/login', async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const limitKey = `${req.ip}|${username.toLowerCase()}`;
  if (tooMany(limitKey)) return res.status(429).json({ error: 'Đăng nhập sai quá nhiều lần. Thử lại sau 10 phút.' });
  const [rows] = await pool.query('SELECT id, username, password_hash FROM users WHERE username_key = ?', [username.toLowerCase()]);
  const row = rows[0];

  const ok = await bcrypt.compare(password, row ? row.password_hash : '$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidinv');
  if (!row || !ok) { addFail(limitKey); return res.status(401).json({ error: 'Tên đăng nhập hoặc mật khẩu không đúng.' }); }
  fails.delete(limitKey);
  setSession(res, row);
  res.json({ user: { username: row.username } });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie(COOKIE);
  res.json({ ok: true });
});

app.get('/api/me', (req, res, next) => {
  if (!req.cookies[COOKIE]) return res.json({ user: null });
  auth(req, res, () => res.json({ user: { username: req.user.username } }));
});

app.get('/api/data', auth, async (req, res) => {
  const [rows] = await pool.query('SELECT k, v FROM user_data WHERE user_id = ?', [req.user.id]);
  const data = {};
  rows.forEach(r => { data[r.k] = r.v; });
  res.json({ data });
});

app.put('/api/data', auth, async (req, res) => {
  const set = req.body.set && typeof req.body.set === 'object' ? req.body.set : {};
  const remove = Array.isArray(req.body.remove) ? req.body.remove : [];
  const entries = Object.entries(set);
  for (const [k, v] of entries) {
    if (!KEY_RE.test(k) || typeof v !== 'string') return res.status(400).json({ error: `Khóa dữ liệu không hợp lệ: ${k}` });
    if (v.length > MAX_VALUE) return res.status(413).json({ error: `Mục "${k}" quá lớn (tối đa 12MB).` });
  }
  if (remove.some(k => !KEY_RE.test(String(k)))) return res.status(400).json({ error: 'Khóa dữ liệu không hợp lệ.' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    if (req.body.replace) {
      if (entries.length) await conn.query('DELETE FROM user_data WHERE user_id = ? AND k NOT IN (?)', [req.user.id, entries.map(e => e[0])]);
      else await conn.query('DELETE FROM user_data WHERE user_id = ?', [req.user.id]);
    }
    if (remove.length) await conn.query('DELETE FROM user_data WHERE user_id = ? AND k IN (?)', [req.user.id, remove.map(String)]);
    const [[{ n }]] = await conn.query('SELECT COUNT(*) AS n FROM user_data WHERE user_id = ?', [req.user.id]);
    if (n + entries.length > MAX_KEYS * 2) throw Object.assign(new Error('too many'), { status: 413 });
    for (const [k, v] of entries) {
      await conn.query(
        'INSERT INTO user_data (user_id, k, v) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE v = VALUES(v)',
        [req.user.id, k, v]);
    }
    await conn.commit();
    res.json({ ok: true });
  } catch (e) {
    await conn.rollback();
    throw e;
  } finally {
    conn.release();
  }
});

app.use(express.static(path.join(__dirname, 'public'), { index: 'StudyManage.html' }));

app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large' || err.status === 413) return res.status(413).json({ error: 'Dữ liệu quá lớn.' });
  console.error(err);
  res.status(500).json({ error: 'Lỗi máy chủ. Kiểm tra MySQL đã chạy chưa.' });
});

if (require.main === module) {
  initDb()
    .then(() => app.listen(PORT, () => console.log(`Chạy tại http://localhost:${PORT}  (MySQL: ${DB.user}@${DB.host}:${DB.port}/${DB.database})`)))
    .catch(e => {
      console.error('Không kết nối được MySQL:', e.code || e.message);
      console.error('→ Mở Laragon, bấm "Start All", kiểm tra DB_USER / DB_PASSWORD trong file .env');
      process.exit(1);
    });
}
module.exports = { app, initDb };
