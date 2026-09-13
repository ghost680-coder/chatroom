const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const Database = require('better-sqlite3');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { transports: ['websocket', 'polling'] });

const DATA_DIR = process.env.DATA_DIR || __dirname;
const UPLOADS = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(UPLOADS, { recursive: true });

const MAX_MEMBERS = 6;
const CODE_RE = /^[A-Z0-9]{6}$/;
const FILE_RE = /^[a-f0-9]{32}(\.[a-z0-9]{1,10})?$/i;
const SESSION_MS = 30 * 24 * 60 * 60 * 1000;
const EMPTY_GRACE_MS = 60 * 1000;
const USER_RE = /^[a-zA-Z0-9_]{3,24}$/;

// ---------- database ----------

const db = new Database(path.join(DATA_DIR, 'chat.db'));
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');

// ---------- migrations ----------
// Each function upgrades the schema by one version. Never edit a shipped
// migration — add a new one. The database remembers its version in
// PRAGMA user_version, so this runs exactly once per change.

const MIGRATIONS = [
  // 0 -> 1: initial schema (v1)
  function m1(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS rooms (
        id TEXT PRIMARY KEY,
        name TEXT,
        persistent INTEGER NOT NULL DEFAULT 1,
        owner_id INTEGER,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS memberships (
        user_id INTEGER NOT NULL,
        room_id TEXT NOT NULL,
        display_name TEXT,
        joined_at INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL,
        PRIMARY KEY (user_id, room_id)
      );
      CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id TEXT NOT NULL,
        user_id INTEGER,
        author TEXT NOT NULL,
        kind TEXT NOT NULL,
        body TEXT,
        file_name TEXT, file_path TEXT, file_size INTEGER, mime TEXT,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_msg_room ON messages(room_id, id);
      CREATE INDEX IF NOT EXISTS idx_sess_token ON sessions(token);
      CREATE INDEX IF NOT EXISTS idx_memb_user ON memberships(user_id, last_seen_at);
    `);
  },

  // 1 -> 2: full-text search index over messages
  function m2(db) {
    db.exec(`
      CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
        body,
        content='messages',
        content_rowid='id',
        tokenize='porter unicode61'
      );
      CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
        INSERT INTO messages_fts(rowid, body) VALUES (new.id, new.body);
      END;
      CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
        INSERT INTO messages_fts(messages_fts, rowid, body) VALUES('delete', old.id, old.body);
      END;
      CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
        INSERT INTO messages_fts(messages_fts, rowid, body) VALUES('delete', old.id, old.body);
        INSERT INTO messages_fts(rowid, body) VALUES (new.id, new.body);
      END;
    `);
    const n = db.prepare('SELECT COUNT(*) AS n FROM messages').get().n;
    if (n > 0) db.exec(`INSERT INTO messages_fts(messages_fts) VALUES('rebuild')`);
  },
];

(function runMigrations() {
  const start = db.pragma('user_version', { simple: true });
  for (let i = start; i < MIGRATIONS.length; i++) {
    console.log(`[migrate] applying v${i + 1}`);
    MIGRATIONS[i](db);
    db.pragma(`user_version = ${i + 1}`);
  }
  if (start !== MIGRATIONS.length) console.log(`[migrate] at v${MIGRATIONS.length}`);
})();

// ---------- prepared statements ----------

const qUserByName = db.prepare('SELECT * FROM users WHERE username = ?');
const qUserById   = db.prepare('SELECT id, username FROM users WHERE id = ?');
const qInsertUser = db.prepare('INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)');

const qSession    = db.prepare('SELECT * FROM sessions WHERE token = ? AND expires_at > ?');
const qNewSession = db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)');
const qDelSession = db.prepare('DELETE FROM sessions WHERE token = ?');

const qRoom       = db.prepare('SELECT * FROM rooms WHERE id = ?');
const qNewRoom    = db.prepare('INSERT INTO rooms (id, name, persistent, owner_id, created_at) VALUES (?, ?, ?, ?, ?)');
const qDelRoom    = db.prepare('DELETE FROM rooms WHERE id = ?');
const qDelMsgs    = db.prepare('DELETE FROM messages WHERE room_id = ?');
const qDelMembers = db.prepare('DELETE FROM memberships WHERE room_id = ?');

const qMyRooms    = db.prepare(`
  SELECT r.id, r.name, r.persistent, r.owner_id, r.created_at,
         m.display_name, m.last_seen_at,
         (SELECT COUNT(*) FROM messages msg
          WHERE msg.room_id = r.id
            AND msg.created_at > m.last_seen_at
            AND (msg.user_id IS NULL OR msg.user_id != m.user_id)) AS unread
  FROM memberships m JOIN rooms r ON r.id = m.room_id
  WHERE m.user_id = ? ORDER BY m.last_seen_at DESC
`);
const qMembership = db.prepare('SELECT * FROM memberships WHERE user_id = ? AND room_id = ?');
const qAddMember  = db.prepare('INSERT OR REPLACE INTO memberships (user_id, room_id, display_name, joined_at, last_seen_at) VALUES (?, ?, ?, ?, ?)');
const qDelMember  = db.prepare('DELETE FROM memberships WHERE user_id = ? AND room_id = ?');
const qSetDisplay = db.prepare('UPDATE memberships SET display_name = ? WHERE user_id = ? AND room_id = ?');
const qTouch      = db.prepare('UPDATE memberships SET last_seen_at = ? WHERE user_id = ? AND room_id = ?');

const qInsert = db.prepare(`INSERT INTO messages (room_id, user_id, author, kind, body, file_name, file_path, file_size, mime, created_at)
                            VALUES (@room_id, @user_id, @author, @kind, @body, @file_name, @file_path, @file_size, @mime, @created_at)`);
const qById = db.prepare('SELECT * FROM messages WHERE id = ?');

// ---------- helpers ----------

function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pw, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(pw, stored) {
  const [salt, hash] = String(stored).split(':');
  if (!salt || !hash) return false;
  const check = crypto.scryptSync(pw, salt, 64).toString('hex');
  const a = Buffer.from(hash, 'hex'), b = Buffer.from(check, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const pair of header.split(';')) {
    const i = pair.indexOf('=');
    if (i < 0) continue;
    out[pair.slice(0, i).trim()] = decodeURIComponent(pair.slice(i + 1).trim());
  }
  return out;
}
function setSessionCookie(res, token) {
  const max = Math.floor(SESSION_MS / 1000);
  res.setHeader('Set-Cookie', `session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${max}`);
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
}

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function newCode() {
  for (;;) {
    const b = crypto.randomBytes(6);
    let c = '';
    for (let i = 0; i < 6; i++) c += ALPHABET[b[i] % ALPHABET.length];
    if (!qRoom.get(c)) return c;
  }
}

function auth(req) {
  const token = parseCookies(req.headers.cookie).session;
  if (!token) return null;
  const s = qSession.get(token, Date.now());
  if (!s) return null;
  const u = qUserById.get(s.user_id);
  return u ? { id: u.id, username: u.username, token } : null;
}

function roomPayload(row, userId) {
  return {
    id: row.id,
    name: row.name,
    persistent: !!row.persistent,
    isOwner: row.owner_id === userId,
    createdAt: row.created_at,
  };
}
function shapeMsg(row) {
  return {
    id: row.id,
    author: row.author,
    kind: row.kind,
    body: row.body,
    fileName: row.file_name,
    fileUrl: row.file_path ? `/uploads/${row.room_id}/${row.file_path}` : null,
    fileSize: row.file_size,
    mime: row.mime,
    createdAt: row.created_at,
  };
}

// ---------- express ----------

app.use(express.json());

app.post('/api/signup', (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  if (!USER_RE.test(username)) return res.status(400).json({ error: 'Username must be 3–24 chars (letters, numbers, _).' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  if (qUserByName.get(username)) return res.status(409).json({ error: 'That username is taken.' });
  const info = qInsertUser.run(username, hashPassword(password), Date.now());
  const token = crypto.randomBytes(32).toString('hex');
  qNewSession.run(token, info.lastInsertRowid, Date.now() + SESSION_MS);
  setSessionCookie(res, token);
  res.json({ user: { id: info.lastInsertRowid, username } });
});

app.post('/api/login', (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  const user = qUserByName.get(username);
  if (!user || !verifyPassword(password, user.password_hash)) {
    return res.status(401).json({ error: 'Wrong username or password.' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  qNewSession.run(token, user.id, Date.now() + SESSION_MS);
  setSessionCookie(res, token);
  res.json({ user: { id: user.id, username: user.username } });
});

app.post('/api/logout', (req, res) => {
  const token = parseCookies(req.headers.cookie).session;
  if (token) qDelSession.run(token);
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const u = auth(req);
  if (!u) return res.status(401).json({ error: 'not signed in' });
  res.json({ user: { id: u.id, username: u.username } });
});

// ---------- rooms ----------

app.get('/api/rooms', (req, res) => {
  const u = auth(req);
  if (!u) return res.status(401).json({ error: 'not signed in' });
  const rows = qMyRooms.all(u.id);
  res.json(rows.map(r => ({
    id: r.id,
    name: r.name,
    persistent: !!r.persistent,
    isOwner: r.owner_id === u.id,
    displayName: r.display_name,
    lastSeenAt: r.last_seen_at,
    unread: r.unread || 0,
  })));
});

app.post('/api/rooms', (req, res) => {
  const u = auth(req);
  if (!u) return res.status(401).json({ error: 'not signed in' });
  const name = String(req.body?.name || '').trim().slice(0, 40) || 'untitled';
  const persistent = req.body?.persistent !== false ? 1 : 0;
  const id = newCode();
  qNewRoom.run(id, name, persistent, u.id, Date.now());
  qAddMember.run(u.id, id, u.username, Date.now(), Date.now());
  res.json({ room: roomPayload(qRoom.get(id), u.id), displayName: u.username });
});

app.post('/api/rooms/:id/join', (req, res) => {
  const u = auth(req);
  if (!u) return res.status(401).json({ error: 'not signed in' });
  const id = String(req.params.id || '').toUpperCase();
  if (!CODE_RE.test(id)) return res.status(400).json({ error: 'Room codes are six characters.' });
  const room = qRoom.get(id);
  if (!room) return res.status(404).json({ error: 'No room with that code.' });

  const display = String(req.body?.displayName || '').trim().slice(0, 24) || u.username;
  const existing = qMembership.get(u.id, id);
  if (!existing) qAddMember.run(u.id, id, display, Date.now(), Date.now());
  else qTouch.run(Date.now(), u.id, id);
  res.json({
    room: roomPayload(room, u.id),
    displayName: existing?.display_name || display,
  });
});

app.post('/api/rooms/:id/display', (req, res) => {
  const u = auth(req);
  if (!u) return res.status(401).json({ error: 'not signed in' });
  const id = String(req.params.id || '').toUpperCase();
  const m = qMembership.get(u.id, id);
  if (!m) return res.status(404).json({ error: 'not in this room' });
  const display = String(req.body?.displayName || '').trim().slice(0, 24) || u.username;
  qSetDisplay.run(display, u.id, id);
  res.json({ displayName: display });
});

app.post('/api/rooms/:id/leave', (req, res) => {
  const u = auth(req);
  if (!u) return res.status(401).json({ error: 'not signed in' });
  const id = String(req.params.id || '').toUpperCase();
  if (req.body?.forget === true) qDelMember.run(u.id, id);
  else qTouch.run(Date.now(), u.id, id);
  res.json({ ok: true });
});

app.post('/api/rooms/:id/delete', (req, res) => {
  const u = auth(req);
  if (!u) return res.status(401).json({ error: 'not signed in' });
  const id = String(req.params.id || '').toUpperCase();
  const room = qRoom.get(id);
  if (!room) return res.status(404).json({ error: 'No such room.' });
  if (room.owner_id !== u.id) return res.status(403).json({ error: 'Only the room owner can delete it.' });

  qDelMsgs.run(id);
  qDelMembers.run(id);
  qDelRoom.run(id);
  presence.delete(id);
  const dir = path.join(UPLOADS, id);
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}

  io.to(id).emit('room deleted');
  io.in(id).socketsLeave(id);
  console.log(`[room ${id}] deleted by ${u.username}`);
  res.json({ ok: true });
});

// ---------- search ----------

app.get('/api/search', (req, res) => {
  const u = auth(req);
  if (!u) return res.status(401).json({ error: 'not signed in' });
  const q = String(req.query.q || '').trim();
  if (!q) return res.json({ results: [] });

  const words = q.split(/\s+/)
    .map(w => w.replace(/[^\p{L}\p{N}]/gu, ''))
    .filter(Boolean)
    .slice(0, 8);
  if (!words.length) return res.json({ results: [] });
  const fts = words.map(w => w + '*').join(' AND ');

  try {
    const rows = db.prepare(`
      SELECT m.id, m.room_id, m.author, m.body, m.created_at, r.name AS room_name
      FROM messages_fts f
      JOIN messages m ON m.id = f.rowid
      JOIN rooms r ON r.id = m.room_id
      JOIN memberships mb ON mb.room_id = m.room_id AND mb.user_id = ?
      WHERE f MATCH ?
      ORDER BY m.created_at DESC
      LIMIT 100
    `).all(u.id, fts);

    res.json({
      results: rows.map(r => ({
        id: r.id,
        roomId: r.room_id,
        roomName: r.room_name,
        author: r.author,
        body: r.body,
        createdAt: r.created_at,
      })),
    });
  } catch (e) {
    console.error('[search]', e.message);
    res.status(500).json({ error: 'search failed' });
  }
});

// ---------- messages ----------

app.get('/api/rooms/:id/messages', (req, res) => {
  const u = auth(req);
  if (!u) return res.status(401).json({ error: 'not signed in' });
  const roomId = String(req.params.id || '').toUpperCase();
  if (!CODE_RE.test(roomId) || !qRoom.get(roomId)) return res.status(404).json({ error: 'no such room' });
  const before = Number(req.query.before) || null;
  const limit = Math.min(Number(req.query.limit) || 60, 200);

  const rows = before
    ? db.prepare(`SELECT * FROM (SELECT * FROM messages WHERE room_id = ? AND id < ? ORDER BY id DESC LIMIT ?) ORDER BY id ASC`).all(roomId, before, limit)
    : db.prepare(`SELECT * FROM (SELECT * FROM messages WHERE room_id = ? ORDER BY id DESC LIMIT ?) ORDER BY id ASC`).all(roomId, limit);
  res.json(rows.map(shapeMsg));
});

// ---------- uploads ----------

const storage = multer.diskStorage({
  destination(req, file, cb) {
    const dir = path.join(UPLOADS, req.roomId);
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename(req, file, cb) {
    const ext = path.extname(file.originalname).slice(0, 10).toLowerCase();
    cb(null, crypto.randomBytes(16).toString('hex') + ext);
  },
});
const upload = multer({ storage });

app.post('/api/upload',
  (req, res, next) => {
    const u = auth(req);
    if (!u) return res.status(401).json({ error: 'not signed in' });
    const roomId = String(req.query.roomId || '').toUpperCase();
    if (!CODE_RE.test(roomId) || !qRoom.get(roomId)) return res.status(404).json({ error: 'no such room' });
    const m = qMembership.get(u.id, roomId);
    if (!m) return res.status(403).json({ error: 'not in this room' });
    req.user = u;
    req.roomId = roomId;
    req.display = m.display_name || u.username;
    next();
  },
  upload.single('file'),
  (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'no file' });
    const info = qInsert.run({
      room_id: req.roomId,
      user_id: req.user.id,
      author: req.display,
      kind: 'file',
      body: null,
      file_name: req.file.originalname,
      file_path: req.file.filename,
      file_size: req.file.size,
      mime: req.file.mimetype,
      created_at: Date.now(),
    });
    const msg = shapeMsg(qById.get(info.lastInsertRowid));
    io.to(req.roomId).emit('message', msg);
    touchRoom(req.roomId);
    res.json(msg);
  }
);

app.get('/uploads/:room/:file', (req, res) => {
  const { room, file } = req.params;
  if (!CODE_RE.test(room) || !FILE_RE.test(file)) return res.sendStatus(400);
  const full = path.join(UPLOADS, room, file);
  if (!full.startsWith(UPLOADS + path.sep) || !fs.existsSync(full)) return res.sendStatus(404);
  res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy', "default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'");
  res.sendFile(full);
});

// ---------- sockets ----------

io.use((socket, next) => {
  const token = parseCookies(socket.handshake.headers.cookie).session;
  if (!token) return next(new Error('unauthorized'));
  const s = qSession.get(token, Date.now());
  if (!s) return next(new Error('unauthorized'));
  const u = qUserById.get(s.user_id);
  if (!u) return next(new Error('unauthorized'));
  socket.userId = u.id;
  socket.username = u.username;
  next();
});

const presence = new Map();
const emptyTimers = new Map();

function occupants(id) { return presence.get(id)?.size ?? 0; }

// Bump last_seen_at for every user with a live socket in this room.
// Called after a message is posted, so readers don't accumulate unread badges.
function touchRoom(roomId) {
  const ids = io.sockets.adapter.rooms.get(roomId);
  if (!ids) return;
  const now = Date.now();
  for (const sid of ids) {
    const s = io.sockets.sockets.get(sid);
    if (s && s.userId) qTouch.run(now, s.userId, roomId);
  }
}

function scheduleRoomCleanup(roomId) {
  if (emptyTimers.has(roomId)) return;
  const t = setTimeout(() => {
    emptyTimers.delete(roomId);
    const room = qRoom.get(roomId);
    if (!room) return;
    if (occupants(roomId) > 0) return;
    if (!room.persistent) {
      qDelMsgs.run(roomId);
      qDelMembers.run(roomId);
      qDelRoom.run(roomId);
      const dir = path.join(UPLOADS, roomId);
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
      console.log(`[room ${roomId}] auto-deleted (empty, temporary)`);
    }
  }, EMPTY_GRACE_MS);
  emptyTimers.set(roomId, t);
}
function cancelCleanup(roomId) {
  const t = emptyTimers.get(roomId);
  if (t) { clearTimeout(t); emptyTimers.delete(roomId); }
}

io.on('connection', (socket) => {
  let roomId = null;
  let display = socket.username;

  function leaveCurrent() {
    if (!roomId) return;
    const id = roomId;
    roomId = null;
    const set = presence.get(id);
    if (set) {
      set.delete(socket.id);
      if (set.size === 0) { presence.delete(id); scheduleRoomCleanup(id); }
    }
    socket.leave(id);
    socket.to(id).emit('presence', { count: occupants(id) });
    socket.to(id).emit('system', `${display} left`);
  }

  socket.on('enter', (payload = {}, cb = () => {}) => {
    const wanted = String(payload.roomId || '').toUpperCase();
    const room = qRoom.get(wanted);
    if (!room) return cb({ ok: false, error: 'Room not found.' });
    const m = qMembership.get(socket.userId, wanted);
    if (!m) return cb({ ok: false, error: 'You are not a member of this room.' });

    const set = presence.get(wanted) || new Map();
    if (set.size >= MAX_MEMBERS && !set.has(socket.id)) {
      return cb({ ok: false, error: `Room is full — ${MAX_MEMBERS} of ${MAX_MEMBERS}.` });
    }

    leaveCurrent();
    cancelCleanup(wanted);
    display = m.display_name || socket.username;
    roomId = wanted;
    if (!presence.has(wanted)) presence.set(wanted, new Map());
    presence.get(wanted).set(socket.id, display);
    socket.join(wanted);

    socket.to(wanted).emit('system', `${display} joined`);
    socket.to(wanted).emit('presence', { count: occupants(wanted) });
    qTouch.run(Date.now(), socket.userId, wanted);
    cb({ ok: true, roomId: wanted, displayName: display, count: occupants(wanted), max: MAX_MEMBERS });
  });

  socket.on('display', (payload = {}, cb = () => {}) => {
    if (!roomId) return cb({ ok: false, error: 'not in a room' });
    const next = String(payload.name || '').trim().slice(0, 24) || socket.username;
    const old = display;
    display = next;
    qSetDisplay.run(next, socket.userId, roomId);
    const set = presence.get(roomId);
    if (set) set.set(socket.id, next);
    socket.to(roomId).emit('system', `${old} is now ${next}`);
    if (cb) cb({ ok: true, displayName: next });
  });

  socket.on('message', (text) => {
    if (!roomId) return;
    if (!qRoom.get(roomId)) { roomId = null; socket.emit('room deleted'); return; }
    const body = String(text ?? '').slice(0, 4000);
    if (!body.trim()) return;
    const info = qInsert.run({
      room_id: roomId,
      user_id: socket.userId,
      author: display,
      kind: 'text',
      body,
      file_name: null, file_path: null, file_size: null, mime: null,
      created_at: Date.now(),
    });
    io.to(roomId).emit('message', shapeMsg(qById.get(info.lastInsertRowid)));
    touchRoom(roomId);
  });

  socket.on('typing', () => {
    if (roomId) socket.to(roomId).emit('typing', display);
  });

  socket.on('disconnect', leaveCurrent);
});

app.use(express.static('public', { maxAge: '1h', etag: true }));

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => console.log('Server running on port ' + PORT));
