const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dokumento-dev-secret-change-in-production';
const FREE_LIMIT = 3;
const BCRYPT_ROUNDS = 10;

const db = new Database(path.join(__dirname, 'users.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    documents_count INTEGER NOT NULL DEFAULT 0,
    documents_month TEXT NOT NULL DEFAULT ''
  )
`);

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

function currentMonth() {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
}

function getUserById(id) {
  return db.prepare('SELECT id, email, documents_count, documents_month FROM users WHERE id = ?').get(id);
}

function resetCountIfNewMonth(user) {
  const month = currentMonth();
  if (user.documents_month !== month) {
    db.prepare('UPDATE users SET documents_count = 0, documents_month = ? WHERE id = ?').run(month, user.id);
    return { ...user, documents_count: 0, documents_month: month };
  }
  return user;
}

function userPayload(user) {
  const used = user.documents_count;
  return {
    id: user.id,
    email: user.email,
    documentsUsed: used,
    documentsRemaining: Math.max(0, FREE_LIMIT - used),
    documentsLimit: FREE_LIMIT,
  };
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Требуется авторизация' });
  }

  const token = header.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = getUserById(payload.userId);
    if (!user) {
      return res.status(401).json({ error: 'Пользователь не найден' });
    }
    req.user = resetCountIfNewMonth(user);
    next();
  } catch {
    return res.status(401).json({ error: 'Недействительный токен' });
  }
}

app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Укажите email и пароль' });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Некорректный email' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Пароль должен быть не менее 6 символов' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
  if (existing) {
    return res.status(409).json({ error: 'Пользователь с таким email уже существует' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const result = db.prepare(
      'INSERT INTO users (email, password_hash, documents_month) VALUES (?, ?, ?)'
    ).run(email.toLowerCase(), passwordHash, currentMonth());

    const user = getUserById(result.lastInsertRowid);
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({ token, user: userPayload(user) });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Укажите email и пароль' });
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
  if (!user) {
    return res.status(401).json({ error: 'Неверный email или пароль' });
  }

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    return res.status(401).json({ error: 'Неверный email или пароль' });
  }

  const freshUser = resetCountIfNewMonth(user);
  const token = jwt.sign({ userId: freshUser.id }, JWT_SECRET, { expiresIn: '7d' });

  res.json({ token, user: userPayload(freshUser) });
});

app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ user: userPayload(req.user) });
});

app.post('/api/documents/count', authMiddleware, (req, res) => {
  const user = req.user;

  if (user.documents_count >= FREE_LIMIT) {
    return res.status(403).json({
      error: 'Лимит бесплатных документов исчерпан',
      used: user.documents_count,
      remaining: 0,
      limit: FREE_LIMIT,
    });
  }

  const newCount = user.documents_count + 1;
  db.prepare('UPDATE users SET documents_count = ? WHERE id = ?').run(newCount, user.id);

  res.json({
    used: newCount,
    remaining: FREE_LIMIT - newCount,
    limit: FREE_LIMIT,
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Документо запущен: http://localhost:${PORT}`);
});
