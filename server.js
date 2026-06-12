const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dokumento-dev-secret-change-in-production';
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const FROM_EMAIL = 'onboarding@resend.dev'; // заменить на свой домен позже

// ЮKassa
const YUKASSA_SHOP_ID = process.env.YUKASSA_SHOP_ID || '';
const YUKASSA_SECRET_KEY = process.env.YUKASSA_SECRET_KEY || '';

const FREE_LIMIT = 3;
const BCRYPT_ROUNDS = 10;
const PRO_PRICE = 49900;
const PRO_DURATION_MS = 30 * 24 * 60 * 60 * 1000;
const CODE_TTL_MS = 10 * 60 * 1000; // код живёт 10 минут

const db = new Database(path.join(__dirname, 'users.db'));

// ─── БД ──────────────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    documents_count INTEGER NOT NULL DEFAULT 0,
    documents_month TEXT NOT NULL DEFAULT '',
    plan TEXT NOT NULL DEFAULT 'free',
    plan_expires_at INTEGER NOT NULL DEFAULT 0,
    email_verified INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS documents_count (
    ip_address TEXT PRIMARY KEY,
    documents_count INTEGER NOT NULL DEFAULT 0,
    documents_month TEXT NOT NULL DEFAULT ''
  );

  CREATE TABLE IF NOT EXISTS email_verifications (
    email TEXT PRIMARY KEY,
    code TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0
  );
`);

// Миграции
try { db.exec(`ALTER TABLE users ADD COLUMN plan TEXT NOT NULL DEFAULT 'free'`); } catch (_) {}
try { db.exec(`ALTER TABLE users ADD COLUMN plan_expires_at INTEGER NOT NULL DEFAULT 0`); } catch (_) {}
try { db.exec(`ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0`); } catch (_) {}

// ─── Express ──────────────────────────────────────────────────────────────────
app.set('trust proxy', 1);
app.use(cors());
app.use(express.static(__dirname));
app.use('/webhook/yukassa', express.raw({ type: 'application/json' }));
app.use(express.json());

// ─── Хелперы ─────────────────────────────────────────────────────────────────
function currentMonth() {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
}

function getUserById(id) {
  return db.prepare(
    'SELECT id, email, plan, plan_expires_at, documents_count, documents_month, email_verified FROM users WHERE id = ?'
  ).get(id);
}

function checkAndExpirePlan(user) {
  if (user.plan === 'pro' && user.plan_expires_at > 0 && Date.now() > user.plan_expires_at) {
    db.prepare('UPDATE users SET plan = ?, plan_expires_at = 0 WHERE id = ?').run('free', user.id);
    return { ...user, plan: 'free', plan_expires_at: 0 };
  }
  return user;
}

function resetUserCountIfNewMonth(user) {
  const month = currentMonth();
  if (user.documents_month !== month) {
    db.prepare('UPDATE users SET documents_count = 0, documents_month = ? WHERE id = ?').run(month, user.id);
    return { ...user, documents_count: 0, documents_month: month };
  }
  return user;
}

function userPayload(user) {
  const isPro = user.plan === 'pro';
  const used = user.documents_count;
  const daysLeft = isPro && user.plan_expires_at > 0
    ? Math.ceil((user.plan_expires_at - Date.now()) / (1000 * 60 * 60 * 24))
    : null;
  return {
    id: user.id,
    email: user.email,
    plan: user.plan,
    planExpiresAt: user.plan_expires_at || null,
    planDaysLeft: daysLeft,
    planExpiringSoon: isPro && daysLeft !== null && daysLeft <= 3,
    documentsUsed: used,
    documentsRemaining: isPro ? null : Math.max(0, FREE_LIMIT - used),
    documentsLimit: isPro ? null : FREE_LIMIT,
    emailVerified: !!user.email_verified,
  };
}

function generateCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

async function sendVerificationEmail(email, code) {
  if (!RESEND_API_KEY) {
    console.log(`[DEV] Код для ${email}: ${code}`);
    return true;
  }
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: FROM_EMAIL,
      to: email,
      subject: 'Ваш код подтверждения — Документо',
      html: `
        <div style="font-family:Inter,sans-serif;max-width:480px;margin:0 auto;padding:32px 24px">
          <div style="font-size:1.4rem;font-weight:800;margin-bottom:24px">Документо</div>
          <p style="font-size:1rem;color:#333;margin-bottom:16px">Ваш код подтверждения:</p>
          <div style="font-size:2.5rem;font-weight:800;letter-spacing:0.15em;color:#6366f1;
                      background:#f0f0ff;border-radius:12px;padding:20px;text-align:center;
                      margin-bottom:24px">${code}</div>
          <p style="font-size:0.85rem;color:#888">Код действует 10 минут. Если вы не регистрировались — просто проигнорируйте письмо.</p>
        </div>
      `,
    }),
  });
  return res.ok;
}

// ─── Auth middleware ──────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Требуется авторизация' });
  }
  try {
    const payload = jwt.verify(header.slice(7), JWT_SECRET);
    let user = getUserById(payload.userId);
    if (!user) return res.status(401).json({ error: 'Пользователь не найден' });
    user = checkAndExpirePlan(user);
    user = resetUserCountIfNewMonth(user);
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Недействительный токен' });
  }
}

// ─── Шаг 1: Отправить код на email ───────────────────────────────────────────
app.post('/api/verify/send', async (req, res) => {
  const { email } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Некорректный email' });
  }

  const emailLower = email.toLowerCase();

  // Проверяем не зарегистрирован ли уже
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(emailLower);
  if (existing) return res.status(409).json({ error: 'Пользователь с таким email уже существует' });

  // Rate limit: не чаще раза в минуту
  const prev = db.prepare('SELECT expires_at FROM email_verifications WHERE email = ?').get(emailLower);
  if (prev && prev.expires_at - CODE_TTL_MS + 60000 > Date.now()) {
    return res.status(429).json({ error: 'Подождите минуту перед повторной отправкой' });
  }

  const code = generateCode();
  const expiresAt = Date.now() + CODE_TTL_MS;

  db.prepare(`
    INSERT INTO email_verifications (email, code, expires_at, attempts)
    VALUES (?, ?, ?, 0)
    ON CONFLICT(email) DO UPDATE SET code = excluded.code, expires_at = excluded.expires_at, attempts = 0
  `).run(emailLower, code, expiresAt);

  const sent = await sendVerificationEmail(emailLower, code);
  if (!sent) return res.status(500).json({ error: 'Не удалось отправить письмо. Попробуйте позже.' });

  res.json({ ok: true, message: 'Код отправлен на ' + emailLower });
});

// ─── Шаг 2: Проверить код и зарегистрировать ─────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { email, password, code } = req.body;

  if (!email || !password) return res.status(400).json({ error: 'Укажите email и пароль' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Некорректный email' });
  if (password.length < 6) return res.status(400).json({ error: 'Пароль должен быть не менее 6 символов' });
  if (!code) return res.status(400).json({ error: 'Введите код подтверждения' });

  const emailLower = email.toLowerCase();

  // Проверяем код
  const verification = db.prepare('SELECT * FROM email_verifications WHERE email = ?').get(emailLower);

  if (!verification) return res.status(400).json({ error: 'Сначала запросите код подтверждения' });
  if (Date.now() > verification.expires_at) return res.status(400).json({ error: 'Код истёк. Запросите новый.' });
  if (verification.attempts >= 5) return res.status(429).json({ error: 'Слишком много попыток. Запросите новый код.' });

  if (verification.code !== String(code).trim()) {
    db.prepare('UPDATE email_verifications SET attempts = attempts + 1 WHERE email = ?').run(emailLower);
    const left = 5 - (verification.attempts + 1);
    return res.status(400).json({ error: `Неверный код. Осталось попыток: ${left}` });
  }

  // Код верный — удаляем и создаём аккаунт
  db.prepare('DELETE FROM email_verifications WHERE email = ?').run(emailLower);

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(emailLower);
  if (existing) return res.status(409).json({ error: 'Пользователь уже существует' });

  try {
    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const result = db.prepare(
      'INSERT INTO users (email, password_hash, documents_month, plan, plan_expires_at, email_verified) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(emailLower, passwordHash, currentMonth(), 'free', 0, 1);

    const user = getUserById(result.lastInsertRowid);
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user: userPayload(user) });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ─── Login ────────────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Укажите email и пароль' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
  if (!user) return res.status(401).json({ error: 'Неверный email или пароль' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Неверный email или пароль' });

  let freshUser = getUserById(user.id);
  freshUser = checkAndExpirePlan(freshUser);
  freshUser = resetUserCountIfNewMonth(freshUser);

  const token = jwt.sign({ userId: freshUser.id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: userPayload(freshUser) });
});

app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ user: userPayload(req.user) });
});

// ─── Счётчик документов ───────────────────────────────────────────────────────
app.post('/api/documents/count', authMiddleware, (req, res) => {
  const user = req.user;

  if (user.plan === 'pro') {
    const newCount = user.documents_count + 1;
    db.prepare('UPDATE users SET documents_count = ? WHERE id = ?').run(newCount, user.id);
    return res.json({ used: newCount, remaining: null, limit: null, plan: 'pro' });
  }

  if (user.documents_count >= FREE_LIMIT) {
    return res.status(403).json({
      error: 'Лимит бесплатных документов исчерпан. Перейдите на Pro.',
      used: user.documents_count,
      remaining: 0,
      limit: FREE_LIMIT,
      plan: 'free',
    });
  }

  const newCount = user.documents_count + 1;
  db.prepare('UPDATE users SET documents_count = ?, documents_month = ? WHERE id = ?').run(
    newCount, currentMonth(), user.id
  );
  res.json({ used: newCount, remaining: FREE_LIMIT - newCount, limit: FREE_LIMIT, plan: 'free' });
});

// ─── Создание платежа ЮKassa ──────────────────────────────────────────────────
app.post('/api/payment/create', authMiddleware, async (req, res) => {
  if (!YUKASSA_SHOP_ID || !YUKASSA_SECRET_KEY) {
    return res.status(500).json({ error: 'Платёжная система временно недоступна' });
  }

  const userId = req.user.id;
  const idempotenceKey = crypto.randomUUID();
  const returnUrl = (req.headers.origin || 'https://mydokumento.ru') + '/success.html';

  try {
    const response = await fetch('https://api.yookassa.ru/v3/payments', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Idempotence-Key': idempotenceKey,
        'Authorization': 'Basic ' + Buffer.from(`${YUKASSA_SHOP_ID}:${YUKASSA_SECRET_KEY}`).toString('base64'),
      },
      body: JSON.stringify({
        amount: { value: '499.00', currency: 'RUB' },
        confirmation: { type: 'redirect', return_url: returnUrl },
        capture: true,
        description: 'Подписка Документо Pro на 1 месяц',
        metadata: { userId: String(userId) },
      }),
    });

    const payment = await response.json();
    if (!response.ok) {
      console.error('ЮKassa create error:', payment);
      return res.status(500).json({ error: 'Ошибка создания платежа' });
    }

    res.json({ url: payment.confirmation.confirmation_url, paymentId: payment.id });
  } catch (err) {
    console.error('Payment create error:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ─── Вебхук ЮKassa ───────────────────────────────────────────────────────────
app.post('/webhook/yukassa', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    const expected = 'Basic ' + Buffer.from(`${YUKASSA_SHOP_ID}:${YUKASSA_SECRET_KEY}`).toString('base64');
    if (authHeader !== expected) {
      console.warn('ЮKassa webhook: неверная авторизация');
      return res.status(401).send('Unauthorized');
    }

    const body = JSON.parse(req.body.toString('utf8'));
    const { event, object } = body;
    console.log(`ЮKassa webhook: ${event}`, object?.id);

    if (event === 'payment.succeeded') {
      const payment = object;
      const paidAmount = parseFloat(payment.amount?.value || '0') * 100;
      if (paidAmount < PRO_PRICE) return res.status(200).send('OK');

      const userId = parseInt(payment.metadata?.userId, 10);
      if (!userId || isNaN(userId)) return res.status(200).send('OK');

      const user = db.prepare('SELECT id, plan, plan_expires_at FROM users WHERE id = ?').get(userId);
      if (!user) return res.status(200).send('OK');

      const baseTime = user.plan === 'pro' && user.plan_expires_at > Date.now()
        ? user.plan_expires_at : Date.now();
      const expiresAt = baseTime + PRO_DURATION_MS;

      db.prepare('UPDATE users SET plan = ?, plan_expires_at = ? WHERE id = ?').run('pro', expiresAt, userId);
      console.log(`✅ ЮKassa: пользователь ${userId} → Pro до ${new Date(expiresAt).toISOString()}`);
      return res.status(200).send('OK');
    }

    if (event === 'refund.succeeded') {
      const refund = object;
      let userId = parseInt(refund.metadata?.userId, 10);

      if (!userId || isNaN(userId)) {
        try {
          const paymentId = refund.payment_id;
          if (paymentId) {
            const pr = await fetch(`https://api.yookassa.ru/v3/payments/${paymentId}`, {
              headers: { 'Authorization': 'Basic ' + Buffer.from(`${YUKASSA_SHOP_ID}:${YUKASSA_SECRET_KEY}`).toString('base64') }
            });
            const pd = await pr.json();
            userId = parseInt(pd.metadata?.userId, 10);
          }
        } catch (e) {
          console.error('ЮKassa refund: ошибка получения платежа', e);
        }
      }

      if (!userId || isNaN(userId)) return res.status(200).send('OK');

      db.prepare('UPDATE users SET plan = ?, plan_expires_at = 0 WHERE id = ?').run('free', userId);
      console.log(`↩️ ЮKassa: пользователь ${userId} → возврат, план сброшен на free`);
      return res.status(200).send('OK');
    }

    return res.status(200).send('OK');
  } catch (err) {
    console.error('Webhook error:', err);
    res.status(500).send('Error');
  }
});

// ─── Catch-all ────────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Документо запущен: http://localhost:${PORT}`);
});
