require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');

const PORT = process.env.PORT || 3000;
const OTP_TTL_MS = 5 * 60 * 1000;       // kode berlaku 5 menit
const MAX_TRIES = 5;                    // maksimal salah 5 kali
const RESEND_COOLDOWN_MS = 60 * 1000;   // kirim ulang tiap 60 detik
const USER_RE = /^[a-zA-Z0-9_.]{3,20}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ---- Penyimpanan akun: file JSON (cukup untuk uji coba).
// Untuk produksi, ganti dengan database sungguhan (PostgreSQL, MySQL, dll).
const DB_FILE = path.join(__dirname, 'data', 'users.json');
fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
const loadUsers = () => { try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch { return []; } };
const saveUsers = (u) => fs.writeFileSync(DB_FILE, JSON.stringify(u, null, 2));

// Pendaftaran yang menunggu verifikasi (di memori). email -> data
const pending = new Map();
setInterval(() => {
  for (const [k, p] of pending) if (Date.now() > p.expires + 30 * 60 * 1000) pending.delete(k);
}, 10 * 60 * 1000).unref();

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: process.env.SMTP_SECURE === 'true',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});

async function issueOtp(p) {
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  p.otpHash = await bcrypt.hash(code, 8);    // kode disimpan dalam bentuk hash
  p.expires = Date.now() + OTP_TTL_MS;
  p.attempts = 0;
  p.lastSent = Date.now();
  await transporter.sendMail({
    from: process.env.MAIL_FROM || process.env.SMTP_USER,
    to: p.email,
    subject: 'Kode verifikasi kamu',
    text: `Kode verifikasi kamu: ${code}\nBerlaku 5 menit. Jika bukan kamu yang mendaftar, abaikan email ini.`,
    html: `<div style="font-family:Arial,sans-serif;max-width:420px">
      <p>Kode verifikasi kamu:</p>
      <p style="font-size:32px;letter-spacing:8px;font-weight:700;margin:12px 0">${code}</p>
      <p style="color:#666">Berlaku 5 menit. Jika bukan kamu yang mendaftar, abaikan email ini.</p></div>`
  });
}

const DUMMY_HASH = bcrypt.hashSync('dummy-password', 10);
const app = express();
app.use(express.json({ limit: '10kb' }));
app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, limit: 60, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Terlalu banyak permintaan. Coba lagi beberapa menit lagi.' } }));
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/register', async (req, res) => {
  const { username = '', email = '', password = '' } = req.body || {};
  const u = String(username).trim();
  const e = String(email).trim().toLowerCase();
  if (!USER_RE.test(u)) return res.status(400).json({ field: 'username', error: 'Username 3–20 karakter: huruf, angka, titik, atau garis bawah.' });
  if (!EMAIL_RE.test(e)) return res.status(400).json({ field: 'email', error: 'Format email belum benar.' });
  if (String(password).length < 8) return res.status(400).json({ field: 'password', error: 'Password minimal 8 karakter.' });

  const users = loadUsers();
  if (users.some(x => x.username.toLowerCase() === u.toLowerCase())) return res.status(409).json({ field: 'username', error: 'Username sudah dipakai.' });
  if (users.some(x => x.email === e)) return res.status(409).json({ field: 'email', error: 'Email sudah terdaftar.' });

  const p = { username: u, email: e, passwordHash: await bcrypt.hash(String(password), 10) };
  pending.set(e, p);
  try { await issueOtp(p); }
  catch (err) {
    console.error('Gagal kirim email:', err.message);
    pending.delete(e);
    return res.status(502).json({ error: 'Gagal mengirim email. Periksa pengaturan SMTP di file .env.' });
  }
  res.json({ ok: true });
});

app.post('/api/resend-otp', async (req, res) => {
  const e = String(req.body?.email || '').trim().toLowerCase();
  const p = pending.get(e);
  if (!p) return res.status(404).json({ error: 'Sesi pendaftaran tidak ditemukan. Silakan daftar ulang.' });
  const wait = Math.ceil((p.lastSent + RESEND_COOLDOWN_MS - Date.now()) / 1000);
  if (wait > 0) return res.status(429).json({ error: `Tunggu ${wait} detik sebelum kirim ulang.` });
  try { await issueOtp(p); }
  catch (err) { console.error('Gagal kirim email:', err.message); return res.status(502).json({ error: 'Gagal mengirim email.' }); }
  res.json({ ok: true });
});

app.post('/api/verify-otp', async (req, res) => {
  const e = String(req.body?.email || '').trim().toLowerCase();
  const code = String(req.body?.code || '');
  const p = pending.get(e);
  if (!p) return res.status(404).json({ error: 'Sesi pendaftaran tidak ditemukan. Silakan daftar ulang.' });
  if (Date.now() > p.expires) return res.status(400).json({ error: 'Kode sudah kedaluwarsa. Kirim ulang kode.' });
  if (p.attempts >= MAX_TRIES) return res.status(429).json({ error: 'Terlalu banyak percobaan. Kirim ulang kode.' });

  if (!(await bcrypt.compare(code, p.otpHash))) {
    p.attempts++;
    const left = MAX_TRIES - p.attempts;
    return res.status(400).json({ error: left > 0 ? `Kode tidak cocok. Sisa percobaan: ${left}.` : 'Terlalu banyak percobaan. Kirim ulang kode.' });
  }

  const users = loadUsers();
  users.push({ username: p.username, email: p.email, passwordHash: p.passwordHash, createdAt: new Date().toISOString() });
  saveUsers(users);
  pending.delete(e);
  res.json({ ok: true, username: p.username });
});

app.post('/api/login', async (req, res) => {
  const id = String(req.body?.identifier || '').trim().toLowerCase();
  const pw = String(req.body?.password || '');
  const user = loadUsers().find(x => x.username.toLowerCase() === id || x.email === id);
  const ok = await bcrypt.compare(pw, user ? user.passwordHash : DUMMY_HASH);
  if (!user || !ok) return res.status(401).json({ error: 'Username/email atau password salah.' });
  // TODO: buat sesi login (cookie httpOnly / JWT) di sini untuk dashboard kamu.
  res.json({ ok: true, username: user.username });
});

app.listen(PORT, () => console.log(`Server jalan di http://localhost:${PORT}`));
