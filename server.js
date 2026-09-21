require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { Pool } = require('pg');
const PDFDocument = require('pdfkit');

/* =====================================================================
 *  KONFIGURASI
 * ===================================================================== */
const PORT = Number(process.env.PORT) || 3000;
const APP_PIN = String(process.env.APP_PIN || '').trim();
const SESSION_SECRET = process.env.SESSION_SECRET || APP_PIN;
const SESSION_DAYS = Number(process.env.SESSION_DAYS) || 0;
const REPORT_NAME = process.env.REPORT_NAME || 'Laporan Mingguan';
const REPORT_ORG = process.env.REPORT_ORG || 'LPK ZENITH';
const APP_TIMEZONE = process.env.APP_TIMEZONE || 'Asia/Makassar';
const PDF_FONT_SIZE = Number(process.env.PDF_FONT_SIZE) || 14;

const PUBLIC_DIR = path.join(__dirname, 'public');
const LOGO_PATH = path.join(PUBLIC_DIR, 'logo.png');
const COOKIE_NAME = 'zr_session';

if (!process.env.DATABASE_URL) {
  console.error('[FATAL] DATABASE_URL belum diatur di file .env');
  process.exit(1);
}
if (!APP_PIN) {
  console.error('[FATAL] APP_PIN belum diatur di file .env');
  process.exit(1);
}

// Font opsional untuk karakter non-Latin (Jepang, dll) pada PDF
let FALLBACK_FONT = null;
if (process.env.PDF_UNICODE_FONT) {
  const p = path.resolve(__dirname, process.env.PDF_UNICODE_FONT);
  if (fs.existsSync(p)) FALLBACK_FONT = p;
  else console.warn('[PDF] PDF_UNICODE_FONT tidak ditemukan:', p);
}

/* =====================================================================
 *  DATABASE (Neon PostgreSQL)
 * ===================================================================== */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});
pool.on('error', (err) => console.error('[DB] Idle client error:', err.message));

const ACTIVITY_COLS =
  "id, title, to_char(activity_date, 'YYYY-MM-DD') AS date, notes";

/* =====================================================================
 *  UTIL TANGGAL (semua berbasis string ISO "YYYY-MM-DD", tanpa zona waktu)
 * ===================================================================== */
const HARI = ['Minggu', 'Senin', 'Selasa', 'Rabu', 'Kamis', 'Jumat', 'Sabtu'];
const BULAN = [
  'Januari', 'Februari', 'Maret', 'April', 'Mei', 'Juni',
  'Juli', 'Agustus', 'September', 'Oktober', 'November', 'Desember',
];
const ISO_RE = /^\d{4}-\d{2}-\d{2}$/;

const parseISO = (s) => {
  const [y, m, d] = s.split('-').map(Number);
  return new Date(Date.UTC(y, m - 1, d));
};
const toISO = (d) => d.toISOString().slice(0, 10);
const isValidISODate = (s) => {
  if (typeof s !== 'string' || !ISO_RE.test(s)) return false;
  const d = parseISO(s);
  return !Number.isNaN(d.getTime()) && toISO(d) === s;
};
const addDays = (iso, n) => {
  const d = parseISO(iso);
  d.setUTCDate(d.getUTCDate() + n);
  return toISO(d);
};
const mondayOf = (iso) => {
  const d = parseISO(iso);
  const dow = d.getUTCDay();
  d.setUTCDate(d.getUTCDate() + (dow === 0 ? -6 : 1 - dow));
  return toISO(d);
};
const longDate = (iso) => {
  const d = parseISO(iso);
  return `${HARI[d.getUTCDay()]}, ${d.getUTCDate()} ${BULAN[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
};
const todayISO = () =>
  new Intl.DateTimeFormat('en-CA', {
    timeZone: APP_TIMEZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(new Date());

function periodLabel(from, to, forceYear = false) {
  const a = parseISO(from);
  const b = parseISO(to);
  const sameYear = a.getUTCFullYear() === b.getUTCFullYear();
  const sameMonth = sameYear && a.getUTCMonth() === b.getUTCMonth();
  const part = (d, y) =>
    `${d.getUTCDate()} ${BULAN[d.getUTCMonth()]}${y ? ' ' + d.getUTCFullYear() : ''}`;

  if (from === to) return part(a, true);
  if (sameMonth && !forceYear) return `${a.getUTCDate()}-${b.getUTCDate()} ${BULAN[b.getUTCMonth()]}`;
  if (sameYear && !forceYear) return `${part(a, false)} - ${part(b, false)}`;
  return `${part(a, true)} - ${part(b, true)}`;
}

/* =====================================================================
 *  AUTENTIKASI (middleware berbasis PIN + cookie tertanda tangan)
 * ===================================================================== */
const EXPECTED_TOKEN = crypto
  .createHmac('sha256', SESSION_SECRET)
  .update('zenith-report-auth:' + APP_PIN)
  .digest('hex');

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(';').forEach((part) => {
    const idx = part.indexOf('=');
    if (idx < 0) return;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    try {
      out[key] = decodeURIComponent(val);
    } catch {
      out[key] = val;
    }
  });
  return out;
}

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function isAuthed(req) {
  const token = parseCookies(req.headers.cookie)[COOKIE_NAME];
  return Boolean(token) && safeEqual(token, EXPECTED_TOKEN);
}

// Middleware untuk halaman HTML: belum login -> redirect ke /login
function requirePage(req, res, next) {
  if (isAuthed(req)) return next();
  return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
}

// Middleware untuk API: belum login -> 401 JSON
function requireApi(req, res, next) {
  if (isAuthed(req)) return next();
  return res.status(401).json({ message: 'Sesi berakhir. Silakan masukkan PIN kembali.' });
}

/* =====================================================================
 *  HALAMAN LOGIN (di-embed agar struktur file tetap sederhana)
 *  Catatan: script di dalam template ini sengaja tanpa backtick / ${}
 * ===================================================================== */
const LOGIN_HTML = `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#e4efdb">
<title>Masukkan PIN · Hiro Zenith Report</title>
<script src="https://cdn.tailwindcss.com"></script>
<script>
tailwind.config = { theme: { extend: {
  fontFamily: { sans: ['Nunito', 'ui-sans-serif', 'system-ui', 'sans-serif'] },
  colors: {
    leaf: { 50:'#f3f8ef',100:'#e4efdb',200:'#cbe1bb',300:'#a9cf94',400:'#86b872',500:'#679d55',600:'#4f7f42',700:'#3f6537',800:'#34512f',900:'#2b4328' },
    cream: { 50:'#fdfcf6',100:'#faf7ea',200:'#f3edd3' },
    sky2: { 100:'#e3f1f4',200:'#c7e3ea',400:'#7fb9c8' },
    peach: { 100:'#fdeedd',200:'#fadcbb',400:'#eea86c',600:'#c8823f' },
    rose2: { 100:'#fbe6e4',200:'#f6cbc7',400:'#e28f88',600:'#c4574f' }
  },
  keyframes: { pop: { '0%': { opacity: 0, transform: 'translateY(-8px) scale(.98)' }, '100%': { opacity: 1, transform: 'none' } },
               shake: { '0%,100%': { transform: 'translateX(0)' }, '25%': { transform: 'translateX(-6px)' }, '75%': { transform: 'translateX(6px)' } } },
  animation: { pop: 'pop .25s ease-out', shake: 'shake .35s ease-in-out' }
} } };
</script>
<style>
/* Hilangkan tanda panah pada input number */
input[type="number"]::-webkit-inner-spin-button,
input[type="number"]::-webkit-outer-spin-button {
    -webkit-appearance: none;
    margin: 0;
}
    </style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
</head>
<body class="font-sans text-leaf-900 min-h-screen antialiased">
<div class="fixed inset-0 -z-10 bg-gradient-to-b from-sky2-100 via-cream-50 to-leaf-200"></div>
<div class="fixed -z-10 top-10 -left-16 w-56 h-56 rounded-full bg-white/60 blur-2xl"></div>
<div class="fixed -z-10 bottom-10 -right-16 w-64 h-64 rounded-full bg-leaf-200/70 blur-2xl"></div>

<div id="alertBox" class="fixed top-4 inset-x-0 z-50 px-4 pointer-events-none"></div>

<main class="min-h-screen flex items-center justify-center px-5 py-10">
  <div class="w-full max-w-sm">
    <div class="bg-white/85 backdrop-blur rounded-[2rem] border border-leaf-100 shadow-xl shadow-leaf-500/10 p-7">
      <div class="flex flex-col items-center text-center">
        <div class="w-20 h-20 rounded-3xl bg-cream-50 border border-leaf-100 flex items-center justify-center overflow-hidden">
          <img src="/logo.png" alt="Logo" class="w-14 h-14 object-contain" onerror="this.style.display='none';this.nextElementSibling.style.display='block'">
          <i class="fa-solid fa-leaf text-3xl text-leaf-500" style="display:none"></i>
        </div>
        <h1 class="mt-4 text-xl font-extrabold text-leaf-900">Hiro Zenith Report</h1>
        <p class="mt-1 text-sm text-leaf-600">Masukkan PIN untuk membuka laporan harianmu</p>
      </div>

      <div id="pinWrap" class="mt-6">
        <label for="pin" class="block text-sm font-bold text-leaf-800 mb-2">PIN</label>
        <div class="relative">
          <input id="pin" type="number" autocomplete="off" autofocus placeholder="••••••"
            class="w-full h-14 rounded-2xl border-2 border-leaf-200 bg-white px-4 pr-14 text-center text-xl tracking-[0.35em] font-bold text-leaf-900 placeholder:tracking-normal placeholder:text-leaf-300 outline-none focus:border-leaf-500 focus:ring-4 focus:ring-leaf-200/60">
          <div id="togglePin" role="button" tabindex="0" aria-label="Tampilkan PIN"
            class="absolute right-2 top-1/2 -translate-y-1/2 w-10 h-10 rounded-xl flex items-center justify-center text-leaf-500 hover:bg-leaf-100 cursor-pointer">
            <i class="fa-solid fa-eye"></i>
          </div>
        </div>
      </div>

      <button id="btnLogin" class="mt-5 w-full h-14 rounded-2xl bg-leaf-500 hover:bg-leaf-600 active:scale-[.98] transition text-white text-base font-extrabold shadow-md shadow-leaf-500/30 flex items-center justify-center gap-2">
        <i class="fa-solid fa-lock-open"></i><span>Masuk</span>
      </button>
    </div>
    <p class="text-center text-xs text-leaf-600 mt-5">Daily Report - Hiro</p>
  </div>
</main>

<script>
(function () {
  var pin = document.getElementById('pin');
  var btn = document.getElementById('btnLogin');
  var alertBox = document.getElementById('alertBox');
  var wrap = document.getElementById('pinWrap');
  var busy = false;

  function showAlert(type, msg) {
    var styles = {
      error: 'bg-rose2-100 border-rose2-200 text-rose2-600',
      success: 'bg-leaf-100 border-leaf-300 text-leaf-800'
    };
    var icon = type === 'error' ? 'fa-circle-exclamation' : 'fa-circle-check';
    alertBox.innerHTML =
      '<div class="max-w-sm mx-auto pointer-events-auto animate-pop flex items-start gap-3 rounded-2xl border px-4 py-3 shadow-lg ' + styles[type] + '">' +
      '<i class="fa-solid ' + icon + ' mt-0.5"></i><p class="text-sm font-bold flex-1"></p></div>';
    alertBox.querySelector('p').textContent = msg;
    clearTimeout(showAlert.t);
    showAlert.t = setTimeout(function () { alertBox.innerHTML = ''; }, 3500);
  }

  function safeNext() {
    var n = new URLSearchParams(location.search).get('next');
    if (n && n.charAt(0) === '/' && n.charAt(1) !== '/') return n;
    return '/';
  }

  async function submit() {
    if (busy) return;
    var value = pin.value;
    if (!value) {
      showAlert('error', 'PIN wajib diisi.');
      pin.focus();
      return;
    }
    busy = true;
    btn.disabled = true;
    btn.classList.add('opacity-70');
    try {
      var res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pin: value })
      });
      var data = {};
      try { data = await res.json(); } catch (e) {}
      if (!res.ok) throw new Error(data.message || 'Gagal masuk.');
      showAlert('success', 'PIN benar. Membuka aplikasi...');
      setTimeout(function () { location.replace(safeNext()); }, 350);
    } catch (err) {
      showAlert('error', err.message || 'Terjadi kesalahan.');
      pin.value = '';
      pin.focus();
      wrap.classList.remove('animate-shake');
      void wrap.offsetWidth;
      wrap.classList.add('animate-shake');
      busy = false;
      btn.disabled = false;
      btn.classList.remove('opacity-70');
    }
  }

  btn.addEventListener('click', submit);
  pin.addEventListener('keydown', function (e) { if (e.key === 'Enter') submit(); });
  document.getElementById('togglePin').addEventListener('click', function () {
    var show = pin.type === 'password';
    pin.type = show ? 'text' : 'password';
    this.innerHTML = show ? '<i class="fa-solid fa-eye-slash"></i>' : '<i class="fa-solid fa-eye"></i>';
  });
})();
</script>
</body>
</html>`;

/* =====================================================================
 *  APLIKASI EXPRESS
 * ===================================================================== */
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));

// Jangan simpan cache halaman/API (agar tombol back setelah logout aman)
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

/* ---------- Login / Logout ---------- */
app.get('/login', (req, res) => {
  if (isAuthed(req)) return res.redirect('/');
  res.type('html').send(LOGIN_HTML);
});

app.post('/api/login', (req, res) => {
  const pin = req.body && typeof req.body.pin === 'string' ? req.body.pin : '';
  if (!pin || !safeEqual(pin, APP_PIN)) {
    return res.status(401).json({ message: 'PIN salah. Silakan coba lagi.' });
  }
  const opts = { httpOnly: true, sameSite: 'lax', path: '/', secure: req.secure };
  if (SESSION_DAYS > 0) opts.maxAge = SESSION_DAYS * 24 * 60 * 60 * 1000;
  res.cookie(COOKIE_NAME, EXPECTED_TOKEN, opts);
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME, { path: '/' });
  res.json({ ok: true });
});

/* ---------- Halaman terproteksi ---------- */
const sendPage = (file) => (req, res) => res.sendFile(path.join(PUBLIC_DIR, file));

app.get('/', requirePage, sendPage('index.html'));
app.get('/statistic', requirePage, sendPage('statistic.html'));
app.get('/calendar', requirePage, sendPage('calender.html'));
app.get('/export', requirePage, sendPage('export.html'));

// Cegah akses langsung ke file .html lewat static (mis. /statistic.html)
app.use((req, res, next) => {
  if (req.path.toLowerCase().endsWith('.html')) return res.redirect('/');
  next();
});

// Aset publik non-HTML (logo, dll)
app.use(express.static(PUBLIC_DIR, { index: false, dotfiles: 'ignore' }));

/* ---------- Semua API di bawah ini wajib login ---------- */
app.use('/api', requireApi);

app.get('/api/config', (req, res) => {
  res.json({ name: REPORT_NAME, org: REPORT_ORG, today: todayISO() });
});

/* ---------- Pengaturan hari kerja ---------- */
app.get(
  '/api/settings',
  ah(async (req, res) => {
    const { rows } = await pool.query(
      'SELECT include_saturday, include_sunday FROM work_settings WHERE id = 1'
    );
    const r = rows[0] || {};
    res.json({
      includeSaturday: Boolean(r.include_saturday),
      includeSunday: Boolean(r.include_sunday),
    });
  })
);

app.put(
  '/api/settings',
  ah(async (req, res) => {
    const b = req.body || {};
    const sat = Boolean(b.includeSaturday);
    const sun = Boolean(b.includeSunday);
    await pool.query(
      `INSERT INTO work_settings (id, include_saturday, include_sunday, updated_at)
       VALUES (1, $1, $2, NOW())
       ON CONFLICT (id) DO UPDATE
         SET include_saturday = EXCLUDED.include_saturday,
             include_sunday   = EXCLUDED.include_sunday,
             updated_at       = NOW()`,
      [sat, sun]
    );
    res.json({ includeSaturday: sat, includeSunday: sun });
  })
);

/* ---------- Meta (tanggal pertama/terakhir, total) ---------- */
app.get(
  '/api/meta',
  ah(async (req, res) => {
    const { rows } = await pool.query(
      `SELECT to_char(MIN(activity_date), 'YYYY-MM-DD') AS first_date,
              to_char(MAX(activity_date), 'YYYY-MM-DD') AS last_date,
              COUNT(*)::int AS total
         FROM activities`
    );
    const r = rows[0];
    res.json({ firstDate: r.first_date, lastDate: r.last_date, total: r.total });
  })
);

/* ---------- CRUD Kegiatan ---------- */
function validateActivity(body) {
  const b = body || {};
  const title = typeof b.title === 'string' ? b.title.trim() : '';
  const date = typeof b.date === 'string' ? b.date.trim() : '';
  const notes = typeof b.notes === 'string' ? b.notes.trim() : '';
  const errors = [];
  if (!title) errors.push('Nama kegiatan wajib diisi.');
  else if (title.length > 255) errors.push('Nama kegiatan maksimal 255 karakter.');
  if (!isValidISODate(date)) errors.push('Tanggal tidak valid.');
  if (notes.length > 2000) errors.push('Catatan maksimal 2000 karakter.');
  return { errors, value: { title, date, notes: notes || null } };
}

function parseId(raw) {
  const id = Number.parseInt(raw, 10);
  return Number.isInteger(id) && id > 0 ? id : null;
}

app.get(
  '/api/activities',
  ah(async (req, res) => {
    const { from, to } = req.query;
    const cond = [];
    const params = [];
    if (from !== undefined) {
      if (!isValidISODate(from)) return res.status(400).json({ message: 'Parameter "from" tidak valid.' });
      params.push(from);
      cond.push(`activity_date >= $${params.length}`);
    }
    if (to !== undefined) {
      if (!isValidISODate(to)) return res.status(400).json({ message: 'Parameter "to" tidak valid.' });
      params.push(to);
      cond.push(`activity_date <= $${params.length}`);
    }
    const where = cond.length ? 'WHERE ' + cond.join(' AND ') : '';
    const { rows } = await pool.query(
      `SELECT ${ACTIVITY_COLS} FROM activities ${where} ORDER BY activity_date ASC, id ASC`,
      params
    );
    res.json(rows);
  })
);

app.get(
  '/api/activities/:id',
  ah(async (req, res) => {
    const id = parseId(req.params.id);
    if (!id) return res.status(400).json({ message: 'ID tidak valid.' });
    const { rows } = await pool.query(`SELECT ${ACTIVITY_COLS} FROM activities WHERE id = $1`, [id]);
    if (!rows.length) return res.status(404).json({ message: 'Kegiatan tidak ditemukan.' });
    res.json(rows[0]);
  })
);

app.post(
  '/api/activities',
  ah(async (req, res) => {
    const { errors, value } = validateActivity(req.body);
    if (errors.length) return res.status(400).json({ message: errors.join(' ') });
    const { rows } = await pool.query(
      `INSERT INTO activities (title, activity_date, notes)
       VALUES ($1, $2, $3)
       RETURNING ${ACTIVITY_COLS}`,
      [value.title, value.date, value.notes]
    );
    res.status(201).json(rows[0]);
  })
);

app.put(
  '/api/activities/:id',
  ah(async (req, res) => {
    const id = parseId(req.params.id);
    if (!id) return res.status(400).json({ message: 'ID tidak valid.' });
    const { errors, value } = validateActivity(req.body);
    if (errors.length) return res.status(400).json({ message: errors.join(' ') });
    const { rows } = await pool.query(
      `UPDATE activities
          SET title = $1, activity_date = $2, notes = $3, updated_at = NOW()
        WHERE id = $4
        RETURNING ${ACTIVITY_COLS}`,
      [value.title, value.date, value.notes, id]
    );
    if (!rows.length) return res.status(404).json({ message: 'Kegiatan tidak ditemukan.' });
    res.json(rows[0]);
  })
);

app.delete(
  '/api/activities/:id',
  ah(async (req, res) => {
    const id = parseId(req.params.id);
    if (!id) return res.status(400).json({ message: 'ID tidak valid.' });
    const { rowCount } = await pool.query('DELETE FROM activities WHERE id = $1', [id]);
    if (!rowCount) return res.status(404).json({ message: 'Kegiatan tidak ditemukan.' });
    res.json({ ok: true });
  })
);

/* =====================================================================
 *  EXPORT PDF  (meniru format dokumen LAPORAN MINGGUAN LPK ZENITH)
 * ===================================================================== */
// PENTING: sengaja TIDAK pakai nama font bawaan pdfkit ('Times-Roman', 'Helvetica', dst).
// Semua font "standar 14" pdfkit (termasuk Helvetica/font default-nya) di-load lewat mekanisme
// internal package yang riskan gagal di lingkungan serverless seperti Vercel (file pendukungnya
// tidak selalu ikut ter-bundle). Jadi gantinya kita pakai file .ttf sendiri yang taruh di
// public/fonts/ - pasti ikut ke-deploy karena bagian dari folder public/ project ini juga.
const FONT_DIR = path.join(PUBLIC_DIR, 'fonts');
const STD_FONT_FILES = {
  regular: path.join(FONT_DIR, 'Tinos-Regular.ttf'),
  bold: path.join(FONT_DIR, 'Tinos-Bold.ttf'),
  italic: path.join(FONT_DIR, 'Tinos-Italic.ttf'),
};
// Fallback darurat: kalau file font kustom di atas ternyata tidak ketemu (misal lupa ikut commit/
// deploy), tetap coba jalan pakai font bawaan pdfkit supaya tidak 100% mati - tapi ini kembali
// berisiko sama seperti masalah awal, jadi selalu cek log berikut di production.
const STD_FONT = {
  regular: fs.existsSync(STD_FONT_FILES.regular) ? STD_FONT_FILES.regular : 'Helvetica',
  bold: fs.existsSync(STD_FONT_FILES.bold) ? STD_FONT_FILES.bold : 'Helvetica-Bold',
  italic: fs.existsSync(STD_FONT_FILES.italic) ? STD_FONT_FILES.italic : 'Helvetica-Oblique',
};
if (STD_FONT.regular === 'Helvetica') {
  console.warn('[PDF] File font kustom tidak ditemukan di', FONT_DIR, '- fallback ke font bawaan pdfkit (berisiko gagal lagi di production).');
}
// Karakter di luar WinAnsi tidak bisa dirender font bawaan PDF
const NON_LATIN = /[^\u0000-\u00FF\u2013\u2014\u2018\u2019\u201C\u201D\u2022\u2026\u20AC]/;
const NON_LATIN_G = new RegExp(NON_LATIN.source, 'g');

const cleanText = (s) => {
  let t = String(s || '')
    .replace(/\r/g, '')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '');
  if (!FALLBACK_FONT) t = t.replace(NON_LATIN_G, '?');
  return t;
};

function renderReportPdf(res, { title, periode, name, days, filename, inline }) {
  const MARGIN = 72; // 1 inci, sama seperti dokumen contoh
  const BODY = PDF_FONT_SIZE;
  const NOTE = Math.max(BODY - 2, 8);
  const GAP = 2; // lineGap

  const doc = new PDFDocument({
    size: 'A4',
    margins: { top: MARGIN, bottom: MARGIN, left: MARGIN, right: MARGIN },
    info: { Title: title, Author: name, Subject: 'Periode ' + periode },
  });

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `${inline ? 'inline' : 'attachment'}; filename="${filename}"`);
  doc.pipe(res);

  const L = MARGIN;
  const W = doc.page.width - MARGIN * 2;
  const MAX_Y = () => doc.page.height - MARGIN;
  let y = MARGIN;

  const useFont = (style, text) => {
    if (FALLBACK_FONT && NON_LATIN.test(text)) doc.font(FALLBACK_FONT);
    else doc.font(STD_FONT[style]);
  };
  const heightOf = (text, width, style, size) => {
    useFont(style, text);
    doc.fontSize(size);
    return doc.heightOfString(text, { width, lineGap: GAP });
  };
  const put = (text, x, yy, width, style, size, align = 'left') => {
    useFont(style, text);
    doc.fontSize(size).text(text, x, yy, { width, lineGap: GAP, align });
  };
  const ensure = (h) => {
    if (y + h > MAX_Y() + 0.5) {
      doc.addPage();
      y = MARGIN;
    }
  };

  /* --- Kop: logo, judul, periode, nama, garis --- */
  if (fs.existsSync(LOGO_PATH)) {
    try {
      const img = doc.openImage(LOGO_PATH);
      const h = 64;
      const w = (img.width * h) / img.height;
      doc.image(img, (doc.page.width - w) / 2, y, { width: w, height: h });
      y += h + 14;
    } catch (e) {
      console.warn('[PDF] Logo gagal dimuat:', e.message);
    }
  }

  [
    [cleanText(title), 12],
    [cleanText('Periode : ' + periode), 12],
    [cleanText(name), 4],
  ].forEach(([text, gap]) => {
    const h = heightOf(text, W, 'bold', BODY);
    put(text, L, y, W, 'bold', BODY, 'center');
    y += h + gap;
  });
  doc.save().lineWidth(1).strokeColor('#000').moveTo(L, y).lineTo(L + W, y).stroke().restore();
  y += 16;

  /* --- Isi: per hari, daftar bernomor --- */
  const NUM_X = L + 6;
  const NUM_W = 26;
  const TEXT_X = L + 40;
  const TEXT_W = W - 40;

  const itemHeight = (it) => {
    let h = heightOf(it.title, TEXT_W, 'regular', BODY);
    if (it.notes) h += 2 + heightOf('Catatan: ' + it.notes, TEXT_W, 'italic', NOTE);
    return h + 4;
  };

  days.forEach((day) => {
    const items = day.items.map((it) => ({
      title: cleanText(it.title),
      notes: it.notes ? cleanText(it.notes) : '',
    }));
    const heading = cleanText(longDate(day.date));
    const hh = heightOf(heading, W, 'bold', BODY);

    // Judul hari tidak boleh sendirian di dasar halaman
    ensure(hh + 4 + itemHeight(items[0]));
    put(heading, L, y, W, 'bold', BODY);
    y += hh + 4;

    items.forEach((it, i) => {
      const h = itemHeight(it);
      ensure(h);
      put(`${i + 1}.`, NUM_X, y, NUM_W, 'regular', BODY, 'right');
      put(it.title, TEXT_X, y, TEXT_W, 'regular', BODY);
      let yy = y + heightOf(it.title, TEXT_W, 'regular', BODY);
      if (it.notes) {
        yy += 2;
        doc.fillColor('#444');
        put('Catatan: ' + it.notes, TEXT_X, yy, TEXT_W, 'italic', NOTE);
        doc.fillColor('#000');
      }
      y += h;
    });
    y += 8;
  });

  doc.end();
}

app.get(
  '/api/export/pdf',
  ah(async (req, res) => {
    const mode = String(req.query.mode || '');
    if (!['weekday', 'fullweek', 'all'].includes(mode)) {
      return res.status(400).json({ message: 'Mode export tidak valid.' });
    }

    let from;
    let to;
    let rows;

    if (mode === 'all') {
      ({ rows } = await pool.query(
        `SELECT ${ACTIVITY_COLS} FROM activities ORDER BY activity_date ASC, id ASC`
      ));
      if (rows.length) {
        from = rows[0].date;
        to = rows[rows.length - 1].date;
      }
    } else {
      const ref = isValidISODate(req.query.week) ? req.query.week : todayISO();
      from = mondayOf(ref);
      to = addDays(from, mode === 'weekday' ? 4 : 6);
      ({ rows } = await pool.query(
        `SELECT ${ACTIVITY_COLS} FROM activities
          WHERE activity_date BETWEEN $1 AND $2
          ORDER BY activity_date ASC, id ASC`,
        [from, to]
      ));
    }

    if (!rows.length) {
      return res.status(404).json({ message: 'Belum ada kegiatan pada periode yang dipilih.' });
    }

    // Kelompokkan per tanggal
    const byDate = new Map();
    rows.forEach((r) => {
      if (!byDate.has(r.date)) byDate.set(r.date, []);
      byDate.get(r.date).push({ title: r.title, notes: r.notes });
    });
    const days = [...byDate.entries()].map(([date, items]) => ({ date, items }));

    const isAll = mode === 'all';
    renderReportPdf(res, {
      title: isAll ? `LAPORAN KEGIATAN ${REPORT_ORG}` : `LAPORAN MINGGUAN ${REPORT_ORG}`,
      periode: periodLabel(from, to, isAll),
      name: REPORT_NAME,
      days,
      filename: `Laporan_${isAll ? 'Semua' : 'Mingguan'}_${from}_sd_${to}.pdf`,
      inline: req.query.inline === '1',
    });
  })
);

/* =====================================================================
 *  404 & ERROR HANDLER
 * ===================================================================== */
app.use('/api', (req, res) => res.status(404).json({ message: 'Endpoint tidak ditemukan.' }));

app.use((req, res) => {
  if (!isAuthed(req)) return res.redirect('/login');
  res.status(404).type('text').send('Halaman tidak ditemukan.');
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[ERROR]', err);
  if (res.headersSent) return;
  const status = err.status && err.status < 500 ? err.status : 500;
  res.status(status).json({
    message: status < 500 ? err.message : 'Terjadi kesalahan pada server.',
  });
});

/* =====================================================================
 *  START
 * ===================================================================== */
app.listen(PORT, async () => {
  console.log(`[SERVER] Berjalan di http://localhost:${PORT}`);
  try {
    await pool.query('SELECT 1');
    console.log('[DB] Terhubung ke Neon PostgreSQL');
  } catch (err) {
    console.error('[DB] Gagal terhubung:', err.message);
  }
});

process.on('SIGTERM', async () => {
  await pool.end().catch(() => {});
  process.exit(0);
});