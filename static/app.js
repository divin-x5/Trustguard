/* ============================================================
   TRUSTGUARD — app.js
   Matrix rain, custom cursor, scroll reveals, analyze + render.
   ============================================================ */
'use strict';

const $ = id => document.getElementById(id);

/* ---------- API base URL resolution ----------
   Priority:
     1. window.TRUSTGUARD_CONFIG.API_BASE_URL (edit static/config.js)
     2. auto: localhost -> http://localhost:8000, else same origin
   Works whether the page is served by FastAPI on :8000 or by
   GitHub Pages from a repository subpath. */
const LOCAL_API = 'http://localhost:8000';
const IS_LOCAL = /^(localhost|127\.0\.0\.1|\[::1\])$/.test(location.hostname);

function resolveApiBase() {
  const configured = (window.TRUSTGUARD_CONFIG?.API_BASE_URL || '').trim();
  if (configured) return configured.replace(/\/+$/, '');
  if (IS_LOCAL) return LOCAL_API;
  return location.origin; // same origin (e.g. FastAPI serving its own UI)
}

const API_BASE_URL = resolveApiBase();
const apiUrl = path => API_BASE_URL + path;

/* Human-readable host shown in the SYSTEM INTEL panel. */
function describeApi() {
  try {
    const u = new URL(API_BASE_URL);
    return u.host + (u.pathname === '/' ? '' : u.pathname);
  } catch {
    return API_BASE_URL || '(not configured)';
  }
}

const LEVELS = {
  SAFE:   { color: 'var(--green)', label: 'CLEAN',      icon: '[ OK ] ' },
  LOW:    { color: 'var(--amber)', label: 'LOW RISK',   icon: '[ .. ] ' },
  MEDIUM: { color: 'var(--amber)', label: 'MEDIUM RISK', icon: '[ !! ] ' },
  HIGH:   { color: 'var(--red)',   label: 'HIGH RISK',  icon: '[ ⚠ ] ' },
};

/* ---------- matrix rain ---------- */
const cv = $('rain');
const ctx = cv.getContext('2d');
const CHARS = 'アイウエオカキクケコ01ﾊﾋﾌﾍﾎ$#@&=%';
let cols, drops;

function sizeRain() {
  cv.width = innerWidth;
  cv.height = innerHeight;
  cols = Math.floor(cv.width / 16);
  drops = Array(cols).fill(0).map(() => Math.random() * -60);
}

function tickRain() {
  ctx.fillStyle = 'rgba(5,8,7,.09)';
  ctx.fillRect(0, 0, cv.width, cv.height);
  ctx.font = '13px "JetBrains Mono", monospace';
  drops.forEach((y, i) => {
    ctx.fillStyle = Math.random() < .04 ? '#b8ffe2' : 'rgba(0,255,156,.75)';
    ctx.fillText(CHARS[(Math.random() * CHARS.length) | 0], i * 16, y * 16);
    drops[i] = y * 16 > cv.height && Math.random() > .975 ? 0 : y + 1;
  });
}

sizeRain();
addEventListener('resize', sizeRain);
setInterval(tickRain, 60);

/* ---------- custom cursor ---------- */
const cur = $('cur');
const curdot = $('curdot');
let mx = -100, my = -100, rx = -100, ry = -100;

addEventListener('mousemove', e => {
  mx = e.clientX;
  my = e.clientY;
  curdot.style.left = mx + 'px';
  curdot.style.top = my + 'px';
});

(function follow() {
  rx += (mx - rx) * .16;
  ry += (my - ry) * .16;
  cur.style.left = rx + 'px';
  cur.style.top = ry + 'px';
  requestAnimationFrame(follow);
})();

function wireCursor() {
  document.querySelectorAll('button, textarea, a').forEach(el => {
    el.addEventListener('mouseenter', () => cur.classList.add('hovering'));
    el.addEventListener('mouseleave', () => cur.classList.remove('hovering'));
  });
}
wireCursor();

/* ---------- scroll: progress bar + reveal cards ---------- */
addEventListener('scroll', () => {
  const h = document.documentElement;
  const max = h.scrollHeight - h.clientHeight;
  $('progress').style.width = (max > 0 ? (h.scrollTop / max) * 100 : 0) + '%';
});

const io = new IntersectionObserver(
  entries => entries.forEach(e => {
    if (e.isIntersecting) {
      e.target.classList.add('in');
      io.unobserve(e.target);
    }
  }),
  { threshold: .12 }
);

function observeReveals() {
  document.querySelectorAll('.reveal:not(.in)').forEach(el => io.observe(el));
}
observeReveals();
new MutationObserver(observeReveals).observe(document.body, { childList: true });

/* ---------- API connectivity indicator ---------- */
async function checkApi() {
  const hostEl = $('apiHost');
  const statusEl = $('apiStatus');
  if (hostEl) hostEl.textContent = describeApi();
  if (!statusEl) return;

  // An explicit http:// URL on an https:// page can never work: the browser
  // blocks it as mixed content before the request is even sent.
  if (/^http:\/\//i.test(API_BASE_URL) && location.protocol === 'https:') {
    statusEl.className = 'bad';
    statusEl.textContent = '✕ blocked — API must be https';
    return;
  }

  statusEl.className = '';
  statusEl.textContent = '○ checking...';
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 6000);
    const res = await fetch(apiUrl('/health'), { signal: ctrl.signal, cache: 'no-store' });
    clearTimeout(timer);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json().catch(() => ({}));
    statusEl.className = 'ok';
    statusEl.textContent = '● online' + (data.status ? ' (' + data.status + ')' : '');
  } catch {
    statusEl.className = 'bad';
    statusEl.textContent = IS_LOCAL ? '✕ backend offline' : '✕ unreachable — check config.js';
  }
}

checkApi();
setInterval(checkApi, 30000);

/* ---------- app logic ---------- */
document.querySelectorAll('.chip').forEach(c =>
  c.addEventListener('click', () => {
    $('input').value = c.dataset.ex;
    analyze();
  })
);
$('go').addEventListener('click', analyze);
$('input').addEventListener('keydown', e => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) analyze();
});

async function analyze() {
  const text = $('input').value.trim();
  hideError();
  $('verdictCard').style.display = 'none';
  if (!text) {
    showError('ERR: empty input — paste a URL or message to analyze.');
    return;
  }
  $('go').disabled = true;
  $('status').textContent = '> resolving target... scanning language patterns... correlating signals';
  try {
    const res = await fetch(apiUrl('/analyze'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text })
    });
    const data = await res.json();
    if (!res.ok) {
      const msg = Array.isArray(data.detail) ? data.detail[0].msg : (data.detail || 'Analysis failed');
      showError('ERR: ' + msg);
      return;
    }
    render(data);
  } catch {
    showError(IS_LOCAL
      ? 'ERR: cannot reach TrustGuard engine — is the server running on ' + LOCAL_API + '?'
      : 'ERR: cannot reach the TrustGuard API at ' + describeApi() + ' — check static/config.js');
  } finally {
    $('go').disabled = false;
    $('status').textContent = '';
  }
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function weightLabel(base) {
  return base >= 30 ? 'major' : base >= 15 ? 'moderate' : 'minor';
}

function render(r) {
  const L = LEVELS[r.risk.level] || LEVELS.SAFE;
  const card = $('verdictCard');
  card.style.display = 'block';
  card.style.setProperty('--lvl', L.color);
  document.documentElement.style.setProperty('--lvl', L.color);
  card.classList.remove('in');
  void card.offsetWidth;
  card.classList.add('in');

  $('levelText').innerHTML = `<span style="color:${L.color}">${L.icon}${L.label}</span>`;

  const score = $('scoreNum');
  score.textContent = r.risk.score;
  score.style.color = L.color;

  const fill = $('meterFill');
  fill.style.background = L.color;
  fill.style.boxShadow = `0 0 14px ${L.color}`;
  fill.style.width = '0';
  requestAnimationFrame(() => requestAnimationFrame(() => { fill.style.width = r.risk.score + '%'; }));

  $('summaryText').textContent = '> ' + r.summary;

  $('signals').innerHTML = r.signals.length
    ? r.signals.map(s =>
        `<div class="line"><span class="pre">[!]</span>${esc(s.description)}` +
        `<span class="sid">signal: ${esc(s.id)} · weight: ${weightLabel(s.base_score)}</span></div>`
      ).join('')
    : '<div class="line"><span class="pre">[ok]</span>No risk indicators detected.</div>';

  $('actions').innerHTML = r.recommended_actions
    .map(a => `<div class="line"><span class="pre">→</span>${esc(a)}</div>`)
    .join('');

  $('disclaimer').textContent = r.disclaimer;
  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function showError(msg) {
  const e = $('error');
  e.textContent = msg;
  e.style.display = 'block';
}

function hideError() {
  $('error').style.display = 'none';
}
