/* KAVACH SOC dashboard — vanilla JS single-page app, no build step, no external dependencies. */
'use strict';

// ======================================================================= helpers
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const S = { token: null, user: null, es: null, listeners: [], feed: [], openAlerts: 0, cleanup: [] };
try { S.token = sessionStorage.getItem('kavach-token'); } catch (e) { }

async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (S.token) headers.Authorization = 'Bearer ' + S.token;
  const r = await fetch(path, { ...opts, headers });
  if (r.status === 401 && !path.startsWith('/api/auth/login')) { logout(true); throw new Error('Session expired'); }
  const ct = r.headers.get('content-type') || '';
  const data = ct.includes('json') ? await r.json() : await r.text();
  if (!r.ok) { const err = new Error((data && data.detail) || r.statusText); err.status = r.status; err.data = data; throw err; }
  return data;
}
const post = (p, b) => api(p, { method: 'POST', body: JSON.stringify(b || {}) });
const put = (p, b) => api(p, { method: 'PUT', body: JSON.stringify(b || {}) });
const del = p => api(p, { method: 'DELETE' });
const can = p => S.user && S.user.permissions.includes(p);

const inr = n => n == null ? '—' : '₹' + Number(n).toLocaleString('en-IN', { maximumFractionDigits: n < 100 ? 2 : 0 });
const inrShort = n => { if (n == null) return '—'; n = Number(n); if (n >= 1e7) return '₹' + (n / 1e7).toFixed(2) + ' Cr'; if (n >= 1e5) return '₹' + (n / 1e5).toFixed(2) + ' L'; return inr(n); };
const tfmt = new Intl.DateTimeFormat('en-IN', { timeZone: 'Asia/Kolkata', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
const when = ts => ts ? tfmt.format(new Date(ts * 1000)) : '—';
const ago = ts => { if (!ts) return '—'; const s = Date.now() / 1000 - ts; if (s < 60) return Math.max(0, Math.round(s)) + 's ago'; if (s < 3600) return Math.round(s / 60) + 'm ago'; if (s < 86400) return Math.round(s / 3600) + 'h ago'; return Math.round(s / 86400) + 'd ago'; };
const pct = v => v == null ? '—' : v + '%';
const badge = (t, cls = '') => `<span class="badge ${cls}">${esc(t)}</span>`;
const prio = p => p ? badge(p, 'p-' + p) : '<span class="muted">—</span>';
const stat = s => badge(String(s).replace(/_/g, ' '), 'st-' + s);
function riskColor(s) { return s >= 75 ? 'var(--critical)' : s >= 55 ? 'var(--serious)' : s >= 35 ? 'var(--warning)' : 'var(--good)'; }
const risk = s => s == null ? '—' : `<span class="risk"><span class="bar"><i style="width:${Math.min(100, s)}%;background:${riskColor(s)}"></i></span>${Number(s).toFixed(0)}</span>`;

function toast(msg, cls = '') {
  const d = document.createElement('div'); d.className = cls; d.innerHTML = msg; $('#toast').appendChild(d);
  setTimeout(() => d.remove(), 5000);
}
const ok = msg => toast('✓ ' + esc(msg));
const fail = e => toast('⚠ ' + esc(e.message || e), 'alert');
function on(type, fn) { S.listeners.push({ type, fn }); }

async function download(path, filename) {
  try {
    const r = await fetch(path, { headers: { Authorization: 'Bearer ' + S.token } });
    if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
    const blob = await r.blob(); const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = filename; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  } catch (e) { fail(e); }
}

function modal(title, bodyHtml, onSubmit, submitLabel = 'Confirm', danger = false) {
  const w = document.createElement('div'); w.className = 'modal-wrap';
  w.innerHTML = `<form class="modal"><h2>${esc(title)}</h2><div>${bodyHtml}</div><div class="err"></div>
    <div class="bar-row" style="justify-content:flex-end"><button type="button" data-x>Cancel</button>${onSubmit ? `<button class="${danger ? 'danger' : 'primary'}">${esc(submitLabel)}</button>` : ''}</div></form>`;
  document.body.appendChild(w);
  const close = () => w.remove();
  w.addEventListener('click', e => { if (e.target === w || e.target.dataset.x !== undefined) close(); });
  $('form', w).addEventListener('submit', async e => {
    e.preventDefault();
    try { await onSubmit(new FormData(e.target), w); close(); } catch (err) { $('.err', w).textContent = err.message; }
  });
  const first = $('input,select,textarea', w); if (first) first.focus();
  return w;
}
function prompt2(title, fields, onSubmit, label, danger) {
  const html = fields.map(f => `<label class="f" style="margin-bottom:10px">${esc(f.label)}${f.options
    ? `<select name="${f.name}">${f.options.map(o => `<option value="${esc(o[0])}">${esc(o[1])}</option>`).join('')}</select>`
    : f.area ? `<textarea name="${f.name}" placeholder="${esc(f.ph || '')}">${esc(f.value || '')}</textarea>`
      : `<input name="${f.name}" value="${esc(f.value || '')}" placeholder="${esc(f.ph || '')}" ${f.type ? `type="${f.type}"` : ''}>`}</label>`).join('');
  return modal(title, html, fd => onSubmit(Object.fromEntries(fd)), label, danger);
}

// ======================================================================= charts (hand-rolled SVG)
function barChart(el, values, { color = 'var(--series-1)', start, bucket, unit = '' } = {}) {
  const W = Math.max(280, el.clientWidth || 500), H = 150, pl = 34, pb = 20, pt = 8;
  const max = Math.max(1, ...values); const nice = niceMax(max);
  const bw = (W - pl) / values.length;
  const y = v => pt + (H - pt - pb) * (1 - v / nice);
  let g = '';
  for (let i = 0; i <= 3; i++) { const v = nice * i / 3; g += `<line x1="${pl}" x2="${W}" y1="${y(v)}" y2="${y(v)}" stroke="var(--grid)"/><text x="${pl - 6}" y="${y(v) + 4}" text-anchor="end" font-size="10" fill="var(--text-muted)">${fmtTick(v)}</text>`; }
  const step = Math.ceil(values.length / 6);
  values.forEach((v, i) => {
    const x = pl + i * bw + 1, w = Math.max(1, bw - 2), h = H - pb - y(v);
    if (v > 0) g += `<path d="${roundedTop(x, y(v), w, h, Math.min(3, w / 2))}" fill="${color}"/>`;
    if (i % step === 0) { const t = new Date((start + i * bucket) * 1000); g += `<text x="${x + w / 2}" y="${H - 5}" text-anchor="middle" font-size="10" fill="var(--text-muted)">${t.toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour: '2-digit', minute: '2-digit', hour12: false })}</text>`; }
    g += `<rect x="${pl + i * bw}" y="${pt}" width="${bw}" height="${H - pt - pb}" fill="transparent" data-i="${i}"/>`;
  });
  el.innerHTML = `<div class="chart"><svg viewBox="0 0 ${W} ${H}" role="img">${g}</svg><div class="tip"></div></div>`;
  const tip = $('.tip', el), svg = $('svg', el);
  svg.addEventListener('mousemove', e => {
    const i = e.target.dataset && e.target.dataset.i; if (i == null) { tip.style.display = 'none'; return; }
    const t0 = new Date((start + i * bucket) * 1000), t1 = new Date((start + (+i + 1) * bucket) * 1000);
    const f = d => d.toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour: '2-digit', minute: '2-digit', hour12: false });
    tip.innerHTML = `<b>${values[i].toLocaleString('en-IN')}</b> ${unit}<br><span class="muted">${f(t0)}–${f(t1)} IST</span>`;
    const r = el.getBoundingClientRect(); tip.style.display = 'block';
    tip.style.left = Math.min(e.clientX - r.left + 12, r.width - 140) + 'px'; tip.style.top = (e.clientY - r.top - 10) + 'px';
  });
  svg.addEventListener('mouseleave', () => tip.style.display = 'none');
}
function roundedTop(x, y, w, h, r) { if (h < r) r = h; return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`; }
function niceMax(m) { const p = Math.pow(10, Math.floor(Math.log10(m))); for (const k of [1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) if (k * p >= m) return k * p; return m; }
function fmtTick(v) { return v >= 1000 ? (v / 1000).toFixed(v % 1000 ? 1 : 0) + 'k' : Math.round(v); }

// force-directed link-analysis graph
function forceGraph(el, data, onNode) {
  const W = el.clientWidth || 700, H = el.clientHeight || 520;
  const nodes = data.nodes.map((n, i) => ({ ...n, x: W / 2 + Math.cos(i) * 150 * Math.random(), y: H / 2 + Math.sin(i) * 150 * Math.random(), vx: 0, vy: 0 }));
  const idx = Object.fromEntries(nodes.map((n, i) => [n.id, i]));
  const edges = data.edges.filter(e => e.source in idx && e.target in idx).map(e => ({ ...e, s: nodes[idx[e.source]], t: nodes[idx[e.target]] }));
  if (!nodes.length) { el.innerHTML = '<div class="empty">No linked entities in this window.</div>'; return; }
  for (let it = 0; it < 320; it++) {
    const alpha = 1 - it / 320;
    for (let i = 0; i < nodes.length; i++) for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i], b = nodes[j]; let dx = a.x - b.x, dy = a.y - b.y; let d2 = dx * dx + dy * dy + 0.01;
      if (d2 > 90000) continue; const f = 1800 / d2 * alpha; const d = Math.sqrt(d2); dx /= d; dy /= d;
      a.vx += dx * f; a.vy += dy * f; b.vx -= dx * f; b.vy -= dy * f;
    }
    for (const e of edges) { const dx = e.t.x - e.s.x, dy = e.t.y - e.s.y; const d = Math.sqrt(dx * dx + dy * dy) || 1; const f = (d - 70) * 0.02 * alpha; e.s.vx += dx / d * f; e.s.vy += dy / d * f; e.t.vx -= dx / d * f; e.t.vy -= dy / d * f; }
    for (const n of nodes) { n.vx += (W / 2 - n.x) * 0.004 * alpha; n.vy += (H / 2 - n.y) * 0.004 * alpha; n.x += n.vx; n.y += n.vy; n.vx *= 0.6; n.vy *= 0.6; n.x = Math.max(24, Math.min(W - 24, n.x)); n.y = Math.max(20, Math.min(H - 20, n.y)); }
  }
  const col = { customer: 'var(--series-1)', payee: 'var(--series-2)', device: 'var(--series-3)', ip: 'var(--text-muted)' };
  const shape = n => {
    const r = n.kind === 'customer' ? 9 : 7, ring = n.watchlisted || n.status === 'BLOCKED' ? `stroke="var(--critical)" stroke-width="3"` : `stroke="var(--surface-2)" stroke-width="2"`;
    if (n.kind === 'payee') return `<rect x="${n.x - r}" y="${n.y - r}" width="${2 * r}" height="${2 * r}" rx="2" fill="${col.payee}" ${ring}/>`;
    if (n.kind === 'device') return `<path d="M${n.x},${n.y - r - 1}L${n.x + r + 1},${n.y + r}L${n.x - r - 1},${n.y + r}Z" fill="${col.device}" ${ring}/>`;
    if (n.kind === 'ip') return `<path d="M${n.x},${n.y - r}L${n.x + r},${n.y}L${n.x},${n.y + r}L${n.x - r},${n.y}Z" fill="${col.ip}" ${ring}/>`;
    return `<circle cx="${n.x}" cy="${n.y}" r="${r + Math.min(6, (n.risk || 0) / 20)}" fill="${col.customer}" ${ring}/>`;
  };
  const lbl = n => n.kind === 'customer' ? (n.name || n.label) : n.label.length > 22 ? n.label.slice(0, 20) + '…' : n.label;
  let g = edges.map(e => `<line x1="${e.s.x}" y1="${e.s.y}" x2="${e.t.x}" y2="${e.t.y}" stroke="${e.kind === 'paid' ? 'var(--series-2)' : 'var(--text-muted)'}" stroke-opacity="${e.kind === 'paid' ? .7 : .35}" stroke-width="${e.kind === 'paid' ? Math.min(4, 1 + e.count / 2) : 1}"><title>${esc(e.kind)} ×${e.count}${e.amount ? ' · ' + inr(e.amount) : ''}</title></line>`).join('');
  g += nodes.map(n => `<g class="nd" data-id="${esc(n.id)}" style="cursor:${n.kind === 'customer' ? 'pointer' : 'default'}">${shape(n)}<text x="${n.x + 12}" y="${n.y + 4}" font-size="11" fill="var(--text-secondary)">${esc(lbl(n))}</text><title>${esc(n.kind)}: ${esc(n.label)}${n.name ? ' (' + esc(n.name) + ')' : ''}${n.watchlisted ? ' — WATCHLISTED' : ''}${n.status === 'BLOCKED' ? ' — BLOCKED' : ''}${n.risk ? ' — max risk ' + Math.round(n.risk) : ''}</title></g>`).join('');
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}">${g}</svg>`;
  $$('.nd', el).forEach(x => x.addEventListener('click', () => { const n = nodes[idx[x.dataset.id]]; if (n.kind === 'customer' && onNode) onNode(n); }));
}
const graphLegend = `<div class="legend"><span><i style="background:var(--series-1);border-radius:50%"></i>Customer</span><span><i style="background:var(--series-2)"></i>Payee / beneficiary</span><span><i style="background:var(--series-3)"></i>Device</span><span><i style="background:var(--text-muted)"></i>IP address</span><span><i style="background:transparent;border:2px solid var(--critical)"></i>Watchlisted or blocked</span></div>`;

// ======================================================================= auth & shell
function logout(expired) {
  if (S.token && !expired) api('/api/auth/logout', { method: 'POST' }).catch(() => { });
  S.token = null; S.user = null; try { sessionStorage.removeItem('kavach-token'); } catch (e) { }
  if (S.es) S.es.close(); renderLogin(expired ? 'Your session ended. Please sign in again.' : '');
}

const SHIELD = `<svg width="30" height="30" viewBox="0 0 32 32" aria-hidden="true"><path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" fill="var(--accent)"/><path d="m11 16 3.5 3.5L21.5 12" stroke="#fff" stroke-width="2.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

function renderLogin(msg = '') {
  $('#root').innerHTML = `<div class="login"><div class="card">
    <div class="brand" style="padding:0">${SHIELD}<div><b>KAVACH</b><small>AI-SOC Fraud Detection Platform</small></div></div>
    <form id="lf"><input name="username" placeholder="Username" autocomplete="username" required>
    <input name="password" type="password" placeholder="Password" autocomplete="current-password" required>
    <input name="otp" placeholder="6-digit authenticator code" inputmode="numeric" autocomplete="one-time-code" style="display:none">
    <div class="err">${esc(msg)}</div><button class="primary" style="justify-content:center;padding:10px">Sign in</button></form>
    <p class="muted" style="font-size:12px;margin:14px 0 0">Authorised bank personnel only. All activity is logged.</p></div></div>`;
  const f = $('#lf');
  f.addEventListener('submit', async e => {
    e.preventDefault(); const b = Object.fromEntries(new FormData(f)); $('.err', f).textContent = '';
    try {
      const r = await fetch('/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) });
      const d = await r.json();
      if (d.mfa_required) { f.otp.style.display = ''; f.otp.required = true; f.otp.focus(); $('.err', f).textContent = 'Enter the code from your authenticator app.'; return; }
      if (!r.ok) throw new Error(d.detail || 'Login failed');
      S.token = d.token; S.user = d.user; try { sessionStorage.setItem('kavach-token', d.token); } catch (e) { }
      boot();
    } catch (err) { $('.err', f).textContent = err.message; }
  });
}

const NAV = [
  ['overview', 'Overview', 'view'], ['alerts', 'Alerts', 'view'], ['cases', 'Cases', 'view'], ['investigate', 'Investigate', 'view'],
  ['networks', 'Fraud networks', 'view'], ['response', 'Response log', 'view'], ['model', 'Rules & model', 'view'],
  ['reports', 'Reports & compliance', 'reports'], ['audit', 'Audit trail', 'audit'], ['admin', 'Administration', 'view'],
];
const ICONS = {
  overview: 'M3 13h8V3H3zm10 8h8V11h-8zM3 21h8v-6H3zm10-18v6h8V3z', alerts: 'M12 2 1 21h22L12 2zm1 15h-2v-2h2zm0-4h-2V9h2z',
  cases: 'M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8z', investigate: 'M15.5 14h-.8l-.3-.3A6.5 6.5 0 1 0 9.5 16a6.5 6.5 0 0 0 4.2-1.6l.3.3v.8l5 5 1.5-1.5zm-6 0a4.5 4.5 0 1 1 0-9 4.5 4.5 0 0 1 0 9z',
  networks: 'M17 16a3 3 0 0 0-2.4 1.2l-5.2-2.6a3 3 0 0 0 0-1.2l5.2-2.6A3 3 0 1 0 14 9l-5.2 2.6a3 3 0 1 0 0 2.8L14 17a3 3 0 1 0 3-1z', response: 'M13 2 3 14h9l-1 8 10-12h-9z',
  model: 'M19.4 13a7.5 7.5 0 0 0 0-2l2.1-1.6-2-3.5-2.5 1a7 7 0 0 0-1.7-1L15 3h-4l-.4 2.7a7 7 0 0 0-1.7 1l-2.5-1-2 3.5L6.6 11a7.5 7.5 0 0 0 0 2l-2.1 1.6 2 3.5 2.5-1a7 7 0 0 0 1.7 1L11 21h4l.4-2.7a7 7 0 0 0 1.7-1l2.5 1 2-3.5zM13 15.5a3.5 3.5 0 1 1 0-7 3.5 3.5 0 0 1 0 7z',
  reports: 'M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zM9 17H7v-7h2zm4 0h-2V7h2zm4 0h-2v-4h2z', audit: 'M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8zm-1 7V3.5L18.5 9z',
  admin: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zm0 2c-2.7 0-8 1.3-8 4v2h16v-2c0-2.7-5.3-4-8-4z',
};

async function boot() {
  if (!S.user) { try { S.user = await api('/api/me'); } catch (e) { return renderLogin(); } }
  $('#root').innerHTML = `<div class="app"><aside class="side"><div class="brand">${SHIELD}<div><b>KAVACH</b><small>AI-SOC · Fraud Defence</small></div></div>
    <nav class="nav">${NAV.filter(n => can(n[2])).map(n => `<a href="#/${n[0]}" data-nav="${n[0]}"><svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="${ICONS[n[0]]}"/></svg>${n[1]}${n[0] === 'alerts' ? '<span class="count" id="alertCount" hidden></span>' : ''}</a>`).join('')}</nav>
    <div class="foot">Signed in as <b>${esc(S.user.full_name)}</b><br>${badge(S.user.role)}<br><br><a href="#/account">My account &amp; MFA</a> · <a href="#" id="themeBtn">Theme</a> · <a href="#" id="logoutBtn">Sign out</a></div></aside>
    <div class="main"><header class="top"><div class="title" id="pageTitle"></div><div class="grow"></div><span class="live" id="live"><i></i><span>Connecting…</span></span></header><main class="content" id="view"></main></div></div>`;
  $('#logoutBtn').onclick = e => { e.preventDefault(); logout(); };
  $('#themeBtn').onclick = e => {
    e.preventDefault(); const cur = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    document.documentElement.dataset.theme = cur; try { localStorage.setItem('kavach-theme', cur); } catch (x) { } route();
  };
  connectStream(); refreshAlertCount(); route();
}

function connectStream() {
  if (S.es) S.es.close();
  const es = new EventSource('/api/stream?token=' + encodeURIComponent(S.token)); S.es = es;
  const live = () => $('#live');
  es.onopen = () => { const l = live(); if (l) { l.classList.add('on'); $('span', l).textContent = 'Live feed'; } };
  es.onerror = () => { const l = live(); if (l) { l.classList.remove('on'); $('span', l).textContent = 'Reconnecting…'; } };
  for (const type of ['txn', 'alert', 'action', 'case', 'notification', 'log', 'customer']) {
    es.addEventListener(type, ev => {
      const d = JSON.parse(ev.data);
      if (type === 'txn') { S.feed.unshift(d); S.feed.length = Math.min(S.feed.length, 80); }
      if (type === 'alert') {
        S.openAlerts++; setAlertCount();
        if (d.priority === 'HIGH') toast(`<b>HIGH alert #${d.id}</b> · ${esc(d.customer_id)} · ${inr(d.amount)} ${esc(d.channel)}<br><span class="muted">${esc(d.reasons)}</span> <a href="#/alerts">Review</a>`, 'alert');
      }
      S.listeners.filter(l => l.type === type).forEach(l => { try { l.fn(d); } catch (e) { console.error(e); } });
    });
  }
}
async function refreshAlertCount() { try { const a = await api('/api/alerts?status=OPEN&limit=1000'); S.openAlerts = a.length; setAlertCount(); } catch (e) { } }
function setAlertCount() { const c = $('#alertCount'); if (c) { c.hidden = !S.openAlerts; c.textContent = S.openAlerts > 999 ? '999+' : S.openAlerts; } }

// ======================================================================= router
const VIEWS = {};
async function route() {
  if (!S.user) return;
  S.listeners = []; S.cleanup.forEach(f => f()); S.cleanup = [];
  const [name, arg] = (location.hash.replace(/^#\//, '') || 'overview').split('/');
  const v = VIEWS[name] || VIEWS.overview;
  $$('.nav a').forEach(a => a.classList.toggle('active', a.dataset.nav === name || (name === 'case' && a.dataset.nav === 'cases') || (name === 'customer' && a.dataset.nav === 'investigate')));
  // fresh element each navigation so view-level listeners never leak into the next view
  const prev = $('#view'), el = prev.cloneNode(false); prev.replaceWith(el); el.innerHTML = '<div class="empty">Loading…</div>';
  try { await v(el, arg ? decodeURIComponent(arg) : undefined); }
  catch (e) {
    if (e.status === 503) { el.innerHTML = `<div class="card"><h2>KAVACH is starting up</h2><p class="secondary">${esc(e.message)}</p></div>`; setTimeout(route, 2500); }
    else el.innerHTML = `<div class="card"><h2>Something went wrong</h2><p class="secondary">${esc(e.message)}</p></div>`;
  }
}
window.addEventListener('hashchange', route);
window.addEventListener('unhandledrejection', e => { if (e.reason instanceof TypeError && /null/.test(e.reason.message)) e.preventDefault(); });
const title = t => { $('#pageTitle').textContent = t; document.title = t + ' · KAVACH SOC'; };
const every = (ms, fn) => { const h = setInterval(fn, ms); S.cleanup.push(() => clearInterval(h)); };

// ======================================================================= overview
VIEWS.overview = async el => {
  title('Security operations overview');
  el.innerHTML = `<div class="tiles" id="tiles"></div>
    <div class="row cols-21"><div class="card"><div class="hd"><h2>Activity, last 24 hours</h2><div class="grow"></div><span class="muted" style="font-size:12px">IST · hover a bar for details</span></div>
      <div class="row cols-2"><div><h3 style="margin-bottom:6px">Transactions scored</h3><div id="c1"></div></div><div><h3 style="margin-bottom:6px">Alerts raised</h3><div id="c2"></div></div></div></div>
      <div class="card"><div class="hd"><h2>By channel</h2></div><div id="chan"></div></div></div>
    <div class="row cols-21"><div class="card"><div class="hd"><h2>Live transaction feed</h2><div class="grow"></div><span class="muted" style="font-size:12px" id="lat"></span></div>
      <div class="tbl-wrap"><table><thead><tr><th>Time</th><th>Txn</th><th>Customer</th><th>Channel</th><th class="num">Amount</th><th>Payee</th><th>City</th><th>Risk</th><th>Decision</th></tr></thead><tbody id="feed"></tbody></table></div></div>
      <div class="row" style="align-content:start"><div class="card"><div class="hd"><h2>Newest alerts</h2><div class="grow"></div><a href="#/alerts">All alerts</a></div><div id="la"></div></div>
      ${can('simulator') ? `<div class="card"><div class="hd"><h2>Attack simulator</h2><div class="grow"></div><span id="simst" class="muted" style="font-size:12px"></span></div>
        <p class="secondary" style="margin:0 0 10px;font-size:13px">Inject a fraud pattern into the synthetic feed and watch KAVACH detect it.</p>
        <div class="bar-row" id="sim"></div></div>` : ''}</div></div>`;
  const feedRow = t => `<tr class="click flash" data-t="${esc(t.id)}"><td class="mono">${when(t.ts).split(', ')[1] || when(t.ts)}</td><td class="mono">${esc(t.id.slice(0, 9))}</td><td><a href="#/customer/${esc(t.customer_id)}">${esc(t.customer_id)}</a></td><td>${esc(t.channel)}</td><td class="num">${inr(t.amount)}</td><td class="trunc" style="max-width:160px">${esc(t.payee)}</td><td>${esc(t.city)}</td><td>${risk(t.risk_score)}</td><td>${stat(t.status)}</td></tr>`;
  const fb = $('#feed');
  const initial = S.feed.length ? S.feed.slice(0, 25) : await api('/api/transactions?limit=25');
  fb.innerHTML = initial.map(feedRow).join('').replace(/ flash/g, '');
  fb.addEventListener('click', e => { const tr = e.target.closest('tr'); if (tr && e.target.tagName !== 'A') showTxn(tr.dataset.t); });
  on('txn', t => { fb.insertAdjacentHTML('afterbegin', feedRow(t)); while (fb.children.length > 25) fb.lastChild.remove(); });
  const loadAlerts = async () => {
    const a = (await api('/api/alerts?status=ALL&limit=8'));
    a.sort((x, y) => y.created - x.created);
    $('#la').innerHTML = a.length ? `<table><tbody>${a.map(x => `<tr class="click" data-t="${esc(x.txn_id)}"><td>${prio(x.priority)}</td><td><b>${esc(x.customer_name)}</b><div class="muted trunc" style="max-width:220px;font-size:12px">${esc(x.reasons)}</div></td><td class="num">${inr(x.amount)}<div class="muted" style="font-size:11px">${ago(x.created)}</div></td></tr>`).join('')}</tbody></table>` : '<div class="empty">No alerts yet</div>';
    $$('#la tr').forEach(tr => tr.onclick = () => showTxn(tr.dataset.t));
  };
  let pending = null; on('alert', () => { clearTimeout(pending); pending = setTimeout(loadAlerts, 600); }); S.cleanup.push(() => clearTimeout(pending));
  const load = async () => {
    const d = await api('/api/overview?hours=24'); const k = d.kpis;
    $('#tiles').innerHTML = [
      ['Transactions scored', k.transactions.toLocaleString('en-IN'), inrShort(k.volume) + ' volume'],
      ['Open alerts', k.alerts_open, `${k.alerts_by_priority.HIGH || 0} high · ${k.alerts_by_priority.MEDIUM || 0} medium · ${k.alerts_by_priority.LOW || 0} low`],
      ['Detection rate', pct(k.detection_rate), `${k.fraud_transactions} fraudulent transactions`],
      ['Alert precision', pct(k.alert_precision), 'alerts that were real fraud'],
      ['False positive rate', k.false_positive_rate_txn == null ? '—' : k.false_positive_rate_txn + '%', 'of genuine transactions flagged'],
      ['Loss prevented', inrShort(k.loss_prevented), inrShort(k.loss_exposed) + ' exposed'],
      ['Mean time to respond', k.mean_time_to_acknowledge_min == null ? '—' : k.mean_time_to_acknowledge_min + ' min', 'alert → analyst acknowledgement'],
      ['Open cases', k.cases_open_total, `${k.sla_breaches} past SLA`],
    ].map(t => `<div class="tile"><div class="k">${t[0]}</div><div class="v">${t[1]}</div><div class="s">${t[2]}</div></div>`).join('');
    const s = k.series; barChart($('#c1'), s.transactions, { start: s.start, bucket: s.bucket_seconds, unit: 'transactions' });
    barChart($('#c2'), s.alerts, { start: s.start, bucket: s.bucket_seconds, unit: 'alerts', color: 'var(--series-2)' });
    $('#chan').innerHTML = `<table><thead><tr><th>Channel</th><th class="num">Txns</th><th class="num">Volume</th><th class="num">Alerts</th><th class="num">Fraud caught</th></tr></thead><tbody>${Object.entries(k.by_channel).map(([c, v]) => `<tr><td><b>${c}</b></td><td class="num">${v.transactions.toLocaleString('en-IN')}</td><td class="num">${inrShort(v.volume)}</td><td class="num">${v.alerts}</td><td class="num">${v.fraud_detected}/${v.fraud}</td></tr>`).join('')}</tbody></table>
      <p class="muted" style="font-size:12px;margin:12px 0 0">Model <b>${esc(d.model)}</b> · auto-response ${d.auto_response ? 'on' : 'off'} · auto-block ${d.auto_block ? 'on' : 'off'}</p>`;
    $('#lat').textContent = `scoring latency ${d.engine.avg_latency_ms} ms avg`;
    if ($('#sim') && d.feed) {
      $('#simst').textContent = d.feed.running ? `${d.feed.tps} txn/s` : 'paused';
      if (!$('#sim').children.length) {
        $('#sim').innerHTML = ['ACCOUNT_TAKEOVER', 'MULE_RING', 'CARD_TESTING', 'IMPOSSIBLE_TRAVEL', 'SIM_SWAP'].map(k => `<button class="sm" data-k="${k}">${k.replace(/_/g, ' ').toLowerCase()}</button>`).join('') + `<button class="sm" data-p>${d.feed.running ? 'Pause feed' : 'Resume feed'}</button>`;
        $$('#sim [data-k]').forEach(b => b.onclick = async () => { try { const r = await post('/api/simulator/inject', { kind: b.dataset.k }); ok(`Injected ${r.kind.replace(/_/g, ' ').toLowerCase()} (${r.events} events over the next few minutes)`); } catch (e) { fail(e); } });
        $('#sim [data-p]').onclick = async e => { try { const r = await post('/api/simulator', { running: !d.feed.running }); d.feed.running = r.running; e.target.textContent = r.running ? 'Pause feed' : 'Resume feed'; } catch (x) { fail(x); } };
      }
    }
  };
  await Promise.all([load(), loadAlerts()]);
  every(15000, load);
};

// ======================================================================= transaction drawer
async function showTxn(id) {
  const t = await api('/api/transactions/' + encodeURIComponent(id)).catch(fail); if (!t) return;
  const r = t.reasons || {}; const c = r.components || {}; const a = t.alert;
  const ov = document.createElement('div'); ov.className = 'overlay';
  ov.innerHTML = `<div class="drawer"><div class="bar-row"><h2 style="flex:1">Transaction <span class="mono">${esc(t.id)}</span></h2><button data-x>Close</button></div>
    <div class="bar-row">${prio(t.priority)} ${stat(t.status)} ${t.label ? badge('Label: ' + t.label) : ''} <span class="muted">${when(t.ts)} IST</span></div>
    <div class="card"><div class="hd"><h2>Risk score ${risk(t.risk_score)}</h2></div>
      ${[['Rules', c.rules], ['ML model', c.ml], ['Behaviour', c.profile]].map(([k, v]) => `<div class="comp"><span>${k}</span><span class="track"><i style="width:${v || 0}%"></i></span><span class="num">${v == null ? '—' : Math.round(v)}</span></div>`).join('')}
      <p class="muted" style="font-size:12px;margin:10px 0 0">Model ${esc(r.model_version || '—')}${r.ml && r.ml.fraud_probability != null ? ` · fraud probability ${r.ml.fraud_probability}% · anomaly percentile ${r.ml.anomaly_pct}` : ''}</p></div>
    <div class="card"><h2 style="margin-bottom:8px">Why it was flagged</h2>${(r.rules || []).length + (r.profile || []).length ? `<ul class="reasons">${(r.rules || []).map(h => `<li><b>${esc(h.rule)} ${esc(h.name)}</b> <span class="muted">(+${h.weight})</span><br><span class="secondary">${esc(h.detail)}</span></li>`).join('')}${(r.profile || []).map(p => `<li>${esc(p)}</li>`).join('')}</ul>` : '<span class="muted">No rule or behavioural signal; ML score only.</span>'}</div>
    <div class="card kv"><div>Customer</div><div><a href="#/customer/${esc(t.customer_id)}">${esc(t.customer_id)}</a></div><div>Channel</div><div>${esc(t.channel)}</div><div>Amount</div><div><b>${inr(t.amount)}</b></div>
      <div>Payee</div><div>${esc(t.payee)} <span class="muted">(${esc(t.payee_type)}, ${esc(t.category)})</span></div><div>Device</div><div class="mono">${esc(t.device_id)}</div><div>IP</div><div class="mono">${esc(t.ip)}</div><div>Location</div><div>${esc(t.city)} <span class="muted">${(+t.lat).toFixed(3)}, ${(+t.lon).toFixed(3)}</span></div><div>Source</div><div>${esc(t.source)}</div></div>
    ${a ? `<div class="card"><div class="hd"><h2>Alert #${a.id}</h2>${stat(a.status)}${a.case_id ? `<a href="#/case/${a.case_id}">Case #${a.case_id}</a>` : ''}</div>
      <div class="bar-row">${can('triage') && /OPEN|ACKED|IN_CASE/.test(a.status) ? `<button data-act="ack">Acknowledge</button>${a.case_id ? '' : '<button data-act="case">Open case</button>'}<button data-act="fp">False positive</button><button class="danger" data-act="fraud">Confirm fraud</button>` : ''}</div></div>` : ''}
    ${can('respond') ? `<div class="bar-row">${t.status !== 'BLOCKED' ? '<button class="danger" data-act="block">Block transaction</button>' : ''}${t.status !== 'APPROVED' ? '<button data-act="release">Release transaction</button>' : ''}</div>` : ''}
    <details><summary class="muted">Model features</summary><table>${Object.entries(t.features || {}).map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td class="num">${Number(v).toFixed(3)}</td></tr>`).join('')}</table></details></div>`;
  document.body.appendChild(ov);
  const close = () => ov.remove();
  ov.addEventListener('click', async e => {
    if (e.target === ov || e.target.dataset.x !== undefined) return close();
    const act = e.target.dataset.act; if (!act) return;
    try {
      if (act === 'ack') await post(`/api/alerts/${a.id}/ack`);
      if (act === 'case') { const r2 = await post(`/api/alerts/${a.id}/case`); close(); location.hash = '#/case/' + r2.case_id; return; }
      if (act === 'fp') await post(`/api/alerts/${a.id}/close`, { disposition: 'FALSE_POSITIVE' });
      if (act === 'fraud') await post(`/api/alerts/${a.id}/close`, { disposition: 'CONFIRMED_FRAUD' });
      if (act === 'block') await post('/api/respond/transaction', { txn_id: t.id, status: 'BLOCKED', reason: 'Blocked from investigation view' });
      if (act === 'release') await post('/api/respond/transaction', { txn_id: t.id, status: 'APPROVED', reason: 'Released after review' });
      ok('Done'); close(); refreshAlertCount(); route();
    } catch (x) { fail(x); }
  });
}

// ======================================================================= alerts
VIEWS.alerts = async el => {
  title('Alert queue');
  const st = { status: 'OPEN', priority: '' };
  el.innerHTML = `<div class="card"><div class="hd"><div class="seg" id="fs">${[['OPEN', 'Open'], ['IN_CASE', 'In a case'], ['CLOSED_FP', 'False positive'], ['CLOSED_FRAUD', 'Confirmed fraud'], ['ALL', 'All']].map(([v, l]) => `<button data-v="${v}" class="${v === 'OPEN' ? 'on' : ''}">${l}</button>`).join('')}</div>
    <select id="fp"><option value="">All priorities</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select><div class="grow"></div><span class="muted" id="cnt" style="font-size:12px"></span></div>
    <div class="tbl-wrap"><table><thead><tr><th>Priority</th><th>Raised</th><th>Customer</th><th>Channel</th><th class="num">Amount</th><th>Score</th><th>Why</th><th>Txn</th><th>Owner</th><th></th></tr></thead><tbody id="rows"></tbody></table></div></div>`;
  const load = async () => {
    const rows = await api(`/api/alerts?status=${st.status}&priority=${st.priority}&limit=300`);
    $('#cnt').textContent = rows.length + ' alerts';
    $('#rows').innerHTML = rows.length ? rows.map(a => `<tr class="click" data-t="${esc(a.txn_id)}" data-id="${a.id}"><td>${prio(a.priority)}</td><td title="${when(a.created)}">${ago(a.created)}</td><td><a href="#/customer/${esc(a.customer_id)}">${esc(a.customer_name)}</a><div class="muted mono">${esc(a.customer_id)}</div></td><td>${esc(a.channel)}</td><td class="num">${inr(a.amount)}</td><td>${risk(a.score)}</td><td class="trunc" title="${esc(a.reasons)}">${esc(a.reasons)}</td><td>${stat(a.txn_status)}</td><td>${esc(a.assignee || '—')}</td>
      <td style="white-space:nowrap">${can('triage') && /OPEN|ACKED/.test(a.status) ? `<button class="sm" data-a="case">Case</button> <button class="sm" data-a="fp">FP</button> <button class="sm danger" data-a="fraud">Fraud</button>` : a.case_id ? `<a href="#/case/${a.case_id}">Case #${a.case_id}</a>` : ''}</td></tr>`).join('') : '<tr><td colspan="10" class="empty">Queue is clear.</td></tr>';
  };
  $('#fs').onclick = e => { const v = e.target.dataset.v; if (!v) return; st.status = v; $$('#fs button').forEach(b => b.classList.toggle('on', b.dataset.v === v)); load(); };
  $('#fp').onchange = e => { st.priority = e.target.value; load(); };
  $('#rows').addEventListener('click', async e => {
    const tr = e.target.closest('tr'); if (!tr || e.target.tagName === 'A') return;
    const a = e.target.dataset.a, id = tr.dataset.id;
    try {
      if (a === 'case') { const r = await post(`/api/alerts/${id}/case`); location.hash = '#/case/' + r.case_id; return; }
      if (a === 'fp') { await post(`/api/alerts/${id}/close`, { disposition: 'FALSE_POSITIVE' }); ok('Marked false positive — fed back to the model'); refreshAlertCount(); return load(); }
      if (a === 'fraud') { await post(`/api/alerts/${id}/close`, { disposition: 'CONFIRMED_FRAUD' }); ok('Confirmed fraud — labelled for retraining'); refreshAlertCount(); return load(); }
      showTxn(tr.dataset.t);
    } catch (x) { fail(x); }
  });
  let p; on('alert', () => { clearTimeout(p); p = setTimeout(load, 800); }); S.cleanup.push(() => clearTimeout(p));
  await load();
};

// ======================================================================= cases
VIEWS.cases = async el => {
  title('Case management');
  let mode = 'ACTIVE';
  el.innerHTML = `<div class="card"><div class="hd"><div class="seg" id="cs">${[['ACTIVE', 'Active'], ['MINE', 'Assigned to me'], ['ESCALATED', 'Escalated'], ['CLOSED', 'Closed'], ['', 'All']].map(([v, l]) => `<button data-v="${v}" class="${v === 'ACTIVE' ? 'on' : ''}">${l}</button>`).join('')}</div><div class="grow"></div>
    ${can('case_work') ? '<button class="primary" id="newCase">New case</button>' : ''}</div>
    <div class="tbl-wrap"><table><thead><tr><th>#</th><th>Priority</th><th>Title</th><th>Customer</th><th>Status</th><th>Owner</th><th class="num">Alerts</th><th>SLA</th><th>Updated</th></tr></thead><tbody id="rows"></tbody></table></div></div>`;
  const load = async () => {
    const rows = await api(mode === 'MINE' ? '/api/cases?status=ACTIVE&mine=true' : '/api/cases?status=' + mode);
    $('#rows').innerHTML = rows.length ? rows.map(c => `<tr class="click" onclick="location.hash='#/case/${c.id}'"><td class="mono">${c.id}</td><td>${prio(c.priority)}</td><td class="trunc">${esc(c.title)}</td><td>${esc(c.customer_name)} ${c.customer_status === 'BLOCKED' ? stat('BLOCKED') : ''}</td><td>${stat(c.status)}${c.escalation_level ? ` <span class="muted">L${c.escalation_level}</span>` : ''}${c.resolution ? ` <span class="muted">${esc(c.resolution.replace(/_/g, ' ').toLowerCase())}</span>` : ''}</td><td>${esc(c.assignee || '—')}</td><td class="num">${c.alert_count}</td><td>${c.status === 'CLOSED' ? '—' : c.sla_breached ? badge('Breached', 'st-FAIL') : `<span class="muted">due ${ago(2 * Date.now() / 1000 - c.sla_due).replace(' ago', '')}</span>`}</td><td>${ago(c.updated)}</td></tr>`).join('') : '<tr><td colspan="9" class="empty">No cases here.</td></tr>';
  };
  $('#cs').onclick = e => { const v = e.target.dataset.v; if (v === undefined) return; mode = v; $$('#cs button').forEach(b => b.classList.toggle('on', b.dataset.v === v)); load(); };
  if ($('#newCase')) $('#newCase').onclick = () => prompt2('New case', [{ name: 'customer_id', label: 'Customer ID', ph: 'C10001' }, { name: 'title', label: 'Title' }, { name: 'priority', label: 'Priority', options: [['MEDIUM', 'Medium'], ['HIGH', 'High'], ['LOW', 'Low']] }],
    async b => { const c = await post('/api/cases', b); location.hash = '#/case/' + c.id; }, 'Create');
  on('case', load);
  await load();
};

VIEWS.case = async (el, id) => {
  const c = await api('/api/cases/' + id);
  title(`Case #${c.id}`);
  const users = can('case_assign') ? await api('/api/users') : [];
  const open = c.status !== 'CLOSED', cw = can('case_work') && open, rs = can('respond');
  const p2p = [...new Set(c.alerts.filter(a => /@/.test(a.payee)).map(a => a.payee))];
  el.innerHTML = `<div class="card"><div class="bar-row"><div style="flex:1;min-width:240px"><h1>${esc(c.title)}</h1>
      <div class="bar-row" style="margin-top:8px">${prio(c.priority)} ${stat(c.status)} ${c.escalation_level ? badge('Escalation L' + c.escalation_level, 'st-ESCALATED') : ''} ${c.resolution ? badge(c.resolution.replace(/_/g, ' ')) : ''}
      <span class="muted">Opened ${when(c.created)} · owner <b>${esc(c.assignee || 'unassigned')}</b> · SLA ${c.status === 'CLOSED' ? 'n/a' : c.sla_breached ? '<b style="color:var(--critical)">breached</b>' : 'due ' + when(c.sla_due)}</span></div></div>
      <div class="bar-row">${cw ? `<button data-a="mine">Assign to me</button>${users.length ? `<select id="asg"><option value="">Assign to…</option>${users.filter(u => u.active && u.role !== 'READONLY').map(u => `<option value="${u.id}">${esc(u.full_name)} (${u.role.toLowerCase()})</option>`).join('')}</select>` : ''}
        <select id="cst"><option value="">Set status…</option><option value="INVESTIGATING">Investigating</option><option value="PENDING_CUSTOMER">Pending customer</option></select><button data-a="esc">Escalate</button><button class="primary" data-a="close">Close case</button>` : ''}
        ${can('case_work') && c.resolution === 'CONFIRMED_FRAUD' ? '<button data-a="fmr">Draft FMR report</button>' : ''}</div></div></div>
    <div class="row cols-21"><div class="row" style="align-content:start">
      <div class="card"><div class="hd"><h2>Linked alerts (${c.alerts.length})</h2></div><div class="tbl-wrap"><table><thead><tr><th>Priority</th><th>Time</th><th>Channel</th><th class="num">Amount</th><th>Payee</th><th>Device / IP</th><th>Score</th><th>Txn</th>${rs ? '<th></th>' : ''}</tr></thead><tbody>
        ${c.alerts.map(a => `<tr class="click" data-t="${esc(a.txn_id)}"><td>${prio(a.priority)}</td><td>${when(a.txn_ts)}</td><td>${esc(a.channel)}</td><td class="num">${inr(a.amount)}</td><td class="trunc" style="max-width:160px">${esc(a.payee)}</td><td class="mono" style="font-size:11px">${esc(a.device_id)}<br>${esc(a.ip)}</td><td>${risk(a.score)}</td><td>${stat(a.txn_status)}</td>${rs ? `<td>${a.txn_status === 'HELD' ? `<button class="sm danger" data-tx="BLOCKED">Block</button> <button class="sm" data-tx="APPROVED">Release</button>` : ''}</td>` : ''}</tr>`).join('') || '<tr><td colspan="9" class="empty">No alerts linked</td></tr>'}</tbody></table></div></div>
      <div class="card"><div class="hd"><h2>Investigation notes</h2></div><div class="row" style="gap:8px">${c.notes.map(n => `<div class="note"><div class="muted" style="font-size:12px">${esc(n.author)} · ${when(n.ts)}</div>${esc(n.note)}</div>`).join('') || '<div class="muted">No notes yet.</div>'}</div>
        ${cw ? `<form id="nf" style="margin-top:10px;display:grid;gap:8px"><textarea name="note" placeholder="Add a finding, call outcome, or next step…"></textarea><div><button class="primary">Add note</button></div></form>` : ''}</div>
      <div class="card"><div class="hd"><h2>Actions &amp; history</h2></div><div class="tl">${[...c.actions.map(a => ({ ts: a.ts, cls: 'action', t: `<b>${esc(a.type.replace(/_/g, ' ').toLowerCase())}</b> by ${esc(a.actor)}${a.automated ? ' (automatic)' : ''}` })), ...c.history.map(h => ({ ts: h.ts, cls: 'log', t: `${esc(h.action)} by ${esc(h.actor)} <span class="muted">${esc(h.details)}</span>` }))].sort((a, b) => b.ts - a.ts).map(e => `<div class="ev ${e.cls}"><span class="muted">${when(e.ts)}</span><span class="ic"></span><span>${e.t}</span></div>`).join('') || '<div class="muted">Nothing yet.</div>'}</div></div>
    </div><div class="row" style="align-content:start">
      ${customerCard(c.customer)}
      ${rs ? `<div class="card"><div class="hd"><h2>Respond</h2></div><div class="row" style="gap:8px">
        ${c.customer.status === 'BLOCKED' ? (can('unblock') ? '<button data-r="unblock">Unblock account</button>' : '<span class="muted">Account blocked — a manager can unblock.</span>') : '<button class="danger" data-r="block">Block account</button>'}
        <button data-r="notify">Notify customer (SMS + email)</button><button data-r="team">Trigger bank fraud team</button>
        ${p2p.map(v => `<button data-r="npci" data-v="${esc(v)}">Report ${esc(v)} to NPCI</button>`).join('')}</div></div>` : ''}
    </div></div>`;
  const reload = () => route();
  const act = async fn => { try { await fn(); ok('Done'); reload(); } catch (e) { fail(e); } };
  el.addEventListener('click', e => {
    const b = e.target; const tr = b.closest('tr[data-t]');
    if (b.dataset.tx) { const t = tr.dataset.t; return act(() => post('/api/respond/transaction', { txn_id: t, status: b.dataset.tx, reason: 'Case #' + id, case_id: +id })); }
    if (tr && b.tagName !== 'A' && b.tagName !== 'BUTTON') return showTxn(tr.dataset.t);
    const a = b.dataset.a, r = b.dataset.r; const cid = c.customer.id;
    if (a === 'mine') act(() => post(`/api/cases/${id}/assign`, {}));
    if (a === 'esc') prompt2('Escalate case', [{ name: 'reason', label: 'Reason', area: true }], x => post(`/api/cases/${id}/escalate`, x).then(reload), 'Escalate');
    if (a === 'close') prompt2('Close case', [{ name: 'resolution', label: 'Resolution', options: [['CONFIRMED_FRAUD', 'Confirmed fraud'], ['FALSE_POSITIVE', 'False positive (labels feed model retraining)'], ['INCONCLUSIVE', 'Inconclusive']] }, { name: 'note', label: 'Closing note', area: true }], x => post(`/api/cases/${id}/close`, x).then(reload), 'Close case');
    if (a === 'fmr') post(`/api/cases/${id}/fmr`).then(d => modal('Fraud Monitoring Return — draft', `<pre class="json">${esc(JSON.stringify(d, null, 2))}</pre>`)).catch(fail);
    if (r === 'block') prompt2('Block account', [{ name: 'reason', label: 'Reason', value: 'Suspected account compromise — case #' + id }], x => post('/api/respond/block-account', { customer_id: cid, case_id: +id, ...x }).then(reload), 'Block account', true);
    if (r === 'unblock') prompt2('Unblock account', [{ name: 'reason', label: 'Reason', value: 'Customer verified' }], x => post('/api/respond/unblock-account', { customer_id: cid, case_id: +id, ...x }).then(reload), 'Unblock');
    if (r === 'notify') prompt2('Notify customer', [{ name: 'message', label: 'Message (SMS + email, mocked gateway)', area: true, value: 'We noticed unusual activity on your account. Please call 1800-XXX-XXXX to verify recent transactions.' }], x => post('/api/respond/notify', { customer_id: cid, case_id: +id, ...x }).then(reload), 'Send');
    if (r === 'team') prompt2('Trigger bank fraud team', [{ name: 'summary', label: 'Summary for the fraud desk', area: true, value: c.title }], x => post('/api/respond/fraud-team', { customer_id: cid, case_id: +id, ...x }).then(reload), 'Trigger');
    if (r === 'npci') prompt2('Report VPA to NPCI', [{ name: 'reason', label: 'Reason', value: 'Suspected mule account receiving fraud proceeds' }], x => post('/api/respond/npci', { vpa: b.dataset.v, customer_id: cid, case_id: +id, ...x }).then(d => { ok('NPCI reference ' + d.npci_ref); reload(); }), 'Report');
  });
  if ($('#asg')) $('#asg').onchange = e => e.target.value && act(() => post(`/api/cases/${id}/assign`, { user_id: +e.target.value }));
  if ($('#cst')) $('#cst').onchange = e => e.target.value && act(() => post(`/api/cases/${id}/status`, { status: e.target.value }));
  if ($('#nf')) $('#nf').onsubmit = e => { e.preventDefault(); const note = e.target.note.value; act(() => post(`/api/cases/${id}/note`, { note })); };
};

function customerCard(cu) {
  return `<div class="card"><div class="hd"><h2>${esc(cu.name)}</h2>${stat(cu.status)}<div class="grow"></div><a href="#/customer/${esc(cu.id)}">Investigate →</a></div>
    <div class="kv"><div>Customer ID</div><div class="mono">${esc(cu.id)}</div><div>Segment</div><div>${esc(cu.segment)}</div><div>Home city</div><div>${esc(cu.home_city)}</div><div>UPI ID</div><div class="mono">${esc(cu.vpa)}</div><div>Account</div><div class="mono">${esc(cu.account_no)}</div><div>Card</div><div class="mono">•••• ${esc(cu.card_last4)}</div><div>Mobile</div><div class="mono" id="pii-phone">${esc(cu.phone)}</div><div>Email</div><div class="mono" id="pii-email">${esc(cu.email)}</div></div></div>`;
}

// ======================================================================= investigate / customer 360
VIEWS.investigate = async el => {
  title('Investigate');
  el.innerHTML = `<div class="card"><div class="hd"><h2>Find a customer</h2></div><div class="bar-row"><input id="q" placeholder="Customer ID, name or UPI ID" style="flex:1;max-width:420px"><button class="primary" id="go">Search</button></div><div id="res" style="margin-top:12px"></div></div>
    <div class="card"><div class="hd"><h2>Highest-risk customers, last 24 hours</h2></div><div id="risky"></div></div>`;
  const tbl = rows => rows.length ? `<div class="tbl-wrap"><table><thead><tr><th>Customer</th><th>UPI ID</th><th>City</th><th>Segment</th><th>Status</th>${rows[0].alerts != null ? '<th class="num">Alerts</th><th>Max risk</th>' : ''}</tr></thead><tbody>${rows.map(r => `<tr class="click" onclick="location.hash='#/customer/${r.id}'"><td><b>${esc(r.name)}</b> <span class="muted mono">${esc(r.id)}</span></td><td class="mono">${esc(r.vpa)}</td><td>${esc(r.home_city)}</td><td>${esc(r.segment)}</td><td>${stat(r.status)}</td>${r.alerts != null ? `<td class="num">${r.alerts}</td><td>${risk(r.max_score)}</td>` : ''}</tr>`).join('')}</tbody></table></div>` : '<div class="empty">No matches</div>';
  const search = async () => { $('#res').innerHTML = tbl(await api('/api/customers?q=' + encodeURIComponent($('#q').value))); };
  $('#go').onclick = search; $('#q').onkeydown = e => e.key === 'Enter' && search();
  $('#risky').innerHTML = tbl(await api('/api/customers?risky=true'));
};

VIEWS.customer = async (el, cid) => {
  const c = await api('/api/customers/' + encodeURIComponent(cid));
  title(`${c.name} · ${c.id}`);
  const p = c.profile;
  el.innerHTML = `<div class="row cols-12"><div class="row" style="align-content:start">${customerCard(c)}
      ${can('respond') ? `<div class="card"><div class="hd"><h2>Respond</h2></div><div class="bar-row">
        ${c.status === 'BLOCKED' ? (can('unblock') ? '<button data-r="unblock">Unblock account</button>' : '') : '<button class="danger" data-r="block">Block account</button>'}
        <button data-r="notify">Notify customer</button><button data-r="team">Trigger fraud team</button><button data-r="case">Open case</button><button data-r="pii">Reveal contact details</button></div>
        <p class="muted" style="font-size:12px;margin:10px 0 0">Revealing contact details is recorded in the audit trail.</p></div>` : ''}
      <div class="card"><div class="hd"><h2>Behavioural profile</h2></div>
        <div class="kv"><div>Transactions learned</div><div>${p.transactions.toLocaleString('en-IN')}</div><div>Typical amount</div><div>${inr(p.typical_amount)}</div><div>Largest normal</div><div>${inr(p.max_amount)}</div>
        <div>Channels</div><div>${Object.entries(p.channels).map(([k, v]) => `${k} ${v}`).join(' · ') || '—'}</div><div>Usual cities</div><div>${p.known_cities.map(x => esc(x[0])).join(', ') || '—'}</div><div>Known devices</div><div class="mono" style="font-size:11px">${p.known_devices.map(x => esc(x[0])).join('<br>') || '—'}</div></div>
        <h3 style="margin:14px 0 6px">Activity by hour (IST)</h3><div class="hist" title="Share of this customer's transactions by hour of day">${p.hour_histogram.map((v, h) => `<i style="height:${Math.max(2, v / Math.max(1, ...p.hour_histogram) * 100)}%" title="${String(h).padStart(2, '0')}:00 — ${v} txns"></i>`).join('')}</div>
        <div class="bar-row muted" style="justify-content:space-between;font-size:10px;margin-top:2px"><span>00</span><span>06</span><span>12</span><span>18</span><span>23</span></div></div>
      ${c.cases.length ? `<div class="card"><div class="hd"><h2>Cases</h2></div>${c.cases.map(k => `<div><a href="#/case/${k.id}">#${k.id} ${esc(k.title)}</a> ${stat(k.status)}</div>`).join('')}</div>` : ''}
    </div><div class="card"><div class="tabs" id="tabs">${[['tl', 'Timeline'], ['dev', 'Devices & IPs'], ['geo', 'Geo-location'], ['graph', 'Link analysis']].map(([k, l], i) => `<button data-k="${k}" class="${i ? '' : 'on'}">${l}</button>`).join('')}</div><div id="tab"></div></div></div>`;
  const tabs = {
    tl: async box => {
      const ev = await api(`/api/customers/${cid}/timeline?days=7`);
      box.innerHTML = `<p class="muted" style="font-size:12px;margin-top:0">Last 7 days · ● transaction ■ security log ◆ response action</p><div class="tl">${ev.slice(0, 200).map(e => `<div class="ev ${e.kind}"><span class="muted" style="font-size:12px">${when(e.ts)}</span><span class="ic"></span><span>${e.kind === 'txn'
        ? `<a href="#" data-t="${esc(e.id)}">${esc(e.channel)} ${inr(e.amount)}</a> → ${esc(e.payee)} <span class="muted">· ${esc(e.city)} · ${esc(e.device_id)}</span> ${e.priority ? prio(e.priority) : ''} ${e.status !== 'APPROVED' ? stat(e.status) : ''}`
        : e.kind === 'log' ? `<b>${esc(e.event_type.replace(/_/g, ' ').toLowerCase())}</b> <span class="muted">${esc(e.source)} · ${esc(e.message)} ${e.ip ? '· ' + esc(e.ip) : ''}</span>`
          : `<b>${esc(e.type.replace(/_/g, ' ').toLowerCase())}</b> <span class="muted">by ${esc(e.actor)}</span>`}</span></div>`).join('') || '<div class="empty">No activity in the last 7 days</div>'}</div>`;
      $$('a[data-t]', box).forEach(a => a.onclick = e => { e.preventDefault(); showTxn(a.dataset.t); });
    },
    dev: async box => {
      const d = await api(`/api/customers/${cid}/devices`);
      const t = (rows, label) => `<h3 style="margin:4px 0 8px">${label}</h3><div class="tbl-wrap"><table><thead><tr><th>${label.slice(0, -1)}</th><th class="num">Txns</th><th>First seen</th><th>Last seen</th><th>Cities</th><th>Max risk</th><th>Shared with</th></tr></thead><tbody>${rows.map(r => `<tr><td class="mono">${esc(r.value)} ${r.watchlisted ? badge('Watchlist', 'st-FAIL') : ''}</td><td class="num">${r.n}</td><td>${ago(r.first_seen)}</td><td>${ago(r.last_seen)}</td><td>${esc(r.cities)}</td><td>${risk(r.max_risk)}</td><td>${r.shared_with.length ? r.shared_with.map(x => `<a href="#/customer/${x}">${x}</a>`).join(', ') : '<span class="muted">—</span>'}</td></tr>`).join('')}</tbody></table></div>`;
      box.innerHTML = t(d.devices, 'Devices') + '<br>' + t(d.ips, 'IP addresses') + `<p class="muted" style="font-size:12px">A device or IP shared with other customers is a strong mule / account-takeover indicator.</p>`;
    },
    geo: async box => {
      const g = await api(`/api/customers/${cid}/geo?days=30`);
      const W = Math.max(320, box.clientWidth || 600), H = Math.round(W * 1.05);
      const x = lon => (lon - 67.5) / (98 - 67.5) * (W - 40) + 20, y = lat => (37 - lat) / (37 - 6.5) * (H - 40) + 20;
      let s = Object.entries(g.cities).map(([n, [la, lo]]) => `<circle cx="${x(lo)}" cy="${y(la)}" r="3" fill="var(--text-muted)"/><text x="${x(lo) + 6}" y="${y(la) + 4}" font-size="11" fill="var(--text-muted)">${n}</text>`).join('');
      const pts = g.points;
      if (pts.length > 1) s += `<polyline points="${pts.map(p => x(p.lon) + ',' + y(p.lat)).join(' ')}" fill="none" stroke="var(--series-1)" stroke-opacity=".35" stroke-width="1.5"/>`;
      s += `<circle cx="${x(g.home.home_lon)}" cy="${y(g.home.home_lat)}" r="14" fill="none" stroke="var(--series-3)" stroke-width="2"/><text x="${x(g.home.home_lon) + 16}" y="${y(g.home.home_lat) - 10}" font-size="11" font-weight="600" fill="var(--text-primary)">Home</text>`;
      s += pts.map(p => `<circle cx="${x(p.lon)}" cy="${y(p.lat)}" r="${(p.risk_score || 0) >= 35 ? 7 : 4}" fill="${riskColor(p.risk_score || 0)}" stroke="var(--surface-1)" stroke-width="2"><title>${when(p.ts)} · ${p.city} · ${inr(p.amount)} ${p.channel} · risk ${Math.round(p.risk_score || 0)}</title></circle>`).join('');
      box.innerHTML = `<div class="legend" style="margin-bottom:8px"><span><i style="background:var(--good);border-radius:50%"></i>Low risk</span><span><i style="background:var(--warning);border-radius:50%"></i>Alert (low)</span><span><i style="background:var(--serious);border-radius:50%"></i>Medium</span><span><i style="background:var(--critical);border-radius:50%"></i>High</span><span><i style="border:2px solid var(--series-3);background:transparent;border-radius:50%"></i>Home city</span></div>
        <svg viewBox="0 0 ${W} ${H}" style="width:100%;max-width:720px;background:var(--surface-2);border-radius:8px">${s}</svg><p class="muted" style="font-size:12px">${pts.length} transactions in the last 30 days, schematic map of India (lat/long projection). Hover a point for details.</p>`;
    },
    graph: async box => {
      box.innerHTML = `${graphLegend}<div class="graph-box" id="gb" style="margin-top:8px"></div><p class="muted" style="font-size:12px">Customers linked through shared payees, devices and IP addresses over the last 72 hours. Click a customer to pivot.</p>`;
      forceGraph($('#gb', box), await api(`/api/graph?customer_id=${cid}&hours=72`), n => location.hash = '#/customer/' + n.label);
    },
  };
  const show = k => { $$('#tabs button').forEach(b => b.classList.toggle('on', b.dataset.k === k)); const box = $('#tab'); box.innerHTML = '<div class="empty">Loading…</div>'; tabs[k](box).catch(e => box.innerHTML = `<div class="empty">${esc(e.message)}</div>`); };
  $('#tabs').onclick = e => e.target.dataset.k && show(e.target.dataset.k);
  show('tl');
  el.addEventListener('click', async e => {
    const r = e.target.dataset.r; if (!r) return;
    const reload = () => route();
    if (r === 'block') prompt2('Block account', [{ name: 'reason', label: 'Reason', value: 'Suspicious activity under investigation' }], x => post('/api/respond/block-account', { customer_id: cid, ...x }).then(reload), 'Block account', true);
    if (r === 'unblock') prompt2('Unblock account', [{ name: 'reason', label: 'Reason', value: 'Customer verified' }], x => post('/api/respond/unblock-account', { customer_id: cid, ...x }).then(reload), 'Unblock');
    if (r === 'notify') prompt2('Notify customer', [{ name: 'message', label: 'Message', area: true, value: 'We noticed unusual activity on your account. Please call 1800-XXX-XXXX to verify.' }], x => post('/api/respond/notify', { customer_id: cid, ...x }).then(() => ok('Notification queued (mock gateway)')), 'Send');
    if (r === 'team') prompt2('Trigger bank fraud team', [{ name: 'summary', label: 'Summary', area: true }], x => post('/api/respond/fraud-team', { customer_id: cid, ...x }).then(() => ok('Fraud team notified')), 'Trigger');
    if (r === 'case') prompt2('Open case', [{ name: 'title', label: 'Title', value: 'Investigation: ' + c.name }, { name: 'priority', label: 'Priority', options: [['MEDIUM', 'Medium'], ['HIGH', 'High'], ['LOW', 'Low']] }], x => post('/api/cases', { customer_id: cid, ...x }).then(k => location.hash = '#/case/' + k.id), 'Create');
    if (r === 'pii') { try { const d = await api(`/api/customers/${cid}/pii`); $('#pii-phone').textContent = d.phone; $('#pii-email').textContent = d.email; e.target.disabled = true; } catch (x) { fail(x); } }
  });
};

// ======================================================================= fraud networks
VIEWS.networks = async el => {
  title('Fraud network detection');
  el.innerHTML = `<div class="row cols-12"><div class="card"><div class="hd"><h2>Suspected rings</h2><div class="grow"></div><select id="hrs"><option value="24">Last 24 h</option><option value="72">Last 72 h</option><option value="6">Last 6 h</option></select></div><div id="rings"></div></div>
    <div class="card"><div class="hd"><h2 id="gt">Select a ring</h2></div>${graphLegend}<div class="graph-box" id="gb" style="margin-top:8px"><div class="empty">Clusters of 3+ customers tied together by a shared payee, device or IP appear on the left.</div></div></div></div>`;
  const load = async () => {
    const hrs = $('#hrs').value; const rings = await api('/api/graph/rings?hours=' + hrs);
    $('#rings').innerHTML = rings.length ? rings.map((r, i) => `<div class="card click" data-i="${i}" style="margin-bottom:8px;cursor:pointer;background:var(--surface-2)"><div class="bar-row"><b>${r.size} customers</b>${r.max_score ? risk(r.max_score) : ''}<span class="muted">${r.alerts} alerts</span></div>
      <div style="font-size:12px;margin-top:6px">${r.shared.slice(0, 4).map(s => `<div><span class="muted">${s.type}</span> <span class="mono">${esc(s.value)}</span> · ${s.customers} customers ${s.watchlisted ? badge('Watchlist', 'st-FAIL') : ''}</div>`).join('')}</div></div>`).join('') : '<div class="empty">No rings detected in this window.</div>';
    $$('#rings [data-i]').forEach(d => d.onclick = async () => {
      const r = rings[d.dataset.i]; $('#gt').textContent = `Ring of ${r.size} customers`;
      const shared = r.shared.find(s => s.type === 'payee');
      const g = await api(shared ? `/api/graph?payee=${encodeURIComponent(shared.value)}&hours=${hrs}` : `/api/graph?customer_id=${r.members[0]}&hours=${hrs}`);
      forceGraph($('#gb'), g, n => location.hash = '#/customer/' + n.label);
    });
  };
  $('#hrs').onchange = load; await load();
};

// ======================================================================= response log
VIEWS.response = async el => {
  title('Response & actions');
  el.innerHTML = `<div class="card"><div class="tabs" id="tabs"><button data-k="actions" class="on">Actions taken</button><button data-k="notif">Outbound notifications</button><button data-k="watch">Watchlist</button></div><div id="tab"></div></div>`;
  const tabs = {
    actions: async b => { const r = await api('/api/actions?limit=300'); b.innerHTML = `<div class="tbl-wrap"><table><thead><tr><th>Time</th><th>Action</th><th>Target</th><th>By</th><th>Case / alert</th><th>Details</th></tr></thead><tbody>${r.map(a => `<tr><td>${when(a.ts)}</td><td><b>${esc(a.type.replace(/_/g, ' ').toLowerCase())}</b></td><td>${/^C\d+$/.test(a.target) ? `<a href="#/customer/${a.target}">${a.target}</a>` : `<span class="mono">${esc(a.target)}</span>`}</td><td>${esc(a.actor)} ${a.automated ? badge('auto') : ''}</td><td>${a.case_id ? `<a href="#/case/${a.case_id}">#${a.case_id}</a>` : ''} ${a.alert_id ? 'alert ' + a.alert_id : ''}</td><td class="trunc muted" title="${esc(a.details)}">${esc(a.details)}</td></tr>`).join('')}</tbody></table></div>`; },
    notif: async b => { const r = await api('/api/notifications?limit=300'); b.innerHTML = `<p class="muted" style="margin-top:0;font-size:12px">SMS, email, NPCI and bank fraud-desk gateways are mocked in this prototype: messages are recorded here instead of being sent.</p><div class="tbl-wrap"><table><thead><tr><th>Time</th><th>Channel</th><th>Recipient</th><th>Subject</th><th>Message</th><th>Status</th></tr></thead><tbody>${r.map(n => `<tr><td>${when(n.ts)}</td><td>${badge(n.channel)}</td><td class="mono">${esc(n.recipient)}</td><td>${esc(n.subject)}</td><td class="trunc" title="${esc(n.message)}">${esc(n.message)}</td><td class="muted">${esc(n.status)}</td></tr>`).join('')}</tbody></table></div>`; },
    watch: async b => {
      const r = await api('/api/watchlist');
      b.innerHTML = `${can('respond') ? `<form id="wf" class="bar-row" style="margin-bottom:12px"><input name="value" placeholder="VPA, IP or device ID" required><select name="kind"><option>VPA</option><option>IP</option><option>DEVICE</option></select><input name="reason" placeholder="Reason" style="flex:1"><button class="primary">Add to watchlist</button></form>` : ''}
        <div class="tbl-wrap"><table><thead><tr><th>Value</th><th>Kind</th><th>Reason</th><th>Added</th><th>By</th>${can('rules') ? '<th></th>' : ''}</tr></thead><tbody>${r.map(w => `<tr><td class="mono">${esc(w.value)}</td><td>${esc(w.kind)}</td><td>${esc(w.reason)}</td><td>${ago(w.added)}</td><td>${esc(w.added_by)}</td>${can('rules') ? `<td><button class="sm" data-del="${esc(w.value)}">Remove</button></td>` : ''}</tr>`).join('')}</tbody></table></div>`;
      if ($('#wf', b)) $('#wf', b).onsubmit = async e => { e.preventDefault(); try { await post('/api/watchlist', Object.fromEntries(new FormData(e.target))); ok('Added'); tabs.watch(b); } catch (x) { fail(x); } };
      $$('[data-del]', b).forEach(x => x.onclick = async () => { try { await del('/api/watchlist/' + encodeURIComponent(x.dataset.del)); tabs.watch(b); } catch (y) { fail(y); } });
    },
  };
  const show = k => { $$('#tabs button').forEach(b => b.classList.toggle('on', b.dataset.k === k)); tabs[k]($('#tab')).catch(fail); };
  $('#tabs').onclick = e => e.target.dataset.k && show(e.target.dataset.k); show('actions');
};

// ======================================================================= rules & model
VIEWS.model = async el => {
  title('Detection rules & ML model');
  const [rules, m, st] = await Promise.all([api('/api/rules'), api('/api/model'), api('/api/settings')]);
  const edit = can('rules');
  el.innerHTML = `<div class="row cols-2"><div class="card"><div class="hd"><h2>Machine-learning model</h2><div class="grow"></div>${can('model') ? '<button class="primary" id="rt">Retrain now</button>' : ''}</div>
      <div class="kv"><div>Active version</div><div><b>${esc(m.active)}</b></div><div>Approach</div><div>Isolation Forest (unsupervised anomaly detection) blended with a gradient-boosted classifier trained on confirmed outcomes</div>
      <div>Analyst feedback</div><div>${m.feedback.fraud_feedback || 0} confirmed fraud · ${m.feedback.legit_feedback || 0} false positives / genuine</div><div>Auto-retrain</div><div>every ${m.auto_retrain_minutes} min</div><div>Features</div><div class="mono" style="font-size:11px">${m.features.join(', ')}</div></div></div>
    <div class="card"><div class="hd"><h2>Automated response</h2></div>
      <label class="bar-row" style="margin-bottom:8px"><input type="checkbox" id="ar" ${st.auto_response ? 'checked' : ''} ${edit ? '' : 'disabled'}> Hold high-risk transactions (score ≥ 80) and send step-up SMS</label>
      <label class="bar-row"><input type="checkbox" id="ab" ${st.auto_block ? 'checked' : ''} ${edit ? '' : 'disabled'}> Auto-block account and trigger fraud team (score ≥ 92)</label>
      <p class="muted" style="font-size:12px">Priority bands: High ≥ 75 · Medium ≥ 55 · Low ≥ 35. Final score = 45% rules + 30% ML + 25% behaviour, with critical rules never diluted.</p></div></div>
    <div class="card"><div class="hd"><h2>Model versions</h2></div><div class="tbl-wrap"><table><thead><tr><th>Version</th><th>Trained</th><th>Trigger</th><th>Kind</th><th class="num">Samples</th><th class="num">Labelled</th><th class="num">Holdout AUC</th><th class="num">Precision</th><th class="num">Recall</th><th class="num">IF AUC</th><th></th></tr></thead><tbody>
      ${m.versions.map(v => `<tr><td><b>${v.version}</b> ${v.active ? badge('active', 'st-PASS') : ''}</td><td>${when(v.trained_at)}</td><td>${esc(v.trigger)}</td><td>${esc(v.kind)}</td><td class="num">${v.n_samples.toLocaleString('en-IN')}</td><td class="num">${v.n_labeled.toLocaleString('en-IN')}</td><td class="num">${v.metrics.holdout_auc ?? '—'}</td><td class="num">${v.metrics['holdout_precision@0.5'] ?? '—'}</td><td class="num">${v.metrics['holdout_recall@0.5'] ?? '—'}</td><td class="num">${v.metrics.iforest_auc ?? '—'}</td><td>${!v.active && can('model') ? `<button class="sm" data-v="${v.version}">Activate</button>` : ''}</td></tr>`).join('')}</tbody></table></div></div>
    <div class="card"><div class="hd"><h2>Rule engine</h2><div class="grow"></div><span class="muted" style="font-size:12px">${edit ? 'Edit thresholds and weights, then Save. Changes apply immediately and are audited.' : 'Read-only for your role.'}</span></div>
      <div class="tbl-wrap"><table><thead><tr><th>On</th><th>Rule</th><th>Weight</th><th>Parameters</th><th class="num">Hits</th>${edit ? '<th></th>' : ''}</tr></thead><tbody>
      ${rules.map(r => `<tr data-id="${r.id}"><td><input type="checkbox" name="enabled" ${r.enabled ? 'checked' : ''} ${edit ? '' : 'disabled'}></td><td><b>${r.id} ${esc(r.name)}</b><div class="muted" style="font-size:12px">${esc(r.description)}</div></td>
        <td><input name="weight" type="number" min="0" max="100" value="${r.weight}" style="width:70px" ${edit ? '' : 'disabled'}></td>
        <td><div class="bar-row">${Object.entries(r.params).map(([k, v]) => `<label class="f" style="font-size:11px">${esc(k)}<input data-p="${esc(k)}" value="${v}" style="width:90px" ${edit ? '' : 'disabled'}></label>`).join('') || '<span class="muted">—</span>'}</div></td>
        <td class="num">${r.hits.toLocaleString('en-IN')}</td>${edit ? '<td><button class="sm" data-save>Save</button></td>' : ''}</tr>`).join('')}</tbody></table></div></div>`;
  if ($('#rt')) $('#rt').onclick = async e => { e.target.disabled = true; e.target.textContent = 'Training…'; try { const r = await post('/api/model/retrain'); ok(`Model ${r.version} trained and activated`); route(); } catch (x) { fail(x); e.target.disabled = false; } };
  $$('[data-v]', el).forEach(b => b.onclick = async () => { try { await post('/api/model/activate', { version: b.dataset.v }); ok('Activated ' + b.dataset.v); route(); } catch (x) { fail(x); } });
  $$('[data-save]', el).forEach(b => b.onclick = async () => {
    const tr = b.closest('tr'); const params = {}; $$('[data-p]', tr).forEach(i => params[i.dataset.p] = i.value);
    try { await put('/api/rules/' + tr.dataset.id, { enabled: $('[name=enabled]', tr).checked, weight: +$('[name=weight]', tr).value, params }); ok('Rule ' + tr.dataset.id + ' saved'); } catch (x) { fail(x); }
  });
  const saveSettings = async () => { try { await put('/api/settings', { auto_response: $('#ar').checked, auto_block: $('#ab').checked }); ok('Response settings saved'); } catch (x) { fail(x); } };
  $('#ar').onchange = saveSettings; $('#ab').onchange = saveSettings;
};

// ======================================================================= reports & compliance
VIEWS.reports = async el => {
  title('Reports & compliance');
  let period = 'daily';
  el.innerHTML = `<div class="card"><div class="hd"><div class="seg" id="per"><button data-v="daily" class="on">Daily</button><button data-v="weekly">Weekly</button></div><div class="grow"></div>
    <button id="csv">Download alerts CSV</button><button id="prn">Print report</button>${can('export') ? '<button class="primary" id="aud">Export auditor pack</button>' : ''}</div><div id="rep"></div></div>
    <div class="card"><div class="hd"><h2>Regulatory compliance checks</h2><div class="grow"></div><button id="rc">Re-run checks</button></div><div id="comp"></div></div>`;
  const load = async () => {
    const r = await api('/api/reports/' + period); const k = r.kpis;
    $('#rep').innerHTML = `<p class="muted" style="margin-top:0">${period === 'daily' ? 'Daily' : 'Weekly'} fraud report · ${when(r.from)} → ${when(r.generated_at)} IST</p>
      <div class="tiles">${[['Transactions', k.transactions.toLocaleString('en-IN')], ['Alerts', k.alerts], ['Detection rate', pct(k.detection_rate)], ['Prevention rate', pct(k.prevention_rate)], ['Alert precision', pct(k.alert_precision)],
        ['False positives (closed alerts)', pct(k.false_positive_rate_closed_alerts)], ['Mean time to respond', k.mean_time_to_acknowledge_min == null ? '—' : k.mean_time_to_acknowledge_min + ' min'], ['Mean case resolution', k.mean_case_resolution_hours == null ? '—' : k.mean_case_resolution_hours + ' h'],
        ['Loss prevented', inrShort(k.loss_prevented)], ['Loss exposed', inrShort(k.loss_exposed)], ['Automated actions', k.auto_actions], ['Analyst actions', k.manual_actions]].map(t => `<div class="tile"><div class="k">${t[0]}</div><div class="v" style="font-size:22px">${t[1]}</div></div>`).join('')}</div>
      <div class="row cols-2" style="margin-top:16px"><div><h3 style="margin-bottom:8px">Fraud by typology</h3><table><thead><tr><th>Pattern</th><th class="num">Txns</th><th class="num">Detected</th><th class="num">Amount</th></tr></thead><tbody>${Object.entries(k.by_scenario).map(([s, v]) => `<tr><td>${esc(s.replace(/_/g, ' ').toLowerCase())}</td><td class="num">${v.transactions}</td><td class="num">${v.detected} (${Math.round(v.detected / v.transactions * 100)}%)</td><td class="num">${inr(v.amount)}</td></tr>`).join('') || '<tr><td colspan="4" class="muted">No fraud recorded</td></tr>'}</tbody></table></div>
        <div><h3 style="margin-bottom:8px">Top rules triggered (all time)</h3><table><tbody>${r.top_rules.map(x => `<tr><td>${x.id} ${esc(x.name)}</td><td class="num">${x.hits.toLocaleString('en-IN')}</td></tr>`).join('')}</tbody></table></div></div>
      <div class="row cols-2" style="margin-top:16px"><div><h3 style="margin-bottom:8px">Highest-risk customers</h3><table><thead><tr><th>Customer</th><th>Status</th><th class="num">Alerts</th><th>Max risk</th></tr></thead><tbody>${r.top_risky_customers.map(c => `<tr><td><a href="#/customer/${c.customer_id}">${esc(c.name)}</a></td><td>${stat(c.status)}</td><td class="num">${c.alerts}</td><td>${risk(c.max_risk)}</td></tr>`).join('')}</tbody></table></div>
        <div><h3 style="margin-bottom:8px">Response actions</h3><table><tbody>${r.actions.map(a => `<tr><td>${esc(a.type.replace(/_/g, ' ').toLowerCase())}</td><td class="num">${a.n}</td></tr>`).join('') || '<tr><td class="muted">None</td></tr>'}</tbody></table>
        <h3 style="margin:14px 0 8px">Cases closed</h3><table><tbody>${r.cases_closed.map(a => `<tr><td>${esc((a.resolution || '').replace(/_/g, ' ').toLowerCase())}</td><td class="num">${a.n}</td></tr>`).join('') || '<tr><td class="muted">None</td></tr>'}</tbody></table></div></div>`;
  };
  const comp = async () => {
    const c = await api('/api/compliance');
    $('#comp').innerHTML = `<table><thead><tr><th>Status</th><th>Check</th><th>Reference</th><th>Result</th></tr></thead><tbody>${c.checks.map(x => `<tr><td>${stat(x.status)}</td><td><b>${esc(x.title)}</b></td><td class="muted">${esc(x.reference)}</td><td>${esc(x.detail)}</td></tr>`).join('')}</tbody></table><p class="muted" style="font-size:12px">${esc(c.note)}</p>`;
  };
  $('#per').onclick = e => { const v = e.target.dataset.v; if (!v) return; period = v; $$('#per button').forEach(b => b.classList.toggle('on', b.dataset.v === v)); load(); };
  $('#csv').onclick = () => download(`/api/reports/${period}?format=csv`, `kavach_${period}_alerts.csv`);
  $('#prn').onclick = () => window.print();
  if ($('#aud')) $('#aud').onclick = () => download('/api/export/auditor?days=30', 'kavach_auditor_pack.zip');
  $('#rc').onclick = comp;
  await Promise.all([load(), comp()]);
};

// ======================================================================= audit
VIEWS.audit = async el => {
  title('Audit trail');
  el.innerHTML = `<div class="card"><div class="hd"><input id="fa" placeholder="Actor (e.g. analyst1)"><input id="fx" placeholder="Action contains (e.g. CASE, LOGIN)"><button id="go">Filter</button><div class="grow"></div><button class="primary" id="ver">Verify integrity</button></div><div id="vr"></div>
    <p class="muted" style="font-size:12px;margin-top:0">Every login, view of sensitive data, configuration change and response action is recorded. Each entry is SHA-256 hash-chained to the previous one, so any edit or deletion breaks the chain.</p>
    <div class="tbl-wrap"><table><thead><tr><th>#</th><th>Time (IST)</th><th>Actor</th><th>Role</th><th>Action</th><th>Entity</th><th>Details</th><th>IP</th><th>Hash</th></tr></thead><tbody id="rows"></tbody></table></div></div>`;
  const load = async () => {
    const r = await api(`/api/audit?limit=300&actor=${encodeURIComponent($('#fa').value)}&action=${encodeURIComponent($('#fx').value)}`);
    $('#rows').innerHTML = r.map(a => `<tr><td class="mono">${a.id}</td><td>${when(a.ts)}</td><td>${esc(a.actor)}</td><td>${esc(a.role)}</td><td><b>${esc(a.action)}</b></td><td>${esc(a.entity)} <span class="mono">${esc(a.entity_id)}</span></td><td class="trunc muted" title="${esc(a.details)}">${esc(a.details)}</td><td class="mono">${esc(a.ip)}</td><td class="mono muted">${esc(a.hash.slice(0, 10))}…</td></tr>`).join('');
  };
  $('#go').onclick = load;
  $('#ver').onclick = async () => { const v = await api('/api/audit/verify'); $('#vr').innerHTML = `<p>${v.valid ? stat('PASS') + ` Chain intact — ${v.checked.toLocaleString('en-IN')} entries verified.` : stat('FAIL') + ` Chain broken at entry #${v.broken_at_id}.`}</p>`; };
  await load();
};

// ======================================================================= admin
VIEWS.admin = async el => {
  title('Administration');
  const tabs = [['users', 'Users & roles'], ['int', 'Integrations'], ['siem', 'Security logs (SIEM)'], ['sim', 'Data simulator']];
  el.innerHTML = `<div class="card"><div class="tabs" id="tabs">${tabs.map(([k, l], i) => `<button data-k="${k}" class="${i ? '' : 'on'}">${l}</button>`).join('')}</div><div id="tab"></div></div>`;
  const T = {
    users: async b => {
      const us = await api('/api/users'); const e = can('users');
      b.innerHTML = `<div class="tbl-wrap"><table><thead><tr><th>User</th><th>Role</th><th>MFA</th><th>Active</th><th>Last login</th>${e ? '<th></th>' : ''}</tr></thead><tbody>${us.map(u => `<tr data-id="${u.id}"><td><b>${esc(u.full_name)}</b> <span class="muted">${esc(u.username)}</span></td>
        <td>${e ? `<select data-f="role">${['ADMIN', 'MANAGER', 'ANALYST', 'READONLY'].map(r => `<option ${r === u.role ? 'selected' : ''}>${r}</option>`).join('')}</select>` : esc(u.role)}</td><td>${u.mfa_enabled ? stat('PASS').replace('PASS', 'Enrolled') : '<span class="muted">Not enrolled</span>'}</td>
        <td>${e ? `<input type="checkbox" data-f="active" ${u.active ? 'checked' : ''}>` : u.active ? 'Yes' : 'No'}</td><td>${ago(u.last_login)}</td>${e ? `<td><button class="sm" data-mfa>Reset MFA</button></td>` : ''}</tr>`).join('')}</tbody></table></div>
        ${e ? `<h3 style="margin:16px 0 8px">Add user</h3><form id="uf" class="bar-row"><input name="username" placeholder="username" required><input name="full_name" placeholder="Full name"><select name="role"><option>ANALYST</option><option>MANAGER</option><option>READONLY</option><option>ADMIN</option></select><input name="password" type="password" placeholder="Initial password (10+ chars)" required><button class="primary">Create</button></form>` : ''}
        <h3 style="margin:16px 0 8px">Role permissions</h3><table><thead><tr><th>Role</th><th>Can</th></tr></thead><tbody><tr><td>Admin</td><td>Everything, including users, rules, integrations</td></tr><tr><td>Manager</td><td>Triage, cases, assign &amp; escalate, response actions, unblock, model retraining, exports, audit</td></tr><tr><td>Analyst</td><td>Triage alerts, work cases, response actions (block, notify, NPCI report)</td></tr><tr><td>Read-only</td><td>View dashboards, reports, audit trail, exports (auditors)</td></tr></tbody></table>`;
      $$('[data-f]', b).forEach(i => i.onchange = async () => { const id = i.closest('tr').dataset.id; try { await put('/api/users/' + id, { [i.dataset.f]: i.type === 'checkbox' ? i.checked : i.value }); ok('User updated'); } catch (x) { fail(x); T.users(b); } });
      $$('[data-mfa]', b).forEach(i => i.onclick = async () => { try { await put('/api/users/' + i.closest('tr').dataset.id, { reset_mfa: true }); ok('MFA reset'); T.users(b); } catch (x) { fail(x); } });
      if ($('#uf', b)) $('#uf', b).onsubmit = async ev => { ev.preventDefault(); try { await post('/api/users', Object.fromEntries(new FormData(ev.target))); ok('User created'); T.users(b); } catch (x) { fail(x); } };
    },
    int: async b => {
      const d = await api('/api/integrations'); const e = can('integrations');
      b.innerHTML = `<div class="row cols-2"><div><h3 style="margin-bottom:8px">Bank-facing REST API</h3><div class="kv"><div>Ingest API key</div><div class="mono">${esc(d.ingest_api_key)} ${e ? '<button class="sm" id="rot">Rotate</button>' : ''}</div></div>
        <table style="margin-top:10px"><tbody>${d.endpoints.map(x => `<tr><td>${badge(x.method)}</td><td class="mono">${esc(x.path)}</td><td class="muted">${esc(x.desc)}</td></tr>`).join('')}</tbody></table>
        <p class="muted" style="font-size:12px">Full interactive API docs: <a href="/docs" target="_blank">/docs</a></p>
        <pre class="json">curl -X POST ${location.origin}/api/v1/transactions \\
  -H "X-API-Key: &lt;key&gt;" -H "Content-Type: application/json" \\
  -d '{"customer_id":"C10001","channel":"UPI","amount":49000,
       "payee":"quickcash77@ybl","payee_type":"P2P","device_id":"DEV-NEW1"}'</pre></div>
        <div><h3 style="margin-bottom:8px">Webhooks (real-time alert push)</h3>${e ? `<table><tbody>${d.webhooks.map(w => `<tr><td class="mono trunc">${esc(w.url)}</td><td class="muted">${esc(w.events)}</td><td class="muted">${esc(w.last_status || '')}</td><td><button class="sm" data-test="${w.id}">Test</button> <button class="sm" data-wdel="${w.id}">Delete</button></td></tr>`).join('') || '<tr><td class="muted">No webhooks yet</td></tr>'}</tbody></table>
        <form id="wf" class="bar-row" style="margin-top:10px"><input name="url" placeholder="https://bank.example/hooks/kavach" style="flex:1" value="${location.origin}/api/webhook-sink"><select name="events"><option value="alert.high">alert.high</option><option value="fraud_team.triggered">fraud_team.triggered</option><option value="*">all events</option></select><button class="primary">Add</button></form>
        <p class="muted" style="font-size:12px">Payloads are signed with HMAC-SHA256 in <span class="mono">X-Kavach-Signature</span>. The prefilled URL is a built-in test receiver; deliveries it got are listed below.</p><div id="sink"></div>` : '<p class="muted">Admins manage webhooks.</p>'}</div></div>`;
      if (e) {
        $('#rot', b).onclick = async () => { try { await post('/api/integrations/rotate-key'); ok('Key rotated — update the bank systems'); T.int(b); } catch (x) { fail(x); } };
        $('#wf', b).onsubmit = async ev => { ev.preventDefault(); const f = Object.fromEntries(new FormData(ev.target)); try { const r = await post('/api/webhooks', { url: f.url, events: [f.events] }); ok('Webhook added. Signing secret: ' + r.secret); T.int(b); } catch (x) { fail(x); } };
        $$('[data-test]', b).forEach(x => x.onclick = async () => { await post(`/api/webhooks/${x.dataset.test}/test`); ok('Test sent'); setTimeout(() => T.int(b), 1200); });
        $$('[data-wdel]', b).forEach(x => x.onclick = async () => { await del('/api/webhooks/' + x.dataset.wdel); T.int(b); });
        const sink = await api('/api/webhook-sink');
        $('#sink', b).innerHTML = sink.length ? `<h3 style="margin:10px 0 6px">Test receiver: last deliveries</h3>${sink.slice(0, 5).map(s => `<pre class="json" style="max-height:120px">${esc(when(s.ts))} ${esc(JSON.stringify(s.headers))}\n${esc(s.body)}</pre>`).join('')}` : '';
      }
    },
    siem: async b => {
      const r = await api('/api/siem?limit=300');
      b.innerHTML = `<p class="muted" style="margin-top:0;font-size:12px">Security events aggregated from net-banking, mobile app and telco feeds (simulated). Ingest more via <span class="mono">POST /api/v1/logs</span>. These feed rule R10 and the ML features.</p><div class="tbl-wrap"><table><thead><tr><th>Time</th><th>Source</th><th>Event</th><th>Severity</th><th>Customer</th><th>IP</th><th>Device</th><th>Message</th></tr></thead><tbody>${r.map(l => `<tr><td>${when(l.ts)}</td><td>${esc(l.source)}</td><td><b>${esc(l.event_type)}</b></td><td>${badge(l.severity, l.severity === 'HIGH' ? 'p-HIGH' : l.severity === 'MEDIUM' ? 'p-MEDIUM' : '')}</td><td><a href="#/customer/${esc(l.customer_id)}">${esc(l.customer_id)}</a></td><td class="mono">${esc(l.ip)}</td><td class="mono">${esc(l.device_id)}</td><td>${esc(l.message)}</td></tr>`).join('')}</tbody></table></div>`;
    },
    sim: async b => {
      const s = await api('/api/simulator'); const e = can('simulator');
      b.innerHTML = `<p class="secondary" style="margin-top:0">The simulator stands in for the bank's UPI switch, card switch and mobile-banking core: it streams synthetic transactions for ${'250'} customers and injects fraud patterns.</p>
        <div class="kv"><div>Status</div><div>${s.running ? stat('ACTIVE').replace('ACTIVE', 'Running') : 'Paused'}</div><div>Events emitted</div><div>${s.emitted.toLocaleString('en-IN')}</div><div>Scenarios injected</div><div>${s.scenarios_injected}</div><div>Queued events</div><div>${s.queued_events}</div></div>
        ${e ? `<form id="sf" class="bar-row" style="margin-top:14px"><label class="f">Transactions / second<input name="tps" type="number" step="0.1" min="0.1" max="20" value="${s.tps}"></label><label class="f">Fraud rate (0–0.5)<input name="fraud_rate" type="number" step="0.01" min="0" max="0.5" value="${s.fraud_rate}"></label><label class="f">Running<select name="running"><option value="1" ${s.running ? 'selected' : ''}>Yes</option><option value="" ${s.running ? '' : 'selected'}>No</option></select></label><button class="primary" style="align-self:end">Apply</button></form>
        <div class="bar-row" style="margin-top:12px">${s.scenarios.map(k => `<button class="sm" data-k="${k}">Inject ${k.replace(/_/g, ' ').toLowerCase()}</button>`).join('')}</div>` : ''}`;
      if (e) {
        $('#sf', b).onsubmit = async ev => { ev.preventDefault(); const f = Object.fromEntries(new FormData(ev.target)); try { await post('/api/simulator', { tps: +f.tps, fraud_rate: +f.fraud_rate, running: !!f.running }); ok('Simulator updated'); T.sim(b); } catch (x) { fail(x); } };
        $$('[data-k]', b).forEach(x => x.onclick = async () => { const r = await post('/api/simulator/inject', { kind: x.dataset.k }); ok('Injected ' + r.kind); });
      }
    },
  };
  const show = k => { $$('#tabs button').forEach(x => x.classList.toggle('on', x.dataset.k === k)); T[k]($('#tab')).catch(fail); };
  $('#tabs').onclick = e => e.target.dataset.k && show(e.target.dataset.k); show('users');
};

// ======================================================================= account
VIEWS.account = async el => {
  title('My account');
  const me = await api('/api/me');
  el.innerHTML = `<div class="row cols-2"><div class="card"><div class="hd"><h2>Multi-factor authentication</h2>${me.mfa_enabled ? stat('PASS').replace('PASS', 'Enabled') : ''}</div>
    <p class="secondary">Protect your account with a time-based one-time code (Google Authenticator, Microsoft Authenticator, Authy…).</p>
    <button class="primary" id="ms">${me.mfa_enabled ? 'Re-enrol authenticator' : 'Set up MFA'}</button><div id="mfa" style="margin-top:12px"></div></div>
    <div class="card"><div class="hd"><h2>Change password</h2></div><form id="pf" style="display:grid;gap:10px;max-width:320px"><input type="password" name="old" placeholder="Current password" required><input type="password" name="new" placeholder="New password (10+ chars, mixed)" required><div><button class="primary">Update password</button></div></form>
    <div class="kv" style="margin-top:16px"><div>Username</div><div>${esc(me.username)}</div><div>Role</div><div>${esc(me.role)}</div><div>Permissions</div><div class="muted">${me.permissions.join(', ')}</div></div></div></div>`;
  $('#ms').onclick = async () => {
    const d = await post('/api/me/mfa/setup');
    $('#mfa').innerHTML = `<p>Add this key to your authenticator app, then enter the 6-digit code it shows.</p><div class="kv"><div>Secret key</div><div class="mono">${esc(d.secret)}</div><div>Setup URI</div><div class="mono" style="word-break:break-all;font-size:11px">${esc(d.otpauth_uri)}</div></div>
      <form id="mf" class="bar-row" style="margin-top:10px"><input name="otp" placeholder="123456" inputmode="numeric" required><button class="primary">Verify &amp; enable</button></form>`;
    $('#mf').onsubmit = async e => { e.preventDefault(); try { await post('/api/me/mfa/enable', { otp: e.target.otp.value }); ok('MFA enabled — it will be required at next sign-in'); route(); } catch (x) { fail(x); } };
  };
  $('#pf').onsubmit = async e => { e.preventDefault(); try { await post('/api/me/password', Object.fromEntries(new FormData(e.target))); ok('Password changed'); e.target.reset(); } catch (x) { fail(x); } };
};

// ======================================================================= start
if (S.token) boot(); else renderLogin();
