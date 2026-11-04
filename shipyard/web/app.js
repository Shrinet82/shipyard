/* Shipyard dashboard. Everything from the server is shown as text (textContent): there is no innerHTML anywhere. */
(() => {
'use strict';

// ---- tiny DOM helpers ------------------------------------------------------------------------------
const SVG_NS = 'http://www.w3.org/2000/svg';
const ICONS = {
  logo: ['M12 7v14', 'M5 13a7 7 0 0 0 14 0', 'M8 11h8', 'circle:12,5,2'],
  overview: ['rect:3,3,7,7', 'rect:14,3,7,7', 'rect:3,14,7,7', 'rect:14,14,7,7'],
  audit: ['M8 6h13M8 12h13M8 18h13', 'M3.5 6h.01M3.5 12h.01M3.5 18h.01'],
  approvals: ['circle:12,12,9', 'M12 7v5l3 2'],
  sbom: ['M12 3l8 4.5v9L12 21l-8-4.5v-9z', 'M4 7.5l8 4.5 8-4.5M12 12v9'],
  backends: ['rect:3,4,18,7', 'rect:3,13,18,7', 'M7 7.5h.01M7 16.5h.01'],
  roles: ['circle:9,8,3.5', 'M2.5 20a6.5 6.5 0 0 1 13 0', 'M16 4.5a3.5 3.5 0 0 1 0 7M18 14.5a6.5 6.5 0 0 1 3.5 5.5'],
  key: ['circle:8,15,4', 'M11 12l9-9M17 6l3 3M15 8l2 2'],
  shield: ['M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z', 'M8.5 12l2.5 2.5 4.5-5'],
  copy: ['rect:9,9,11,11', 'M5 15V5a1 1 0 0 1 1-1h10'],
  check: ['M5 12l5 5 9-10'],
  alert: ['circle:12,12,9', 'M12 8v5M12 16h.01'],
  x: ['M6 6l12 12M18 6L6 18'],
  lock: ['rect:5,11,14,10', 'M8 11V8a4 4 0 0 1 8 0v3'],
};
function icon(name, size = 18) {
  const s = document.createElementNS(SVG_NS, 'svg');
  for (const [k, v] of Object.entries({ width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 1.8, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' })) s.setAttribute(k, v);
  for (const d of ICONS[name] || []) {
    let el;
    if (d.startsWith('circle:')) { const [cx, cy, r] = d.slice(7).split(','); el = document.createElementNS(SVG_NS, 'circle'); el.setAttribute('cx', cx); el.setAttribute('cy', cy); el.setAttribute('r', r); }
    else if (d.startsWith('rect:')) { const [x, y, w, hh] = d.slice(5).split(','); el = document.createElementNS(SVG_NS, 'rect'); el.setAttribute('x', x); el.setAttribute('y', y); el.setAttribute('width', w); el.setAttribute('height', hh); el.setAttribute('rx', 1.5); }
    else { el = document.createElementNS(SVG_NS, 'path'); el.setAttribute('d', d); }
    s.appendChild(el);
  }
  return s;
}
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'style' || k === 'html' || k === 'innerHTML') throw new Error('not allowed: ' + k);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === undefined || kid === null || kid === false) continue;
    el.appendChild(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
// replaceChildren that skips null/false, so conditional pieces never turn into the words "null" or "false"
function put(el, ...kids) { el.replaceChildren(...kids.flat(Infinity).filter((k) => k !== null && k !== undefined && k !== false)); }
const mono = (t, cls = '') => h('span', { class: ('mono ' + cls).trim(), text: t });
const safeUrl = (u) => (typeof u === 'string' && /^https:\/\//.test(u) ? u : null);

// ---- state, api --------------------------------------------------------------------------------------
const S = { token: null, me: null, timers: [], approvals: 0 };
try { S.token = sessionStorage.getItem('sy_token'); } catch (e) { /* storage blocked: sign in each time */ }
const root = document.getElementById('root');

async function api(path, opts = {}) {
  const headers = { Accept: 'application/json' };
  if (S.token) headers.Authorization = 'Bearer ' + S.token;
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
  let res;
  try { res = await fetch(path, { method: opts.method || 'GET', headers, body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined }); }
  catch (e) { throw Object.assign(new Error('The Gatekeeper is unreachable.'), { offline: true }); }
  if (opts.raw && res.ok) return res;
  let data = null;
  try { data = await res.json(); } catch (e) { /* not json */ }
  if (res.status === 401 && S.token && !opts.noauth) { signOut('Your session ended. Sign in again.'); throw Object.assign(new Error('signed out'), { signedOut: true }); }
  if (!res.ok) throw Object.assign(new Error((data && data.error) || 'Request failed (' + res.status + ')'), { status: res.status });
  return data;
}
function setToken(t) { S.token = t; try { t ? sessionStorage.setItem('sy_token', t) : sessionStorage.removeItem('sy_token'); } catch (e) { /* ignore */ } }
function signOut(message) { clearTimers(); setToken(null); S.me = null; render(message); }
function clearTimers() { S.timers.forEach((t) => clearInterval(t)); S.timers = []; }
function every(ms, fn) { S.timers.push(setInterval(fn, ms)); }

// ---- time -----------------------------------------------------------------------------------------------
function fmtIn(ts, tz) { return new Date(ts * 1000).toLocaleString('sv-SE', { timeZone: tz }); }
const TZ_SHORT = { 'Asia/Kolkata': 'IST', 'Asia/Calcutta': 'IST' };
function tzName(tz) { if (TZ_SHORT[tz]) return TZ_SHORT[tz]; try { return new Intl.DateTimeFormat('en', { timeZone: tz, timeZoneName: 'short' }).formatToParts(new Date()).find((p) => p.type === 'timeZoneName').value; } catch (e) { return tz; } }
function fullTime(ts) { const tz = S.me.tz; return fmtIn(ts, 'UTC') + ' UTC · ' + fmtIn(ts, tz).slice(11) + ' ' + tzName(tz); }
function rel(ts) {
  const d = Math.max(0, Date.now() / 1000 - ts);
  if (d < 45) return 'just now';
  if (d < 3600) return Math.round(d / 60) + ' min ago';
  if (d < 86400) return Math.round(d / 3600) + ' h ago';
  return Math.round(d / 86400) + ' day' + (Math.round(d / 86400) === 1 ? '' : 's') + ' ago';
}
const timeEl = (ts) => h('span', { class: 'muted', title: fullTime(ts), text: rel(ts) });
function countdown(ts) { const s = Math.max(0, Math.round(ts - Date.now() / 1000)); return String(Math.floor(s / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0'); }

// ---- shared components --------------------------------------------------------------------------------------
const chip = (text, cls) => h('span', { class: 'chip ' + (cls || text), text });
const sev = (s) => chip(s, s);
const roleBadge = (r) => h('span', { class: 'badge ' + r, text: r });
const dot = (state) => h('span', { class: 'dot ' + (state === 'ok' ? '' : state), 'aria-hidden': 'true' });
const person = (p) => h('span', { text: p.name });
function skeleton() { return h('div', { class: 'skeleton', 'aria-busy': 'true', 'aria-label': 'Loading' }, h('i'), h('i'), h('i'), h('i')); }
function empty(title, sub) { return h('div', { class: 'empty' }, icon('check', 32), h('div', { class: 'small', text: title }), h('div', { class: 'small muted', text: sub })); }
function errorBanner(message, retry) {
  return h('div', { class: 'banner', role: 'alert' },
    h('span', { class: 'row' }, icon('alert'), h('span', { text: message })),
    retry && h('button', { class: 'btn', type: 'button', onclick: retry, text: 'Retry now' }));
}
function toast(text, bad) {
  let box = document.querySelector('.toasts');
  if (!box) { box = h('div', { class: 'toasts' }); document.body.appendChild(box); }
  const t = h('div', { class: 'toast' + (bad ? ' bad' : ''), role: bad ? 'alert' : 'status' }, icon(bad ? 'x' : 'check', 16), h('span', { text }),
    h('button', { type: 'button', 'aria-label': 'Dismiss', onclick: () => t.remove(), text: '✕' }));
  box.appendChild(t);
  setTimeout(() => t.remove(), 6000);
}
function copyBtn(value, label) {
  const b = h('button', { class: 'icon-btn', type: 'button', 'aria-label': label || 'Copy' }, icon('copy', 14));
  b.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(value); toast('Copied'); } catch (e) { toast('Copy failed: select the text instead', true); }
  });
  return b;
}
function confirmDialog({ title, body, confirm, danger }) {
  return new Promise((resolve) => {
    const prev = document.activeElement;
    const done = (v) => { back.remove(); document.removeEventListener('keydown', onKey); if (prev && prev.focus) prev.focus(); resolve(v); };
    const onKey = (e) => { if (e.key === 'Escape') done(false); };
    const ok = h('button', { class: 'btn big ' + (danger ? 'danger' : 'primary'), type: 'button', onclick: () => done(true), text: confirm });
    const back = h('div', { class: 'backdrop' }, h('div', { class: 'dialog', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'cf-title' },
      h('h2', { id: 'cf-title', text: title }), h('div', { class: 'col small' }, body),
      h('div', { class: 'row' }, h('button', { class: 'btn big', type: 'button', onclick: () => done(false), text: 'Cancel' }), ok)));
    document.addEventListener('keydown', onKey);
    document.body.appendChild(back);
    ok.focus();
  });
}
function table(head, rows, opts = {}) {
  return h('div', { class: 'tablewrap' }, h('table', null, h('thead', null, h('tr', null, head.map((t) => h('th', { text: t })))), h('tbody', null, rows)));
}
function evChip(e) { return chip(e, e); }

// ---- sign-in -----------------------------------------------------------------------------------------------------
function Gate(message) {
  const card = h('div', { class: 'gate-card' });
  const status = h('div', { class: 'small muted', 'aria-live': 'polite' });
  const area = h('div', { class: 'col' });
  let polling = null;

  async function start() {
    clearInterval(polling);
    let info;
    try { info = await api('/api/login/start', { method: 'POST', body: {}, noauth: true }); }
    catch (e) { status.textContent = e.message; return; }
    const cmd = '@gatekeeper dashboard-login ' + info.code;
    const end = Date.now() + info.expires_in * 1000;
    put(area, 
      h('p', { class: 'small muted', text: 'Type this in any Shipyard room. The Gatekeeper sees who sent it and signs this browser in as them.' }),
      h('div', { class: 'code mono', text: info.code }),
      h('div', { class: 'row' }, h('span', { class: 'mono small', text: cmd }), copyBtn(cmd, 'Copy the command')));
    status.textContent = 'Waiting for you in chat…';
    polling = setInterval(async () => {
      if (Date.now() > end) { clearInterval(polling); status.textContent = 'That code expired.'; return; }
      try {
        const r = await api('/api/login/poll', { method: 'POST', body: { code: info.code, secret: info.secret }, noauth: true });
        if (r.state === 'ok') { clearInterval(polling); setToken(r.token); boot(); }
        else if (r.state === 'expired') { clearInterval(polling); status.textContent = 'That code expired.'; }
      } catch (e) { clearInterval(polling); status.textContent = e.message; }
    }, 2000);
  }

  const tok = h('input', { id: 'tok', class: 'mono', type: 'password', placeholder: 'sy_live_…', autocomplete: 'off', 'aria-invalid': message ? 'true' : null, 'aria-describedby': message ? 'tok-err' : null });
  const form = h('form', { class: 'col', onsubmit: async (e) => {
    e.preventDefault();
    setToken(tok.value.trim());
    try { await boot(true); } catch (err) { setToken(null); status.textContent = ''; tok.setAttribute('aria-invalid', 'true'); err404.textContent = 'That token is wrong or has expired.'; }
  } });
  const err404 = h('p', { id: 'tok-err', class: 'small err', role: 'alert' });
  err404.textContent = message || '';
  form.append(h('div', { class: 'field' }, h('label', { for: 'tok', text: 'Or paste a token' }), tok, err404),
    h('button', { class: 'btn big', type: 'submit', text: 'Open dashboard' }));
  card.append(
    h('div', { class: 'row' }, icon('logo', 28), h('span', { class: 'brand', text: 'Shipyard' })),
    h('div', null, h('h1', { text: 'Sign in to the dashboard' }),
      h('p', { class: 'muted', text: 'Only people with a role on a project can sign in. There is nothing to type a password into: you prove who you are in chat.' })),
    area, h('button', { class: 'btn primary big', type: 'button', onclick: start, text: 'Get a sign-in code' }), status,
    h('hr', { class: 'sr' }), form,
    h('p', { class: 'small muted row' }, icon('lock', 16), h('span', { text: 'The session lives in this tab only. Closing the tab signs you out.' })));
  return h('div', { class: 'gate-page' }, card);
}

// ---- chrome --------------------------------------------------------------------------------------------------------
const NAV = [['overview', 'Overview', 'overview'], ['audit', 'Audit log', 'audit'], ['approvals', 'Approvals', 'approvals'],
  ['sbom', 'SBOM reports', 'sbom'], ['backends', 'Backends', 'backends']];
const OWNER_NAV = [['roles', 'Roles', 'roles'], ['agents', 'Agent access', 'key']];
let chainBadge = null;
function setChain(c) {
  if (!chainBadge) return;
  chainBadge.className = 'verified' + (c.ok ? '' : ' bad');
  put(chainBadge, icon('shield', 14), c.ok ? 'Verified · audit chain intact' : 'Audit chain BROKEN: rows were changed');
}
function Chrome(page, current) {
  const clock = h('span', { class: 'mono small muted' });
  const tick = () => { const n = Date.now() / 1000; clock.textContent = fmtIn(n, 'UTC').slice(11, 16) + ' UTC · ' + fmtIn(n, S.me.tz).slice(11, 16) + ' ' + tzName(S.me.tz); };
  tick(); every(15000, tick);
  chainBadge = h('span', { class: 'verified' }, icon('shield', 14), 'Checking audit chain…');
  const link = ([route, label, ic], tag) => h('a', { href: '#/' + route, 'aria-current': current === route ? 'page' : null },
    icon(ic), label, route === 'approvals' && S.approvals ? h('span', { class: 'count mono', text: S.approvals }) : null, tag ? h('span', { class: 'tag', text: 'owner' }) : null);
  return h('div', { class: 'sy' },
    h('header', { class: 'top' },
      h('div', { class: 'row' }, h('span', { class: 'brand' }, icon('logo', 24), 'Shipyard'), h('span', { class: 'vsep' }), h('span', { class: 'muted', text: 'Project' }),
        mono(S.me.project, 'small'), chainBadge),
      h('div', { class: 'row' }, h('span', { class: 'small' }, person(S.me.identity), ' ', roleBadge(S.me.role)), clock,
        h('button', { class: 'btn', type: 'button', onclick: async () => { try { await api('/api/logout', { method: 'POST', body: {} }); } catch (e) { /* ignore */ } signOut(); }, text: 'Sign out' }))),
    h('div', { class: 'shell' },
      h('nav', { class: 'nav', 'aria-label': 'Main' }, NAV.map((n) => link(n)), h('div', { class: 'grp', text: 'Owner settings' }), OWNER_NAV.map((n) => link(n, true)),
        h('p', { class: 'note', text: 'Pages without the owner tag are read-only. Actions happen in chat.' })),
      h('main', { class: 'main', id: 'main' }, page)));
}

// ---- pages -----------------------------------------------------------------------------------------------------------
function actionText(r) { return r.action + (r.target ? ' · ' + r.target : ''); }
function auditTable(rows, onPick, selected) {
  return table(['Time', 'Who', 'Event', 'Action · target'], rows.map((r) => h('tr', { class: onPick ? 'clickable' + (selected === r.id ? ' sel' : '') : null, tabindex: onPick ? '0' : null,
    onclick: onPick ? () => onPick(r) : null, onkeydown: onPick ? (e) => { if (e.key === 'Enter') onPick(r); } : null },
    h('td', null, timeEl(r.ts)), h('td', { text: r.who.name }), h('td', null, evChip(r.event)),
    h('td', null, h('div', { class: 'mono small', text: actionText(r) }), r.summary && h('div', { class: 'small muted', text: r.summary })))));
}

async function Overview(into) {
  await paintOverview(into);
  every(20000, () => paintOverview(into).catch(() => {}));
}
async function paintOverview(into) {
  const d = await api('/api/overview');
  S.approvals = d.approvals.count; setChain(d.chain);
  const pills = d.health.map((i) => h('a', { class: 'pill' + (i.state === 'warn' || i.state === 'bad' ? ' warn' : ''), href: '#/backends' }, dot(i.state), i.title, h('span', { class: 'muted', text: i.headline })));
  const next = d.approvals.next_expires;
  const tiles = [
    h('a', { class: 'tile', href: '#/approvals' }, h('span', { class: 'small muted', text: 'Pending approvals' }), h('span', { class: 'big', text: d.approvals.count }),
      h('span', { class: 'small muted', text: d.approvals.count ? 'Oldest expires in ' + countdown(next) + ' · approve in ' + d.approvals.room : 'Nothing waiting' })),
  ];
  if (d.sbom_enabled) {
    tiles.push(h('a', { class: 'tile' + (d.gate.blocked ? ' crit' : ''), href: '#/approvals' }, h('span', { class: 'small', text: 'Deploys blocked by SBOM gate' }), h('span', { class: 'big', text: d.gate.blocked }),
      h('span', { class: 'small', text: d.gate.blocked ? d.gate.items.map((i) => i.target + ' · ' + i.cves.join(', ')).join(' | ') + ' · owner override required' : 'No deploy is waiting on the gate' })));
    const rel_ = d.release;
    tiles.push(h('a', { class: 'tile', href: rel_ ? '#/sbom/' + rel_.commit : '#/sbom' }, h('span', { class: 'small muted', text: 'Latest release' }),
      rel_ ? [h('span', { class: 'mono', text: rel_.label }), h('span', { class: 'row' }, chip(rel_.counts.critical + ' critical', rel_.counts.critical ? 'critical' : 'low'), chip(rel_.counts.high + ' high', 'high'))]
           : h('span', { class: 'small muted', text: 'No release recorded yet' })));
  }
  put(into, 
    h('div', { class: 'row between' }, h('div', null, h('h1', { text: 'Overview' }),
      h('p', { class: 'muted', text: [d.apps.join(', '), d.repo && 'repo ' + d.repo, d.rooms.length && 'rooms ' + d.rooms.join(', ')].filter(Boolean).join(' · ') }))),
    h('section', { 'aria-label': 'Backend health', class: 'pills' }, pills),
    h('section', { 'aria-label': 'Needs attention', class: 'tiles' }, tiles),
    h('section', { class: 'col' }, h('div', { class: 'row between' }, h('h2', { text: 'Recent activity' }), h('a', { href: '#/audit', text: 'Full audit log' })),
      d.recent.length ? auditTable(d.recent) : empty('Nothing has happened yet', 'Commands, approvals and results appear here.')));
}

async function Audit(into) {
  const f = { q: '', event: '', actor: '', action: '' };
  let rows = [], more = false, facets = { events: [], actions: [], actors: [] }, picked = null;
  const list = h('div'), aside = h('aside', { 'aria-label': 'Row detail', class: 'card col' });
  const q = h('input', { id: 'q', type: 'search', placeholder: 'Target, detail or id', 'aria-label': 'Search' });
  const sel = (id, label, key, all) => { const s = h('select', { id, 'aria-label': label, onchange: () => { f[key] = s.value; load(true); } }, h('option', { value: '', text: all })); return s; };
  const fe = sel('fe', 'Event', 'event', 'All events'), fp = sel('fp', 'Person', 'actor', 'Everyone'), fa = sel('fa', 'Action', 'action', 'All actions');
  const head = h('div', { class: 'row between' }, h('div', null, h('h1', { text: 'Audit log' }), h('p', { class: 'muted', text: 'Every request, approval and result, newest first. Rows are chained by hash, so an edited row breaks the chain.' })));
  const chainBox = h('div', { class: 'card small' });
  head.appendChild(chainBox);
  const form = h('form', { role: 'search', class: 'row', onsubmit: (e) => { e.preventDefault(); f.q = q.value; load(true); } },
    h('div', { class: 'field' }, h('label', { for: 'q', text: 'Search' }), q), h('div', { class: 'field' }, h('label', { for: 'fe', text: 'Event' }), fe),
    h('div', { class: 'field' }, h('label', { for: 'fp', text: 'Person' }), fp), h('div', { class: 'field' }, h('label', { for: 'fa', text: 'Action' }), fa),
    h('button', { class: 'btn', type: 'button', onclick: () => { Object.keys(f).forEach((k) => { f[k] = ''; }); q.value = ''; fe.value = fp.value = fa.value = ''; load(true); }, text: 'Clear' }));
  function fill(s, vals, label) { const cur = s.value; put(s, h('option', { value: '', text: label }), ...vals.map((v) => h('option', { value: v.value, text: v.text }))); s.value = cur; }
  function detail() {
    if (!picked) { put(aside, h('h2', { text: 'Row detail' }), h('p', { class: 'small muted', text: 'Pick a row to see everything recorded about it.' })); return; }
    const r = picked;
    put(aside, h('div', { class: 'row between' }, h('h2', { text: 'Row detail' }), h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Close detail', onclick: () => { picked = null; draw(); } }, icon('x', 14))),
      h('dl', { class: 'dl small' }, h('dt', { text: 'Id' }), h('dd', null, mono('evt_' + r.id), ' ', copyBtn('evt_' + r.id, 'Copy id')), h('dt', { text: 'Time' }), h('dd', { text: fullTime(r.ts) }),
        h('dt', { text: 'Who' }), h('dd', { text: r.who.name + (r.who.platform ? ' · ' + r.who.platform : '') + (r.who.role ? ' · ' + r.who.role : '') }),
        h('dt', { text: 'Row hash' }), h('dd', null, mono(r.hash, 'small'))),
      h('div', { class: 'small muted', text: 'Raw detail (shown as text)' }), h('pre', { text: JSON.stringify(r.detail, null, 2) }));
  }
  function draw() {
    put(list, rows.length ? auditTable(rows, (r) => { picked = r; draw(); }, picked && picked.id) : empty('No matching rows', 'Change the filters.'),
      h('div', { class: 'row between' }, h('span', { class: 'small muted', text: 'Showing ' + rows.length }), more && h('button', { class: 'btn', type: 'button', onclick: () => load(false), text: 'Load more' })));
    detail();
  }
  async function load(reset) {
    const p = new URLSearchParams({ limit: 50 });
    Object.entries(f).forEach(([k, v]) => v && p.set(k, v));
    if (!reset && rows.length) p.set('before', rows[rows.length - 1].id);
    const d = await api('/api/audit?' + p);
    rows = reset ? d.rows : rows.concat(d.rows); more = d.more; setChain(d.chain);
    put(chainBox, h('div', { class: 'small', text: d.chain.ok ? 'Hash chain verified' : 'Hash chain BROKEN' }), h('div', { class: 'small muted' }, d.chain.rows + ' rows · head ', mono(d.chain.head)));
    fill(fe, d.facets.events.map((v) => ({ value: v, text: v })), 'All events'); fill(fa, d.facets.actions.map((v) => ({ value: v, text: v })), 'All actions');
    fill(fp, d.facets.actors.map((a) => ({ value: a.id, text: a.name })), 'Everyone');
    draw();
  }
  put(into, head, form, h('div', { class: 'split aside' }, list, aside));
  await load(true);
}

function describe(a) {
  const verb = a.action.split('.').slice(1).join('.');
  const extra = a.args.tag ? ' ' + a.args.tag : a.args.replicas !== undefined ? ' ' + a.args.replicas : a.args.argv ? ': ' + a.args.argv.join(' ') : '';
  return verb + ' ' + (verb === 'merge' ? 'PR #' : '') + a.target + extra;
}
const BACKEND = { coolify: 'Coolify', k8s: 'Kubernetes', repo: 'GitHub', ops: 'Shell' };
async function Approvals(into) {
  await paintApprovals(into);
  every(1000, () => into.querySelectorAll('[data-exp]').forEach((e) => { e.textContent = countdown(Number(e.dataset.exp)); }));
  every(10000, () => paintApprovals(into).catch(() => {}));
}
async function paintApprovals(into) {
  const d = await api('/api/approvals');
  S.approvals = d.approvals.length;
  const cards = d.approvals.map((a) => {
    const t = h('span', { class: 'mono small', text: countdown(a.expires) });
    t.dataset.exp = a.expires;
    return h('article', { class: 'approval' },
      a.gate.length ? h('div', { class: 'gate', role: 'alert' }, icon('alert'), 'Blocked by SBOM gate · owner override required', h('span', { class: 'mono small', text: a.gate.join(', ') })) : null,
      h('div', { class: 'body' },
        h('div', { class: 'col' }, h('div', { class: 'row' }, chip(a.id, 'none'), h('strong', { class: 'mono', text: describe(a) })),
          h('div', { class: 'small muted row' }, h('span', { text: 'Requested by ' + a.requester.name + (a.requester.role ? ' (' + a.requester.role + ')' : '') + ' · ' + (BACKEND[a.action.split('.')[0]] || '') + (a.tier ? ' · ' + a.tier + ' tier' : '') + (a.kind === 'agent_proposal' ? ' · proposed by an agent' : '') }),
            a.report ? h('a', { href: '#/sbom/' + a.report, text: 'SBOM report' }) : null)),
        h('div', { class: 'col' }, h('span', { class: 'chip ' + (a.gate.length ? 'overridden' : 'approval_requested'), text: a.needs === 'owner' ? 'Waiting for owner' : a.needs === 'a second person' ? 'Needs a second person' : 'Needs approval' }), t)));
  });
  put(into, 
    h('div', null, h('h1', { text: 'Approvals' }), h('p', { class: 'muted', text: d.approvals.length + ' pending · requests expire after ' + d.timeout_minutes + ' minutes' })),
    h('div', { class: 'note', role: 'note' }, icon('shield'), h('p', null, 'Approve or deny in chat, not here. Reply to the Gatekeeper’s message in ', mono(d.room || 'the ops room'), ' with ', mono('@gatekeeper approve <id>'), ' or ', mono('@gatekeeper deny <id>'),
      '. The Gatekeeper checks who replied, so this page has no buttons.')),
    cards.length ? h('div', { class: 'col' }, cards) : empty('No pending approvals', 'Requests appear here when someone asks for a dangerous action in chat.'),
    h('p', { class: 'small muted' }, 'Expired and resolved requests move to the ', h('a', { href: '#/audit', text: 'audit log' }), '.'));
}

const DECISIONS = [['', 'All'], ['clear', 'clear'], ['blocked', 'blocked'], ['overridden', 'overridden'], ['unverified', 'unverified'], ['no_sbom', 'no SBOM']];
async function SbomList(into) {
  let want = '', rows = [], more = false;
  const filters = h('div', { class: 'row', role: 'group', 'aria-label': 'Decision filter' });
  const body = h('div', { class: 'col' });
  const draw = () => {
    put(filters, h('span', { class: 'small muted', text: 'Decision:' }), ...DECISIONS.map(([v, l]) => h('button', { class: 'btn' + (want === v ? ' primary' : ''), type: 'button', 'aria-pressed': String(want === v), onclick: () => { want = v; load(true); }, text: l })));
    put(body, rows.length ? table(['Release / commit', 'PR', 'Time', 'Packages', 'Critical · High · Medium · Low', 'Decision', 'Deployed'], rows.map((r) => h('tr', null,
      h('td', null, h('a', { href: '#/sbom/' + r.commit, text: r.ref || r.commit.slice(0, 7) }), h('div', { class: 'mono small muted', text: r.commit.slice(0, 7) })),
      h('td', { text: r.pr ? '#' + r.pr : '—' }), h('td', null, timeEl(r.created)), h('td', { text: r.packages || '—' }),
      h('td', null, h('span', { class: 'row' }, chip(r.critical, r.critical ? 'critical' : 'low'), chip(r.high, 'high'), chip(r.medium, 'medium'), chip(r.low, 'low'))),
      h('td', null, chip(r.decision === 'no_sbom' ? 'no SBOM' : r.decision, r.decision)), h('td', null, r.live ? chip('Live', 'live') : r.deployed ? 'Earlier' : 'No')))) : empty('No SBOM reports yet', 'CI produces one for every pull request and every push to the default branch.'),
      more && h('div', null, h('button', { class: 'btn', type: 'button', onclick: () => load(false), text: 'Load more' })));
  };
  async function load(reset) {
    const p = new URLSearchParams({ offset: reset ? 0 : rows.length }); if (want) p.set('decision', want);
    const d = await api('/api/sbom?' + p); rows = reset ? d.rows : rows.concat(d.rows); more = d.more; draw();
  }
  put(into, h('div', null, h('h1', { text: 'SBOM reports' }), h('p', { class: 'muted', text: 'Collected from each CI run. Severities come from the scanner’s report as CI produced it; Shipyard adds only the diff and the deploy decision.' })), filters, body);
  await load(true);
}

async function download(commit, kind) {
  try {
    const res = await api('/api/sbom/' + commit + '/file/' + kind, { raw: true });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    if (kind === 'html') { window.open(url, '_blank', 'noopener'); setTimeout(() => URL.revokeObjectURL(url), 60000); return; }
    const a = h('a', { href: url, download: 'sbom-' + commit.slice(0, 7) + '-' + kind + '.json' }); document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 5000);
  } catch (e) { toast(e.message, true); }
}
const FILE_LABEL = { spdx: 'SPDX', cyclonedx: 'CycloneDX', scan: 'Scan JSON', html: 'HTML report' };
async function SbomDetail(into, commit) {
  const d = await api('/api/sbom/' + commit);
  const c = d.counts, title = d.ref || d.commit.slice(0, 7);
  const msg = d.decision === 'blocked' ? 'Deploy blocked: ' + d.why.join('; ') + '.' + (d.pending_approval ? ' Request ' + d.pending_approval + ' is waiting for an owner.' : ' An owner can override in chat.')
    : d.decision === 'unverified' ? 'Deploy blocked: ' + d.why.join('; ') + '.' : d.decision === 'no_sbom' ? 'Deploy blocked: ' + d.why.join('; ') + '.'
    : d.decision === 'overridden' ? 'An owner overrode the block for this commit. See the audit log.' : 'Clear to deploy: no new critical vulnerability since the last release.';
  const diffRows = [...d.diff.added.map(([k, v]) => ['add', '+', 'added', k, v]), ...d.diff.removed.map(([k, v]) => ['rem', '−', 'removed', k, v]), ...d.diff.upgraded.map(([k, a, b]) => ['up', '↑', 'upgraded', k, a + ' → ' + b])];
  let showAll = false;
  const diffBox = h('div');
  const drawDiff = () => put(diffBox, diffRows.length ? h('div', { class: 'diff' }, (showAll ? diffRows : diffRows.slice(0, 8)).map(([cls, sym, label, k, v]) => h('div', { class: cls }, h('span', { 'aria-label': label, text: sym }), h('span', { text: k }), h('span', { text: v })))) : h('p', { class: 'small muted', text: d.baseline ? 'No package changes.' : 'No earlier release to compare with.' }),
    diffRows.length > 8 && h('button', { class: 'btn', type: 'button', onclick: () => { showAll = !showAll; drawDiff(); }, text: showAll ? 'Show fewer' : 'Show all ' + d.diff.total + ' changes' }));
  drawDiff();
  const cve = d.findings.map((f) => h('tr', null, h('td', null, h('span', { class: 'row' }, safeUrl(f.url) ? h('a', { href: f.url, target: '_blank', rel: 'noopener noreferrer', text: f.id }) : mono(f.id), f.new ? chip('new', 'new') : null)),
    h('td', null, sev(f.severity)), h('td', { class: 'mono small', text: f.key }), h('td', { class: 'mono small', text: f.version }), h('td', { class: 'mono small', text: f.fixed.length ? f.fixed.join(', ') : 'not fixed yet' })));
  const stat = (l, v, crit) => h('div', { class: 'stat' + (crit ? ' crit' : '') }, h('span', { class: 'small muted', text: l }), h('b', { text: v }));
  put(into, 
    h('a', { href: '#/sbom', text: '← All SBOM reports' }),
    h('section', { class: 'col' }, h('div', { class: 'row' }, h('h1', { text: title }), chip(d.decision === 'no_sbom' ? 'no SBOM' : d.decision, d.decision)), h('p', { text: msg }),
      h('p', { class: 'small muted row' }, d.pr ? 'PR #' + d.pr : null, ' commit ', mono(d.commit.slice(0, 7)), copyBtn(d.commit, 'Copy commit'), ' collected ', timeEl(d.collected_at), ' · ' + d.format + ', ' + d.package_count + ' packages')),
    h('section', { class: 'stats', 'aria-label': 'Summary' }, stat('Packages', d.package_count), stat('Added', '+' + d.diff.added.length), stat('Removed', '−' + d.diff.removed.length), stat('Upgraded', d.diff.upgraded.length),
      stat('Critical', c.critical, c.critical), stat('High', c.high), stat('Medium', c.medium), stat('Low', c.low)),
    h('div', { class: 'split two' },
      h('section', { class: 'col', 'aria-labelledby': 'diff' }, h('div', { class: 'row between' }, h('h2', { id: 'diff', text: d.baseline ? 'Changes since ' + d.baseline.slice(0, 7) : 'Changes' }), h('span', { class: 'small muted', text: d.diff.total + (d.diff.total === 1 ? ' package changed' : ' packages changed') })), diffBox),
      h('div', { class: 'col' },
        h('section', { class: 'card col', 'aria-labelledby': 'trust' }, h('h2', { id: 'trust', text: 'Where this came from' }),
          d.trust.ok ? null : h('div', { class: 'banner', role: 'alert' }, h('span', null, h('strong', { text: 'Unverified. ' }), d.trust.reasons.join('; ') + '.')),
          h('dl', { class: 'dl small' }, h('dt', { text: 'Run' }), h('dd', null, safeUrl(d.links.run) ? h('a', { href: d.links.run, target: '_blank', rel: 'noopener noreferrer', text: '#' + d.run_id }) : '—'),
            h('dt', { text: 'Commit' }), h('dd', null, safeUrl(d.links.commit) ? h('a', { href: d.links.commit, target: '_blank', rel: 'noopener noreferrer', text: d.commit.slice(0, 7) }) : mono(d.commit.slice(0, 7))),
            h('dt', { text: 'Workflow' }), h('dd', { class: 'mono', text: d.workflow }), h('dt', { text: 'Tools' }), h('dd', { text: 'Syft (SBOM), Grype (scan), run in CI' }))),
        h('section', { class: 'card col', 'aria-labelledby': 'dl' }, h('h2', { id: 'dl', text: 'Downloads' }),
          h('div', { class: 'row' }, d.files.map((k) => h('button', { class: 'btn', type: 'button', onclick: () => download(d.commit, k), text: FILE_LABEL[k] || k })))))),
    h('section', { class: 'col', 'aria-labelledby': 'cves' }, h('h2', { id: 'cves', text: 'Vulnerabilities (from the CI scan report)' }),
      cve.length ? table(['Id', 'Severity', 'Package', 'Installed', 'Fixed in'], cve) : empty('No vulnerabilities reported', 'The scan found nothing.'),
      d.findings_total > d.findings.length ? h('p', { class: 'small muted', text: 'Showing ' + d.findings.length + ' of ' + d.findings_total + '. Download the scan JSON for all.' }) : null));
}

async function Backends(into) {
  const draw = (d) => put(into, 
    h('div', { class: 'row between' }, h('div', null, h('h1', { text: 'Backends' }), h('p', { class: 'muted', text: d.healthy + ' healthy · ' + d.attention + ' need attention · checked every 60 s' })),
      h('button', { class: 'btn', type: 'button', onclick: async (e) => { e.target.disabled = true; try { draw(await api('/api/backends/refresh', { method: 'POST', body: {} })); } catch (err) { toast(err.message, true); } }, text: 'Refresh all' })),
    d.items.length ? h('div', { class: 'agentgrid' }, d.items.map((i) => h('article', { class: 'card col' },
      h('div', { class: 'row between' }, h('h2', { text: i.title }), h('span', { class: 'row small' }, dot(i.state), i.headline)), h('p', { class: 'small muted', text: i.detail }),
      h('div', { class: 'row between' }, h('span', { class: 'small muted', title: fullTime(i.checked), text: 'Checked ' + rel(i.checked) }),
        h('button', { class: 'btn', type: 'button', onclick: async () => { try { draw(await api('/api/backends/refresh', { method: 'POST', body: { key: i.key } })); } catch (err) { toast(err.message, true); } }, text: 'Refresh' }))))) : empty('Nothing configured', 'No backend is set up for this project.'));
  draw(await api('/api/backends'));
  every(30000, async () => { try { draw(await api('/api/backends')); } catch (e) { /* keep the last view */ } });
}

async function Roles(into) {
  const d = await api('/api/roles');
  const pending = new Map();   // identity -> role or null (remove)
  const added = [];
  const bar = h('div'), tbl = h('div');
  const ident = h('input', { id: 'ident', placeholder: '@switch-discord-…:localhost', 'aria-describedby': 'ident-help', class: 'mono' });
  const nrole = h('select', { id: 'nrole' }, d.roles.map((r) => h('option', { value: r, text: r })));
  const count = () => pending.size + added.length;
  const draw = () => {
    put(bar, count() ? h('div', { class: 'unsaved', role: 'status' }, h('span', { text: count() + ' unsaved change' + (count() === 1 ? '' : 's') }),
      h('div', { class: 'row' }, h('button', { class: 'btn', type: 'button', onclick: () => { pending.clear(); added.length = 0; draw(); }, text: 'Cancel' }),
        h('button', { class: 'btn primary', type: 'button', onclick: save, text: 'Save' }))) : null);
    const rows = d.members.map((m) => {
      const cur = pending.has(m.id) ? pending.get(m.id) : m.role, removed = pending.get(m.id) === null;
      const sel = h('select', { id: 'r-' + m.id, 'aria-label': 'Role for ' + m.name, disabled: !d.editable || m.last_owner || removed, onchange: (e) => { if (e.target.value === m.role) pending.delete(m.id); else pending.set(m.id, e.target.value); draw(); } }, d.roles.slice().reverse().map((r) => h('option', { value: r, text: r, selected: r === cur })));
      return h('tr', null, h('td', null, h('div', { text: m.name }), h('div', { class: 'mono tiny muted', text: m.id })), h('td', { text: m.platform }),
        h('td', null, h('div', { class: 'row' }, sel, pending.has(m.id) && !removed ? h('span', { class: 'small muted', text: 'was ' + m.role }) : removed ? h('span', { class: 'small', text: 'will be removed' }) : null)),
        h('td', null, d.editable ? h('button', { class: 'btn danger', type: 'button', disabled: m.last_owner || null, 'aria-describedby': m.last_owner ? 'last-owner' : null, onclick: () => { if (removed) pending.delete(m.id); else pending.set(m.id, null); draw(); }, text: removed ? 'Undo' : 'Remove' }) : null,
          m.last_owner ? h('div', { id: 'last-owner', class: 'tiny muted', text: 'You can’t remove the last owner' }) : null));
    });
    for (const a of added) rows.push(h('tr', null, h('td', null, h('div', { text: 'New member' }), h('div', { class: 'mono tiny muted', text: a.identity })), h('td', { text: '' }), h('td', { text: a.role + ' (new)' }), h('td', null, h('button', { class: 'btn', type: 'button', onclick: () => { added.splice(added.indexOf(a), 1); draw(); }, text: 'Undo' }))));
    put(tbl, table(['Account', 'Platform', 'Role', 'Remove'], rows));
  };
  async function save() {
    const changes = [...[...pending].map(([identity, role]) => ({ identity, role })), ...added];
    const names = new Map(d.members.map((m) => [m.id, m]));
    const lines = changes.map((c) => { const m = names.get(c.identity); return (m ? m.name : c.identity) + ': ' + (m ? m.role : 'new') + ' → ' + (c.role === null ? 'removed' : c.role); });
    const promote = changes.some((c) => c.role === 'owner' || c.role === 'maintainer');
    if (!(await confirmDialog({ title: changes.length === 1 ? 'Change roles?' : 'Change ' + changes.length + ' roles?', confirm: 'Save changes', body: [lines.map((l) => h('div', { class: 'mono small', text: l })), h('p', { text: (promote ? 'Maintainers and owners can merge PRs and approve dangerous actions. ' : '') + 'This is written to the audit log.' })] }))) return;
    try { const r = await api('/api/roles', { method: 'POST', body: { changes } }); toast('Roles saved. ' + r.audited + ' change' + (r.audited === 1 ? '' : 's') + ' written to the audit log.'); Roles(into); } catch (e) { toast(e.message, true); }
  }
  const form = d.editable ? h('form', { class: 'card col', onsubmit: (e) => { e.preventDefault(); const v = ident.value.trim(); if (!v) return; added.push({ identity: v, role: nrole.value }); ident.value = ''; draw(); } },
    h('h2', { text: 'Add a member' }), h('div', { class: 'row' }, h('div', { class: 'field' }, h('label', { for: 'ident', text: 'Chat identity' }), ident), h('div', { class: 'field' }, h('label', { for: 'nrole', text: 'Role' }), nrole), h('button', { class: 'btn big primary', type: 'submit', text: 'Add member' })),
    h('p', { id: 'ident-help', class: 'small muted' }, 'The person types ', mono('@gatekeeper whoami'), ' in any Shipyard room. The Gatekeeper replies with their exact identity; paste it here. Names alone are not accepted.')) : null;
  put(into, h('div', null, h('h1', { text: 'Roles' }), h('p', { class: 'muted' }, 'Who can do what in project ', mono(d.project), d.editable ? '. Owners edit; everyone else sees this page read-only.' : '. Only owners can edit; this page is read-only for you.')), bar, tbl, form);
  draw();
}

async function Agents(into) {
  const d = await api('/api/agents');
  const preview = h('div');
  async function sync() {
    try {
      const p = await api('/api/agents/preview', { method: 'POST', body: {} });
      if (!p.changes.length) { put(preview, h('div', { class: 'note' }, icon('check'), 'Already in sync: Switch matches the roles.')); return; }
      put(preview, h('section', { class: 'card col', 'aria-labelledby': 'pv' }, h('div', { class: 'row between' }, h('h2', { id: 'pv', text: 'Preview: ' + p.changes.length + ' change' + (p.changes.length === 1 ? '' : 's') + ' from current roles' }),
        h('div', { class: 'row' }, h('button', { class: 'btn', type: 'button', onclick: () => put(preview), text: 'Cancel' }), h('button', { class: 'btn primary', type: 'button', onclick: apply, text: 'Apply to Switch' }))),
        h('div', { class: 'diff' }, p.changes.map((c) => h('div', { class: c.op === '+' ? 'add' : c.op === '-' ? 'rem' : 'up' }, h('span', { text: c.op === '-' ? '−' : c.op }), h('span', { text: c.agent }), h('span', { class: 'small', text: c.text }))))));
    } catch (e) { toast(e.message, true); }
  }
  async function apply() {
    try { const r = await api('/api/agents/sync', { method: 'POST', body: {} }); toast('Switch updated for ' + r.agents.join(', ') + '.'); Agents(into); } catch (e) { toast('Sync failed: ' + e.message, true); }
  }
  put(into, 
    h('div', { class: 'row between' }, h('div', null, h('h1', { text: 'Agent access' }), h('p', { class: 'muted', text: 'Who may talk to each agent, and where. Stored in Switch as each agent’s addressing policy.' })),
      d.editable ? h('button', { class: 'btn primary big', type: 'button', onclick: sync, text: 'Sync from roles' }) : null), preview,
    d.unresolved.length ? h('div', { class: 'note' }, icon('alert'), h('p', { text: d.unresolved.map((u) => u.name).join(', ') + ' cannot be admitted yet: Switch has no record of them until they post in a bridged room.' })) : null,
    h('div', { class: 'agentgrid' }, d.agents.map((a) => h('article', { class: 'card col' }, h('div', { class: 'row between' }, h('h2', { text: a.name }), h('span', { class: 'chip ' + (a.status === 'registered' ? 'allowed' : a.status === 'system' ? 'none' : 'approval_requested'), text: a.status })),
      a.may_address === null ? h('p', { class: 'small', text: 'Every project member may use it for whoami, approve, deny and the other Gatekeeper commands.' }) : [
        h('div', null, h('div', { class: 'small muted', text: 'May address it' }), h('div', { class: 'people' }, a.may_address.length ? a.may_address.map((p) => h('span', { class: 'person', text: p.name + ' · ' + p.role })) : h('span', { class: 'small muted', text: 'only the Switch owner' }))),
        h('div', null, h('div', { class: 'small muted', text: 'In rooms' }), h('div', { class: 'small', text: a.rooms.join(' · ') || 'none' })),
        h('div', { class: 'small muted', title: a.last_synced ? fullTime(a.last_synced) : '', text: a.last_synced ? 'Last synced ' + rel(a.last_synced) : 'Not synced from the dashboard yet' })]))));
}

// ---- router -------------------------------------------------------------------------------------------------------
const PAGES = { overview: Overview, audit: Audit, approvals: Approvals, sbom: SbomList, backends: Backends, roles: Roles, agents: Agents };
async function route() {
  if (!S.me) return;
  clearTimers();
  const [, name = 'overview', arg] = location.hash.split('/');
  const key = PAGES[name] ? name : 'overview';
  const into = h('div', { class: 'col' }, skeleton());
  put(root, Chrome(into, name === 'sbom' && arg ? 'sbom' : key));
  const m = document.getElementById('main'); put(m, into);
  try {
    if (name === 'sbom' && arg && /^[0-9a-f]{7,40}$/.test(arg)) await SbomDetail(into, arg); else await PAGES[key](into);
    if (key !== 'overview' && key !== 'audit') api('/api/overview').then((o) => { S.approvals = o.approvals.count; setChain(o.chain); }).catch(() => {});
  } catch (e) {
    if (e.signedOut) return;
    put(into, errorBanner(e.status === 404 ? 'That page does not exist.' : e.message, e.offline ? () => route() : null));
  }
}
async function boot(strict) {
  try { S.me = await api('/api/me', { noauth: !!strict }); } catch (e) { S.me = null; if (strict) throw e; render(); return; }
  location.hash = location.hash && location.hash !== '#' ? location.hash : '#/overview';
  route();
}
function render(message) { if (S.me) route(); else put(root, Gate(message)); }
window.addEventListener('hashchange', route);
if (S.token) boot(); else render();
})();
