const {api, Auth, esc, get, decodeJwt, theme} = IAM;
const $ = id => document.getElementById(id), view = $('view');
if (!Auth.token()) location.replace('../login/');

let me = {perms: [], roles: [], email: ''};
const can = p => !p || me.perms.includes(p);
const toast = (t, err) => { const d = document.createElement('div'); d.className = 'toast' + (err ? ' err' : ''); d.textContent = t; $('toasts').append(d); setTimeout(() => d.remove(), 3500); };
const fail = e => { if (e.status === 401) { Auth.clear(); location.replace('../login/'); } else toast(e.message, true); };
const ago = d => { if (!d) return '—'; const s = (Date.now() - new Date(d)) / 1000; if (isNaN(s)) return '—'; for (const [n, u] of [[86400, 'd'], [3600, 'h'], [60, 'm']]) if (s >= n) return Math.floor(s / n) + u + ' ago'; return 'just now'; };
const fmt = n => n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e3 ? (n / 1e3).toFixed(1) + 'k' : String(Math.round(n));
const stat = (k, v, s = '') => `<div class="card stat"><div class="k">${k}</div><div class="v">${v}</div><div class="s">${s}</div></div>`;
const secHead = (t, extra = '') => `<div class="sec"><h2>${t}</h2><div class="grow"></div>${extra}</div>`;

function modal(title, html, onSubmit, okLabel = 'Save') {
  const d = $('dlg');
  d.innerHTML = `<form method="dialog"><h3>${title}</h3><div class="alert err" id="mErr"></div>${html}<div class="actions"><button type="button" class="btn" id="mX">Cancel</button><button class="btn primary" id="mOk">${okLabel}</button></div></form>`;
  d.showModal();
  $('mX').onclick = () => d.close();
  d.querySelector('form').onsubmit = async e => {
    e.preventDefault(); $('mOk').disabled = true;
    try { await onSubmit(new FormData(e.target)); d.close(); }
    catch (err) { $('mErr').textContent = err.message; $('mErr').classList.add('show'); }
    finally { if ($('mOk')) $('mOk').disabled = false; }
  };
}

/* ---------- Pages ---------- */
const pages = {};

pages.overview = {title: 'Overview', icon: '▦', group: 'Product', aud: 'both', async render() {
  const [users, roles, pol, metrics] = await Promise.all([
    can('users:read') ? api('/users').catch(() => null) : null,
    can('roles:read') ? api('/roles').catch(() => null) : null,
    api('/tenant/policy').catch(() => null),
    api('/metrics', {auth: false, raw: true}).catch(() => null)]);
  const m = metrics ? parseMetrics(metrics) : null;
  const active = users ? users.filter(u => (get(u, 'status', 'Status') || '').toLowerCase() === 'active').length : null;
  let h = `<div class="grid g4">
    ${stat('Users', users ? users.length : '—', active != null ? active + ' active' : 'needs users:read')}
    ${stat('Roles', roles ? roles.length : '—', 'RBAC roles in tenant')}
    ${stat('MFA enforcement', pol ? (pol.require_mfa ? 'Required' : 'Optional') : '—', pol ? `Max ${pol.max_active_sessions || '∞'} sessions / user` : '')}
    ${stat('Password policy', pol ? pol.password_min_length + '+ chars' : '—', pol ? [pol.password_require_upper && 'upper', pol.password_require_digit && 'digit', pol.password_require_symbol && 'symbol'].filter(Boolean).join(' · ') || 'length only' : '')}
  </div>`;
  if (m) {
    const errRate = m.total ? (m.errors / m.total * 100) : 0, avg = m.count ? m.sum / m.count * 1000 : 0;
    const hit = m.hits + m.misses ? m.hits / (m.hits + m.misses) * 100 : null;
    h += secHead('Platform health <span class="audience badge accent">technical</span>') + `<div class="grid g4">
      ${stat('HTTP requests', fmt(m.total), 'since server start')}
      ${stat('5xx error rate', errRate.toFixed(2) + '%', fmt(m.errors) + ' server errors')}
      ${stat('Avg latency', avg.toFixed(1) + ' ms', 'mean across all routes')}
      ${stat('Principal cache hit', hit == null ? '—' : hit.toFixed(0) + '%', 'Redis session cache')}</div>
    <div class="grid g2" style="margin-top:16px">
      <div class="card"><h3 style="font-size:14px;margin-bottom:14px">Busiest routes</h3>${bars(m.routes.slice(0, 7))}</div>
      <div class="card"><h3 style="font-size:14px;margin-bottom:14px">Auth events <span class="audience badge">product</span></h3>${m.events.length ? bars(m.events) : '<div class="empty">No auth events recorded yet.</div>'}</div></div>`;
  } else h += `<div class="card empty" style="margin-top:16px">Metrics unavailable — is <code>/metrics</code> reachable?</div>`;
  return h;
}};
function bars(rows) {
  if (!rows.length) return '<div class="empty">No data yet.</div>';
  const max = Math.max(...rows.map(r => r[1]));
  return rows.map(([k, v]) => `<div style="margin-bottom:12px"><div class="row" style="justify-content:space-between"><code>${esc(k)}</code><b>${fmt(v)}</b></div><div class="bar"><i style="width:${Math.max(3, v / max * 100)}%"></i></div></div>`).join('');
}
function parseMetrics(t) {
  const o = {total: 0, errors: 0, sum: 0, count: 0, hits: 0, misses: 0, routes: {}, events: {}};
  for (const line of t.split('\n')) {
    if (!line || line[0] === '#') continue;
    const mt = line.match(/^(\w+)(?:\{(.*)\})?\s+([\d.eE+-]+|NaN)$/); if (!mt) continue;
    const [, name, lb = '', val] = mt, v = parseFloat(val), L = Object.fromEntries([...lb.matchAll(/(\w+)="([^"]*)"/g)].map(x => [x[1], x[2]]));
    if (name === 'auth_http_requests_total') { o.total += v; if (L.status >= 500) o.errors += v; o.routes[L.route] = (o.routes[L.route] || 0) + v; }
    else if (name === 'auth_http_request_duration_seconds_sum') o.sum += v;
    else if (name === 'auth_http_request_duration_seconds_count') o.count += v;
    else if (name === 'auth_events_total') o.events[L.event] = (o.events[L.event] || 0) + v;
    else if (name === 'auth_principal_cache_hits_total') o.hits = v;
    else if (name === 'auth_principal_cache_misses_total') o.misses = v;
  }
  const sort = x => Object.entries(x).sort((a, b) => b[1] - a[1]);
  o.routes = sort(o.routes); o.events = sort(o.events); return o;
}

pages.users = {title: 'Users', icon: '☺', group: 'Product', perm: 'users:read', async render() {
  const users = await api('/users'); window._users = users;
  const row = u => { const id = get(u, 'id', 'ID'), name = get(u, 'display_name', 'DisplayName') || get(u, 'username', 'Username') || '—', st = get(u, 'status', 'Status') || 'unknown';
    return `<tr data-q="${esc((name + ' ' + (get(u, 'username', 'Username') || '')).toLowerCase())}"><td><div class="row"><div class="avatar" style="width:30px;height:30px;font-size:12px">${esc(name[0] || '?').toUpperCase()}</div><div><b>${esc(name)}</b><div class="hint">${esc(get(u, 'username', 'Username') || '')}</div></div></div></td>
      <td><span class="badge ${st === 'active' ? 'ok' : 'warn'}">${esc(st)}</span></td><td class="hint">${ago(get(u, 'created_at', 'CreatedAt'))}</td><td><code class="hint">${esc(String(id).slice(0, 8))}…</code></td></tr>`; };
  return `<div class="row"><input class="search" id="q" placeholder="Search users…"><div class="grow"></div>${can('users:create') ? '<button class="btn primary" id="newUser">+ New user</button>' : ''}</div>
    <div class="card tcard" style="margin-top:16px"><table class="tbl"><thead><tr><th>User</th><th>Status</th><th>Joined</th><th>ID</th></tr></thead><tbody id="ub">${users.map(row).join('') || '<tr><td colspan=4 class="empty">No users yet.</td></tr>'}</tbody></table></div>`;
}, mount() {
  $('q').oninput = e => document.querySelectorAll('#ub tr[data-q]').forEach(r => r.style.display = r.dataset.q.includes(e.target.value.toLowerCase()) ? '' : 'none');
  const b = $('newUser'); if (b) b.onclick = async () => {
    const roles = can('roles:read') ? await api('/roles').catch(() => []) : [];
    modal('Create user', `<div class="field"><label>Email</label><input name="email" type="email" required></div>
      <div class="field"><label>Display name</label><input name="display_name"></div>
      <div class="field"><label>Temporary password</label><input name="password" type="password" required minlength="8"></div>
      <div class="field"><label>Role</label>${roles.length ? `<select name="role_name">${roles.map(r => `<option>${esc(get(r, 'name', 'Name'))}</option>`).join('')}</select>` : '<input name="role_name" placeholder="e.g. member">'}</div>`,
      async f => { await api('/users', {method: 'POST', body: Object.fromEntries(f)}); toast('User created'); go('users'); }, 'Create user');
  };
}};

pages.roles = {title: 'Roles & Permissions', icon: '⚿', group: 'Product', perm: 'roles:read', async render() {
  const roles = await api('/roles');
  const cards = await Promise.all(roles.map(async r => { const id = get(r, 'id', 'ID'); const perms = await api(`/roles/${id}/permissions`).catch(() => []); return {r, id, perms}; }));
  return `<div class="row"><p class="hint" style="margin:0">Roles bundle permissions like <code>users:read</code>. Assign roles to users on creation.</p><div class="grow"></div>${can('roles:create') ? '<button class="btn primary" id="newRole">+ New role</button>' : ''}</div>
  <div class="grid g2" style="margin-top:16px">${cards.map(({r, id, perms}) => `<div class="card"><div class="row"><h3 style="font-size:16px">${esc(get(r, 'name', 'Name'))}</h3><div class="grow"></div>${can('roles:update') ? `<button class="btn sm" data-add="${id}">+ Permission</button>` : ''}</div>
    <div class="hint" style="margin:4px 0 12px">${esc(get(r, 'description', 'Description') || 'No description')}</div>
    <div>${perms.length ? perms.map(p => `<span class="tag">${esc(typeof p === 'string' ? p : get(p, 'name', 'Name', 'permission', 'Permission') || JSON.stringify(p))}</span>`).join('') : '<span class="hint">No permissions assigned</span>'}</div></div>`).join('') || '<div class="card empty">No roles yet.</div>'}</div>`;
}, mount() {
  const n = $('newRole'); if (n) n.onclick = () => modal('Create role', `<div class="field"><label>Name</label><input name="name" required placeholder="support-agent"></div><div class="field"><label>Description</label><input name="description"></div>`,
    async f => { await api('/roles', {method: 'POST', body: Object.fromEntries(f)}); toast('Role created'); go('roles'); }, 'Create role');
  document.querySelectorAll('[data-add]').forEach(b => b.onclick = () => modal('Assign permission', `<div class="field"><label>Permission</label><input name="permission" list="pl" required placeholder="resource:action"><datalist id="pl">${['users:read', 'users:create', 'roles:read', 'roles:create', 'roles:update', 'tenant:update'].map(p => `<option>${p}`).join('')}</datalist><span class="hint">Format <code>resource:action</code>.</span></div>`,
    async f => { await api(`/roles/${b.dataset.add}/permissions`, {method: 'POST', body: {permission: f.get('permission')}}); toast('Permission assigned'); go('roles'); }, 'Assign'));
}};

pages.policy = {title: 'Security Policy', icon: '⛨', group: 'Product', async render() {
  const p = await api('/tenant/policy'), ok = can('tenant:update');
  const sw = (n, t, d) => `<div class="toggle"><div><b>${t}</b><div class="hint">${d}</div></div><label class="sw"><input type="checkbox" name="${n}" ${p[n] ? 'checked' : ''} ${ok ? '' : 'disabled'}><i></i></label></div>`;
  return `<form id="pf" class="grid g2">
    <div class="card"><h3 style="margin-bottom:6px">Passwords</h3><div class="field" style="margin-top:14px"><label>Minimum length</label><input name="password_min_length" type="number" min="6" max="128" value="${p.password_min_length}" ${ok ? '' : 'disabled'}></div>
      ${sw('password_require_upper', 'Require uppercase', 'At least one A–Z')}${sw('password_require_digit', 'Require digit', 'At least one 0–9')}${sw('password_require_symbol', 'Require symbol', 'At least one special character')}</div>
    <div class="card"><h3 style="margin-bottom:6px">Access</h3>
      ${sw('require_mfa', 'Require MFA', 'Users without an enrolled factor are blocked at sign-in')}
      <div class="field" style="margin-top:14px"><label>Max active sessions per user (0 = unlimited)</label><input name="max_active_sessions" type="number" min="0" value="${p.max_active_sessions}" ${ok ? '' : 'disabled'}></div>
      <div class="field"><label>Allowed email domains</label><input name="domains" placeholder="acme.com, acme.io" value="${esc((p.allowed_email_domains || []).join(', '))}" ${ok ? '' : 'disabled'}><span class="hint">Comma-separated. Empty allows any domain.</span></div></div>
    <div>${ok ? '<button class="btn primary">Save policy</button>' : '<span class="badge warn">Read-only — requires tenant:update</span>'}</div></form>`;
}, mount() {
  const f = $('pf'); f.onsubmit = async e => { e.preventDefault(); const d = new FormData(f), c = n => f.elements[n].checked;
    try { await api('/tenant/policy', {method: 'PUT', body: {password_min_length: +d.get('password_min_length'), password_require_upper: c('password_require_upper'), password_require_digit: c('password_require_digit'), password_require_symbol: c('password_require_symbol'), require_mfa: c('require_mfa'), max_active_sessions: +d.get('max_active_sessions'), allowed_email_domains: d.get('domains').split(',').map(s => s.trim()).filter(Boolean)}}); toast('Policy saved'); } catch (err) { fail(err); } };
}};

pages.devtools = {title: 'Developer Tools', icon: '⌘', group: 'Technical', async render() {
  return `<div class="tab" id="dt"><button class="on" data-t="oidc">OIDC & JWKS</button><button data-t="jwt">JWT decoder</button><button data-t="api">API explorer</button></div><div id="dtv"></div>`;
}, mount() {
  const tabs = {
    async oidc() { const [d, k] = await Promise.all([api('/.well-known/openid-configuration', {auth: false}), api('/.well-known/jwks.json', {auth: false})]);
      return `<div class="grid g2"><div class="card"><h3 style="font-size:14px;margin-bottom:10px">Discovery document</h3><pre class="code">${esc(JSON.stringify(d, null, 2))}</pre></div>
      <div class="card"><h3 style="font-size:14px;margin-bottom:10px">Signing keys (${(k.keys || []).length})</h3>${(k.keys || []).map(x => `<div class="row" style="margin-bottom:8px"><span class="badge ok">${esc(x.alg || x.kty)}</span><code>${esc(x.kid)}</code><span class="hint">${esc(x.use || '')}</span></div>`).join('') || '<div class="empty">No keys</div>'}<pre class="code" style="margin-top:12px">${esc(JSON.stringify(k, null, 2))}</pre></div></div>`; },
    async jwt() { return `<div class="grid g2"><div class="card"><div class="field"><label>Token</label><textarea id="jt" rows="9" class="mono">${esc(Auth.token() || '')}</textarea></div><button class="btn" id="jx">Decode</button> <span class="hint">Decoded locally; signature isn't verified here.</span></div><div class="card" id="jo"><div class="empty">Paste a token and press Decode.</div></div></div>`; },
    async api() { return `<div class="card"><div class="row"><select id="am" class="search" style="min-width:90px"><option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option></select><input id="ap" class="search mono" style="flex:1" value="/me"><button class="btn primary" id="ago">Send</button></div>
      <div class="field" style="margin-top:12px"><label>JSON body</label><textarea id="ab" rows="4" class="mono" placeholder='{"key":"value"}'></textarea></div><div id="ao"></div></div>`; }};
  const hooks = {
    jwt() { const run = () => { try { const {header, payload} = decodeJwt($('jt').value); const exp = payload.exp ? new Date(payload.exp * 1000) : null;
      $('jo').innerHTML = `<div class="row" style="margin-bottom:10px">${exp ? `<span class="badge ${exp < new Date() ? 'bad' : 'ok'}">${exp < new Date() ? 'expired' : 'expires'} ${exp.toLocaleString()}</span>` : ''}</div><b>Header</b><pre class="code">${esc(JSON.stringify(header, null, 2))}</pre><b>Payload</b><pre class="code">${esc(JSON.stringify(payload, null, 2))}</pre>`; } catch (e) { $('jo').innerHTML = `<div class="alert err show">${esc(e.message)}</div>`; } };
      $('jx').onclick = run; if ($('jt').value) run(); },
    api() { $('ago').onclick = async () => { const t = performance.now(); $('ao').innerHTML = '<div class="hint">…</div>'; try { const b = $('ab').value.trim(); const r = await api($('ap').value, {method: $('am').value, body: b ? JSON.parse(b) : undefined});
      $('ao').innerHTML = `<span class="badge ok">OK · ${Math.round(performance.now() - t)} ms</span><pre class="code" style="margin-top:10px">${esc(typeof r === 'string' ? r : JSON.stringify(r, null, 2))}</pre>`; } catch (e) { $('ao').innerHTML = `<span class="badge bad">${e.status || 'ERR'}</span><pre class="code" style="margin-top:10px">${esc(e.message)}</pre>`; } }; }};
  const load = async t => { document.querySelectorAll('#dt button').forEach(b => b.classList.toggle('on', b.dataset.t === t)); $('dtv').innerHTML = '<div class="hint">Loading…</div>'; try { $('dtv').innerHTML = await tabs[t](); hooks[t]?.(); } catch (e) { $('dtv').innerHTML = `<div class="alert err show">${esc(e.message)}</div>`; } };
  document.querySelectorAll('#dt button').forEach(b => b.onclick = () => load(b.dataset.t)); load('oidc');
}};

pages.account = {title: 'My Security', icon: '☗', group: 'Account', async render() {
  const [f, w] = await Promise.all([api('/mfa/factors').catch(() => []), api('/webauthn/credentials').catch(() => [])]);
  return `<div class="grid g2"><div class="card"><div class="row"><h3 style="font-size:15px">Authenticator apps (TOTP)</h3><div class="grow"></div><button class="btn sm primary" id="enr">+ Enroll</button></div>
    <div style="margin-top:12px">${(f || []).map(x => `<div class="row" style="padding:8px 0;border-bottom:1px solid var(--border)"><b>${esc(get(x, 'label') || 'Authenticator')}</b><div class="grow"></div><span class="badge ${get(x, 'verified') ? 'ok' : 'warn'}">${get(x, 'verified') ? 'verified' : 'pending'}</span></div>`).join('') || '<div class="hint">No factors enrolled.</div>'}</div></div>
    <div class="card"><h3 style="font-size:15px">Passkeys</h3><div style="margin-top:12px">${(w || []).map(x => `<div class="row" style="padding:8px 0;border-bottom:1px solid var(--border)"><b>${esc(get(x, 'label', 'Label') || 'Passkey')}</b><div class="grow"></div><span class="hint">${ago(get(x, 'created_at', 'CreatedAt'))}</span></div>`).join('') || '<div class="hint">No passkeys registered.</div>'}</div></div></div>`;
}, mount() {
  $('enr').onclick = () => modal('Enroll authenticator', `<div class="field"><label>Label</label><input name="label" value="Authenticator" required></div>`, async f => {
    const r = await api('/mfa/enroll/totp', {method: 'POST', body: {label: f.get('label')}});
    setTimeout(() => modal('Verify enrollment', `<p>Add this secret to your authenticator app:</p><pre class="code" style="margin-bottom:12px">${esc(r.secret)}</pre><a href="${esc(r.qr_url)}" class="hint">${esc(r.qr_url)}</a>
      <div class="field" style="margin-top:14px"><label>6-digit code</label><input name="code" inputmode="numeric" maxlength="6" required></div>`,
      async g => { await api('/mfa/enroll/verify', {method: 'POST', body: {factor_id: r.factor_id, code: g.get('code')}}); toast('MFA enabled'); go('account'); }, 'Verify'), 50);
  }, 'Continue');
}};

/* ---------- Shell ---------- */
async function go(id) {
  const p = pages[id] || pages.overview; location.hash = id;
  document.querySelectorAll('#nav a').forEach(a => a.classList.toggle('on', a.dataset.p === id));
  $('pageTitle').textContent = p.title; $('side').classList.remove('open');
  if (!can(p.perm)) { view.innerHTML = `<div class="card empty"><h3>No access</h3><p>This page needs the <code>${p.perm}</code> permission.</p></div>`; return; }
  view.innerHTML = '<div class="hint">Loading…</div>';
  try { view.innerHTML = await p.render(); p.mount?.(); } catch (e) { view.innerHTML = `<div class="alert err show">${esc(e.message)}</div>`; fail(e); }
}
function buildNav() {
  let g = '', h = '';
  for (const [id, p] of Object.entries(pages)) { if (p.group !== g) { g = p.group; h += `<div class="grp">${g}</div>`; } h += `<a data-p="${id}" class="${can(p.perm) ? '' : 'lock'}"><span>${p.icon}</span>${p.title}</a>`; }
  $('nav').innerHTML = h; $('nav').onclick = e => { const a = e.target.closest('a'); if (a) go(a.dataset.p); };
}
async function checkHealth() { const h = $('health'); try { await api('/health', {auth: false, raw: true}); h.className = 'badge ok'; h.innerHTML = '<span class="dot"></span>healthy'; } catch { h.className = 'badge bad'; h.innerHTML = '<span class="dot"></span>unreachable'; } }

(async () => {
  $('theme').onclick = theme.toggle; $('burger').onclick = () => $('side').classList.toggle('open');
  $('logout').onclick = async () => { try { await api('/logout', {method: 'POST'}); } catch {} Auth.clear(); location.replace('../login/'); };
  try { const m = await api('/me'); me = {email: get(m, 'Email', 'email') || '', roles: get(m, 'Roles', 'roles') || [], perms: get(m, 'Permissions', 'permissions') || []}; }
  catch (e) { if (e.status === 401) return fail(e); }
  $('meEmail').textContent = me.email || 'Signed in'; $('av').textContent = (me.email[0] || '?').toUpperCase(); $('meRoles').textContent = me.roles.join(', ') || 'no roles';
  buildNav(); checkHealth(); setInterval(checkHealth, 30000); go(location.hash.slice(1) || 'overview');
})();
