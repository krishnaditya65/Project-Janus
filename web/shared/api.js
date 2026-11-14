// Tiny API client + helpers shared by login and admin UIs.
(function(){
  const S = window.sessionStorage, L = window.localStorage;
  const guess = () => (location.protocol.startsWith('http') && location.port === '8080') ? location.origin : 'http://localhost:8080';
  const get = (o, ...keys) => { for (const k of keys) if (o && o[k] !== undefined) return o[k]; };
  const Auth = {
    base: () => L.getItem('iam.base') || guess(),
    setBase: v => L.setItem('iam.base', v.replace(/\/+$/, '')),
    token: () => S.getItem('iam.token'),
    save(out){ if(out.access_token) S.setItem('iam.token', out.access_token); if(out.refresh_token) S.setItem('iam.refresh', out.refresh_token); if(out.session_id) S.setItem('iam.sid', out.session_id); },
    clear(){ ['iam.token','iam.refresh','iam.sid'].forEach(k => S.removeItem(k)); },
  };
  async function api(path, {method='GET', body, form, auth=true, raw=false} = {}, retry=true){
    const h = {};
    if (auth && Auth.token()) h.Authorization = 'Bearer ' + Auth.token();
    let payload;
    if (form) { h['Content-Type'] = 'application/x-www-form-urlencoded'; payload = new URLSearchParams(form); }
    else if (body !== undefined) { h['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
    let res;
    try { res = await fetch(Auth.base() + path, {method, headers:h, body:payload, credentials:'include'}); }
    catch(e){ throw Object.assign(new Error('Cannot reach server at ' + Auth.base()), {network:true}); }
    if (res.status === 401 && auth && retry && S.getItem('iam.refresh') && path !== '/refresh') {
      const r = await fetch(Auth.base() + '/refresh', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({refresh_token:S.getItem('iam.refresh')})});
      if (r.ok) { const o = await r.json(); Auth.save(o); return api(path, {method, body, form, auth, raw}, false); }
    }
    const text = await res.text();
    let data = text; try { data = JSON.parse(text); } catch(_){}
    if (!res.ok) throw Object.assign(new Error((data && data.error) || (typeof data === 'string' && data.trim()) || res.statusText), {status:res.status, data});
    return raw ? text : data;
  }
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const b64 = s => { s = s.replace(/-/g,'+').replace(/_/g,'/'); return decodeURIComponent(escape(atob(s + '='.repeat((4 - s.length % 4) % 4)))); };
  const decodeJwt = t => { const p = t.trim().split('.'); if (p.length !== 3) throw new Error('Not a JWT (expected 3 parts)'); return {header:JSON.parse(b64(p[0])), payload:JSON.parse(b64(p[1]))}; };
  const theme = { init(){ const t = L.getItem('iam.theme'); if (t) document.documentElement.dataset.theme = t; },
    toggle(){ const dark = getComputedStyle(document.documentElement).getPropertyValue('--bg').trim() === '#0d0f1a'; const n = dark ? 'light' : 'dark'; document.documentElement.dataset.theme = n; L.setItem('iam.theme', n); } };
  theme.init();
  window.IAM = {api, Auth, esc, get, decodeJwt, theme};
})();
