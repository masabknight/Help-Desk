const tok = () => sessionStorage.getItem('token');
async function api(path, method = 'GET', body) {
  const r = await fetch(path, { method, headers: { 'Content-Type': 'application/json', ...(tok() ? { Authorization: 'Bearer ' + tok() } : {}) },
    body: body ? JSON.stringify(body) : undefined });
  let d = {}; try { d = await r.json(); } catch (e) {}
  if (r.status === 401 && !path.includes('login')) logout();
  if (!r.ok) throw new Error(d.error || 'Server error (' + r.status + ')');
  return d;
}
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const badge = s => `<span class="badge ${esc(s)}">${esc(s)}</span>`;
function logout() { try { api('/api/logout', 'POST'); } catch (e) {} sessionStorage.clear(); location.href = '/'; }
function guard(roles) { if (!tok() || !roles.includes(sessionStorage.getItem('role'))) { sessionStorage.clear(); location.href = '/'; } }
function msg(id, text, ok) { const e = document.getElementById(id); e.className = 'msg ' + (ok ? 'ok' : 'err'); e.textContent = text; }
function historyTable(h) {
  return '<table><tr><th>When</th><th>By</th><th>Change</th><th>Remarks</th></tr>' + h.map(x =>
    `<tr><td>${esc(x.changed_at)}</td><td>${esc(x.changed_by)}</td><td>${esc(x.old_status || '—')} → ${esc(x.new_status)}</td><td>${esc(x.remarks)}</td></tr>`).join('') + '</table>';
}
