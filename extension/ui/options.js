import { ext } from '../lib/browser.js';

const $ = (id) => document.getElementById(id);
const send = (msg) => ext.runtime.sendMessage(msg);

(async () => {
  const r = await send({ type: 'ui:getSettings' });
  if (r && r.ok && r.apiBase !== r.defaultBase) $('base').value = r.apiBase;
})();

$('form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const r = await send({ type: 'ui:setApiBase', base: $('base').value.trim() });
  $('msg').textContent = r && r.ok ? `Using ${r.apiBase}.` : (r && r.error) || 'Could not save.';
  $('msg').className = r && r.ok ? 'ok' : 'err';
});

// Firefox / Zen let the person turn host access off. Show it, and ask for it
// from the click itself (permissions.request needs the user gesture).
async function renderAccess() {
  const r = await send({ type: 'ui:access' });
  if (!r || !r.ok) return;
  const a = r.access;
  const parts = [a.allSites ? 'DemiPass can see login forms on all sites.' : 'DemiPass cannot see login forms until you allow it (all sites, or per site from its toolbar popup).'];
  if (a.requestApi) parts.push('It is not allowed to connect to the DemiPass server.');
  $('access-state').textContent = parts.join(' ');
  $('access-all').hidden = !a.requestAll;
  $('access-all').dataset.origins = JSON.stringify(a.requestAll || []);
}
$('access-all').addEventListener('click', (e) => {
  const origins = JSON.parse(e.currentTarget.dataset.origins || '[]');
  if (origins.length) ext.permissions.request({ origins }).finally(renderAccess);
});
renderAccess();
