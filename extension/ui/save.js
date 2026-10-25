// Name prompt for "Store in DemiPass" on selected text. The value stays in the
// background worker; this page only learns its length and source origin.

import { ext } from '../lib/browser.js';

const $ = (id) => document.getElementById(id);
const id = location.hash.slice(1);
const send = (msg) => ext.runtime.sendMessage(msg);

(async () => {
  const r = await send({ type: 'ui:pendingInfo', id });
  if (!r || !r.ok || r.kind !== 'selection') {
    $('info').textContent = (r && r.error) || 'Nothing to store.';
    $('info').className = 'err';
    return;
  }
  $('info').textContent = `${r.length} characters selected${r.origin ? ' on ' + r.origin : ''}.`;
  if (r.origin) $('bind-origin').textContent = r.origin;
  else $('bind-wrap').hidden = true;
  $('form').hidden = false;
  $('name').focus();
})();

// Storing under an existing name replaces it: the first answer is a
// conflict, and only a second click on "Replace" (same name) sends replace.
let replaceName = null;
$('name').addEventListener('input', () => { replaceName = null; $('store').textContent = 'Store'; });

$('form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = e.submitter;
  if (btn) btn.disabled = true;
  const name = $('name').value.trim();
  const r = await send({ type: 'ui:savePending', id, name, secret_type: $('type').value, bindOrigin: $('bind').checked, replace: replaceName === name });
  if (r && r.conflict) {
    replaceName = r.conflict.name;
    $('store').textContent = 'Replace';
    $('msg').textContent = `“${r.conflict.name}” already exists in your vault (${r.conflict.secret_type || 'secret'}). Storing replaces its value. Click Replace to do that, or change the name.`;
    $('msg').className = 'err';
    if (btn) btn.disabled = false;
    return;
  }
  if (r && r.ok) {
    $('form').hidden = true;
    $('msg').textContent = `Stored as “${r.name}” (${r.ref}).`;
    $('msg').className = 'ok';
    setTimeout(() => window.close(), 1500);
  } else {
    $('msg').textContent = (r && r.error) || 'Store failed.';
    $('msg').className = 'err';
    if (btn) btn.disabled = false;
  }
});

$('cancel').addEventListener('click', async () => {
  await send({ type: 'ui:dismissPending', id });
  window.close();
});

