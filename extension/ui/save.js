// Name prompt for "Store in DemiPass" on selected text. The value stays in the
// background worker; this page only learns its length and source origin.

const $ = (id) => document.getElementById(id);
const id = location.hash.slice(1);
const send = (msg) => chrome.runtime.sendMessage(msg);

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

$('form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = e.submitter;
  if (btn) btn.disabled = true;
  const r = await send({ type: 'ui:savePending', id, name: $('name').value, secret_type: $('type').value, bindOrigin: $('bind').checked });
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

