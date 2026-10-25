const $ = (id) => document.getElementById(id);
const send = (msg) => chrome.runtime.sendMessage(msg);

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
