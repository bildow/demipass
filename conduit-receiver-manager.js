'use strict';
const profiles = require('./conduit-receiver-profile');
function acquire(config) {
  const fs = require('fs');
  const fd = fs.openSync(profiles.fileFor(config) + '.owner.lock', fs.constants.O_CREAT | fs.constants.O_RDWR | fs.constants.O_NOFOLLOW, 0o600);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.uid !== process.getuid() || (st.mode & 0o077)) throw Error('receiver_owner_invalid');
    const r = require('child_process').spawnSync('flock', ['-n','3'], { stdio: ['ignore','ignore','pipe',fd], timeout: 3000 });
    if (r.status !== 0) throw Error('receiver_already_owned');
    return () => fs.closeSync(fd);
  } catch (e) { fs.closeSync(fd); throw e; }
}
// Re-arm only after the previous poll has settled. An uncertain delivery or
// resource-limit stop is sticky; it is never converted into an automatic retry.
class ReceiverManager {
  constructor({ snapshot, create, lease = () => () => {} }) { this.snapshot = snapshot; this.create = create; this.lease = lease; this.release = null; this.listener = null; this.key = null; this.holdReason = null; }
  tick() {
    this.holdReason = null;
    let next;
    try { next = this.snapshot(); }
    catch (e) { if (this.listener) this.listener.stop(); throw e; }
    const key = next ? profiles.digest(next) : null;
    if (this.listener) {
      const state = this.listener.status();
      if (key !== this.key) this.listener.stop();
      if (this.listener.status().poll_in_flight) { if(key!==this.key)this.holdReason='receiver_previous_poll_draining';return; }
      if (key === this.key && !state.stopped) return;
      if (state.stopped && state.last_error && state.last_error !== 'inbox_binding_changed') { this.holdReason=state.last_error;return; }
      this.listener.stop(); this.listener = null; this.key = null;
      if (this.release) { this.release(); this.release = null; }
    }
    if (next) {
      this.release = this.lease(next);
      try { this.listener = this.create(next); this.key = key; this.listener.start(); }
      catch (e) { this.listener = null; this.key = null; this.release(); this.release = null; throw e; }
    }
  }
}
module.exports = { ReceiverManager, acquire };
