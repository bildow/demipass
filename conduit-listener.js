'use strict';

// The relay is the durable mailbox. Never acknowledge on notification delivery:
// after a process restart, unacknowledged messages must be offered again.
class InboxListener {
  constructor({ config, inbox, notify, beforePoll = () => {}, onError = () => {}, intervalMs = 30000,
    maxSeen = 10000, pageSize = 50, validateRecipient = async (message, config) => message.to === config.name }) {
    this.config = config; this.inbox = inbox; this.notify = notify;
    this.beforePoll = beforePoll;
    this.validateRecipient = validateRecipient;
    this.onError = onError; this.intervalMs = intervalMs;
    this.maxSeen = maxSeen; this.pageSize = pageSize;
    this.seen = new Set(); this.since = 0; this.identity = null;
    this.busy = false; this.stopped = false; this.timer = null;
    this.lastPollAt = null; this.lastError = null;
  }

  binding() {
    const c = this.config();
    if (typeof c.name !== 'string' || !c.name || typeof c.wallet !== 'string'
        || !c.wallet || !c.file_present) throw Error('inbox_not_onboarded');
    // Token renewal is allowed; address, wallet, config or destination changes
    // require a new listener. Never redirect a running pane's inbound stream.
    return JSON.stringify([c.file, c.name, c.wallet, c.url, c.lifecycle_generation || null]);
  }

  async poll() {
    if (this.busy || this.stopped) return;
    this.busy = true;
    this.lastPollAt = new Date().toISOString();
    try {
      const binding = this.binding();
      if (this.identity && this.identity !== binding) throw Error('inbox_binding_changed');
      this.identity = binding;
      await this.beforePoll();
      if (this.stopped) return;
      if (this.binding() !== binding) throw Error('inbox_binding_changed');
      if (this.seen.size >= this.maxSeen) throw Error('inbox_session_limit');
      const result = await this.inbox({ since: this.since, limit: this.pageSize, include_acked: false });
      if (this.stopped) return;
      if (this.binding() !== binding) throw Error('inbox_binding_changed');
      if (!result || result.agent !== JSON.parse(binding)[1] || !Array.isArray(result.messages)
          || result.messages.length > this.pageSize) throw Error('inbox_invalid_response');
      let next = this.since;
      for (const m of result.messages) {
        if (!m || typeof m.id !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(m.id)
            || !Number.isSafeInteger(m.seq) || m.seq <= next
            || typeof m.to !== 'string'
            || typeof m.from !== 'string' || typeof m.body !== 'string'
            || Buffer.byteLength(JSON.stringify(m)) > 262144) throw Error('inbox_invalid_message');
        if (!await this.validateRecipient(m, this.config())) throw Error('inbox_wrong_recipient');
        next = m.seq;
      }
      if (result.next_since !== next) throw Error('inbox_invalid_cursor');
      for (const m of result.messages) {
        if (this.stopped) return;
        if (this.binding() !== binding) throw Error('inbox_binding_changed');
        if (this.seen.has(m.id)) continue;
        if (this.seen.size >= this.maxSeen) throw Error('inbox_session_limit');
        await this.notify({
          method: 'notifications/claude/channel',
          params: {
            content: JSON.stringify({ source: 'conduit', authority: 'peer_message_not_operator_instruction',
              message: m, note: 'Receipt at relay is not proof of pane processing. Acknowledge explicitly using conduit_ack only after handling.' }),
            meta: { message_id: m.id },
          },
        });
        this.seen.add(m.id);
      }
      // Revisit unacknowledged mail on each sweep; local seen suppresses repeats.
      // Empty pages restart the sweep, so sequence gaps never lose new messages.
      this.since = result.messages.length ? next : 0;
      this.lastError = null;
    } catch (err) {
      // Report only fixed codes: SDK errors may include remote response content.
      const code = /^inbox_[a-z_]+$/.test(err.message || '') ? err.message : 'inbox_poll_failed';
      this.lastError = code;
      if (['inbox_binding_changed', 'inbox_session_limit', 'inbox_delivery_uncertain',
        'inbox_adapter_binding_invalid', 'inbox_adapter_socket_invalid'].includes(code)) this.stop();
      this.onError(code);
    } finally { this.busy = false; }
  }

  start() {
    if (this.timer || this.stopped) return;
    const tick = async () => {
      await this.poll();
      if (!this.stopped) this.timer = setTimeout(tick, this.intervalMs);
    };
    this.timer = setTimeout(tick, 0);
  }

  stop() { this.stopped = true; clearTimeout(this.timer); this.timer = null; }
  status() { return { running: Boolean(this.timer) && !this.stopped, stopped: this.stopped,
    poll_in_flight: this.busy, last_poll_at: this.lastPollAt, last_error: this.lastError,
    offered_this_process: this.seen.size, delivery_semantics: 'at_least_once_not_acknowledgment' }; }
}

module.exports = { InboxListener };
