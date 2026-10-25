// One extension API object for Chromium (chrome.*) and Gecko (browser.*).
// Firefox and Zen expose promise-based `browser`; Chromium exposes `chrome`,
// which returns promises in Manifest V3. Everything else in the extension
// uses `ext` and never names either global.
export const ext = globalThis.browser ?? globalThis.chrome;

// true in Firefox / Zen (moz-extension://), false in Chrome / Brave.
export const isGecko = typeof ext?.runtime?.getURL === 'function' && ext.runtime.getURL('').startsWith('moz-extension:');
