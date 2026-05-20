/* clip-keystore.js — sessionStorage-backed per-session key store.
 *
 * The raw 32-byte AES key is written here in base64. Scope is the browser
 * tab/session: closing the tab clears it. Anyone with XSS on the page can
 * read it — that's an inherent trade-off of E2EE in a web app, and the
 * threat shifts from "trust the operator" to "trust the served HTML/JS".
 */
(function () {
  'use strict';

  const PREFIX = 'clip:key:';

  async function store(sid, key) {
    const b64 = await window.ClipCrypto.exportKeyRaw(key);
    sessionStorage.setItem(PREFIX + sid, b64);
  }

  async function load(sid) {
    const b64 = sessionStorage.getItem(PREFIX + sid);
    if (!b64) return null;
    try {
      return await window.ClipCrypto.importKeyRaw(b64);
    } catch (_) {
      sessionStorage.removeItem(PREFIX + sid);
      return null;
    }
  }

  function clear(sid) {
    sessionStorage.removeItem(PREFIX + sid);
  }

  function has(sid) {
    return sessionStorage.getItem(PREFIX + sid) !== null;
  }

  window.ClipKeystore = { store, load, clear, has };
})();
