/* clip-crypto.js — End-to-end encryption primitives, client-side only.
 *
 * Public API on window.ClipCrypto:
 *   deriveKey(password, saltB64)     -> CryptoKey (AES-GCM, non-extractable view)
 *   encryptString(text, key)         -> "n:c" base64 token
 *   decryptString(token, key)        -> plaintext string
 *   encryptBytes(arrayBuffer, key)   -> Uint8Array (12-byte nonce || ciphertext)
 *   decryptBytes(uint8, key)         -> ArrayBuffer
 *   sha256Hex(stringOrBytes)         -> hex string (used by PoW)
 *   solvePow(challenge, difficulty)  -> { nonce, hash } where SHA256(challenge||nonce) has N leading zero bits
 *   exportKeyRaw(key)                -> base64 raw 32-byte key
 *   importKeyRaw(b64)                -> CryptoKey
 *
 * Notes:
 *   - Argon2id parameters MUST match what we document so a session created in
 *     one tab/browser is decryptable in another. Changing these is a hard break.
 *   - Salt is a random base64 string chosen by the client at session creation
 *     and stored server-side (publicly) so a returning visitor can rederive
 *     the same key from the same typed password.
 *   - Token format is the same shape the server used in v1: two base64 chunks
 *     joined by ":" — keeps Redis schema unchanged.
 */
(function () {
  'use strict';

  if (!window.crypto || !window.crypto.subtle) {
    throw new Error('Web Crypto API unavailable — clipboard requires a modern browser.');
  }
  if (!window.hashwasm || typeof window.hashwasm.argon2id !== 'function') {
    throw new Error('hash-wasm not loaded — include /static/js/vendor/hash-wasm.umd.min.js first.');
  }

  // Argon2id params: identical to the v1 server-side values. Increase only via a
  // major version bump — existing sessions can't be re-keyed.
  const ARGON2_ITERATIONS  = 2;
  const ARGON2_MEMORY_KB   = 64 * 1024;
  const ARGON2_PARALLELISM = 2;
  const ARGON2_HASH_LEN    = 32;
  const NONCE_BYTES        = 12;

  const enc = new TextEncoder();
  const dec = new TextDecoder('utf-8', { fatal: true });

  function b64encode(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  function b64decode(str) {
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function hex(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i].toString(16);
      s += b.length === 1 ? '0' + b : b;
    }
    return s;
  }

  function randomSaltB64(bytes) {
    return b64encode(crypto.getRandomValues(new Uint8Array(bytes || 16)));
  }

  async function deriveKey(password, saltB64) {
    const salt = b64decode(saltB64);
    if (salt.length < 8) throw new Error('Salt too short.');
    const rawHex = await window.hashwasm.argon2id({
      password: password,
      salt: salt,
      parallelism: ARGON2_PARALLELISM,
      iterations: ARGON2_ITERATIONS,
      memorySize: ARGON2_MEMORY_KB,
      hashLength: ARGON2_HASH_LEN,
      outputType: 'hex',
    });

    const rawBytes = new Uint8Array(ARGON2_HASH_LEN);
    for (let i = 0; i < ARGON2_HASH_LEN; i++) {
      rawBytes[i] = parseInt(rawHex.slice(i * 2, i * 2 + 2), 16);
    }

    return crypto.subtle.importKey(
      'raw', rawBytes, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']
    );
  }

  async function encryptString(plaintext, key) {
    if (typeof plaintext !== 'string' || plaintext.length === 0) {
      throw new Error('Cannot encrypt empty plaintext.');
    }
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
    const ctBuf = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      key,
      enc.encode(plaintext)
    );
    return b64encode(nonce) + ':' + b64encode(new Uint8Array(ctBuf));
  }

  async function decryptString(token, key) {
    const idx = token.indexOf(':');
    if (idx < 0) throw new Error('Invalid token format.');
    const nonce = b64decode(token.slice(0, idx));
    const ct    = b64decode(token.slice(idx + 1));
    const ptBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce },
      key,
      ct
    );
    return dec.decode(ptBuf);
  }

  async function encryptBytes(plainBuf, key) {
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
    const ctBuf = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      key,
      plainBuf
    );
    const ct = new Uint8Array(ctBuf);
    const out = new Uint8Array(NONCE_BYTES + ct.length);
    out.set(nonce, 0);
    out.set(ct, NONCE_BYTES);
    return out;
  }

  async function decryptBytes(uint8, key) {
    if (uint8.length <= NONCE_BYTES) throw new Error('Invalid binary token.');
    const nonce = uint8.subarray(0, NONCE_BYTES);
    const ct    = uint8.subarray(NONCE_BYTES);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ct);
  }

  async function sha256Hex(input) {
    const data = typeof input === 'string' ? enc.encode(input) : input;
    const buf  = await crypto.subtle.digest('SHA-256', data);
    return hex(new Uint8Array(buf));
  }

  // Counts leading zero bits in a SHA-256 byte array.
  function leadingZeroBits(bytes) {
    let bits = 0;
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (b === 0) { bits += 8; continue; }
      let mask = 0x80;
      while (mask && (b & mask) === 0) { bits++; mask >>>= 1; }
      return bits;
    }
    return bits;
  }

  // SHA-256 PoW: find a nonce s.t. SHA256(challenge || ":" || nonce) has at
  // least `difficulty` leading zero bits. Uses hash-wasm's synchronous
  // createSHA256 in a tight loop — orders of magnitude faster than awaiting
  // crypto.subtle.digest per attempt. Yields to the event loop every BATCH
  // so the page stays responsive on slow devices.
  async function solvePow(challenge, difficulty) {
    const BATCH = 4096;
    const prefix = challenge + ':';
    const hasher = await window.hashwasm.createSHA256();
    let nonce = 0;
    while (true) {
      for (let i = 0; i < BATCH; i++, nonce++) {
        hasher.init();
        hasher.update(prefix + nonce);
        const hexStr = hasher.digest('hex');
        // First byte is hex[0..2]; quick reject — most attempts fail here.
        if (hexStr[0] !== '0' || hexStr[1] !== '0') continue;
        const bytes = new Uint8Array(32);
        for (let j = 0; j < 32; j++) bytes[j] = parseInt(hexStr.slice(j * 2, j * 2 + 2), 16);
        if (leadingZeroBits(bytes) >= difficulty) {
          return { nonce: String(nonce), hash: hexStr };
        }
      }
      await new Promise(r => setTimeout(r, 0));
    }
  }

  async function exportKeyRaw(key) {
    const raw = await crypto.subtle.exportKey('raw', key);
    return b64encode(new Uint8Array(raw));
  }

  async function importKeyRaw(b64) {
    const bytes = b64decode(b64);
    return crypto.subtle.importKey(
      'raw', bytes, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']
    );
  }

  window.ClipCrypto = {
    deriveKey,
    encryptString, decryptString,
    encryptBytes,  decryptBytes,
    sha256Hex,
    solvePow,
    exportKeyRaw,  importKeyRaw,
    randomSaltB64,
    NONCE_BYTES,
  };
})();
