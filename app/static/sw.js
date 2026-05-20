/* sw.js — Service worker for the Online Clipboard PWA.
 *
 * Strategy:
 *   - Cache name derives from the ?v=<APP_BUILD_ID> registration query string.
 *     Each new build deploys a new SW URL → fresh install → fresh cache.
 *   - Precache: vendored crypto bundle, app JS, fonts, logo, qrcode lib.
 *     These are the assets we want to keep available offline and serve
 *     instantly on subsequent loads.
 *   - Network-only for everything else (HTML, API endpoints, SSE stream).
 *     Caching any of those would either break auth (token refresh) or leak
 *     stale ciphertext.
 *   - Cross-origin requests are ignored (passed through to the network).
 *
 * Pinning the JS in cache makes the "served code" trust window shrink: once
 * a user has loaded a known-good version, subsequent visits replay that
 * exact bundle until they explicitly accept an update. Combined with SRI on
 * the script tags (checked on initial network load), it's defence-in-depth
 * against a runtime swap of the crypto code.
 */

'use strict';

const VERSION = new URLSearchParams(self.location.search).get('v') || 'dev';
const CACHE_NAME = 'clip-' + VERSION;

// Same-origin static assets to keep available offline. Kept short on purpose
// — every entry adds an `addAll` failure surface on install.
const PRECACHE = [
  '/static/js/vendor/hash-wasm.umd.min.js',
  '/static/js/clip-crypto.js',
  '/static/js/clip-keystore.js',
  '/static/qrcode.min.js',
  '/static/logo.png',
  '/static/logo-192.png',
  '/static/logo-512.png',
  '/static/fonts/plex-mono-400.woff2',
  '/static/fonts/plex-mono-500.woff2',
  '/static/fonts/plex-mono-600.woff2',
  '/static/fonts/plex-sans-400.woff2',
  '/static/fonts/plex-sans-500.woff2',
  '/static/fonts/plex-sans-600.woff2',
  '/static/fonts/plex-sans-700.woff2',
];

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    // Use individual fetches so one missing asset doesn't tank the whole
    // install (logo size variants, future fonts, etc. evolve over time).
    await Promise.all(PRECACHE.map(async (url) => {
      try {
        const res = await fetch(url, { cache: 'reload' });
        if (res.ok) await cache.put(url, res);
      } catch (_) { /* offline at install — that's fine, fetched on demand */ }
    }));
    // Activate immediately so users get the new SW without waiting for tabs to close.
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(
      keys.filter((k) => k !== CACHE_NAME && k.startsWith('clip-'))
          .map((k) => caches.delete(k))
    );
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  // Cross-origin → let the network handle it (e.g. dev tooling, embedded resources).
  if (url.origin !== self.location.origin) return;

  // Cache-first only for /static/* — never for navigations or API endpoints.
  // The session HTML, /contents, /pow/challenge, file downloads etc. must
  // always hit the network so tokens, ciphertext freshness, and auth flows
  // work correctly.
  if (!url.pathname.startsWith('/static/')) return;

  event.respondWith((async () => {
    const cache = await caches.open(CACHE_NAME);
    const hit = await cache.match(req);
    if (hit) return hit;
    try {
      const res = await fetch(req);
      if (res.ok) cache.put(req, res.clone());
      return res;
    } catch (err) {
      // Offline + cache miss → propagate the error so the page surfaces it.
      throw err;
    }
  })());
});
