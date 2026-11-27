/* Service worker: shell caching only.
 *
 * Deliberately minimal. Every panel in this dashboard shows live state, and a
 * stale cached answer would be worse than an error message - "sniproxy is
 * running" from ten minutes ago is a lie, not a convenience. So API responses
 * are never cached; only the static shell is, which is what makes the app
 * install to a home screen and open instantly.
 */
const CACHE = 'smartdns-shell-v1';

/* Resolved relative to the worker's own scope, so a sub-path deployment
   (root_path = /dns) works without changes. */
const SHELL = ['style.css', 'app.js', 'icon.svg', 'manifest.webmanifest'];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE)
      .then((c) => c.addAll(SHELL.map((p) => new URL(p, self.registration.scope).pathname)))
      .then(() => self.skipWaiting())
      .catch(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  const isShell = /\.(css|js|svg|webmanifest)$/.test(url.pathname);

  /* Anything that is not a static asset - the page itself, every /api/ route,
     the SSE stream - goes straight to the network, always. */
  if (e.request.method !== 'GET' || !isShell) return;

  e.respondWith(
    fetch(e.request)
      .then((resp) => {
        if (resp && resp.ok) {
          const copy = resp.clone();
          caches.open(CACHE).then((c) => c.put(e.request, copy)).catch(() => {});
        }
        return resp;
      })
      .catch(() => caches.match(e.request))
  );
});
