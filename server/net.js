'use strict';
/*
 * Netz mit Rücksicht: eine Stelle für alle Abfragen an die freien Quellen.
 *   - Drosselung je Adresse (NVD ohne Schlüssel: 5 Abfragen in 30 s → mindestens 6,5 s Abstand)
 *   - Rückoff bei 403/429/503: Retry-After beachten, sonst wachsend warten; nach drei Versuchen Pause für diese Adresse
 *   - Offline-Modus von Hostwerk: keine Verbindung, klarer Fehler (code HW_OFFLINE) – der letzte Stand bleibt sichtbar
 * fetch, Uhr und Warten sind einsetzbar (Tests).
 */

const HOSTS = {
  'services.nvd.nist.gov': { gap: 6500, backoff: [30000, 60000, 120000], pause: 30 * 60000, timeout: 240000 }, // große Seiten (PHP: ~1000 CVEs)
  'api.osv.dev': { gap: 150, backoff: [5000, 15000, 45000], pause: 10 * 60000 },
  'www.cisa.gov': { gap: 1000, backoff: [10000, 30000, 60000], pause: 60 * 60000 },
  'api.first.org': { gap: 1200, backoff: [10000, 30000, 60000], pause: 30 * 60000 },
};
const DEFAULT = { gap: 500, backoff: [5000, 15000, 45000], pause: 10 * 60000 };
const UA = 'Hostwerk-vuln-watch/1.0 (+https://github.com/Passimoritz/hostwerk-ext-vuln-watch)';

class Net {
  /** opts: { fetch, now, sleep, offline: () => bool, timeout } */
  constructor(opts = {}) {
    this.fetch = opts.fetch || ((u, o) => globalThis.fetch(u, o));
    this.now = opts.now || (() => Date.now());
    this.sleep = opts.sleep || ((ms) => new Promise((r) => { const t = setTimeout(r, ms); if (t.unref) t.unref(); }));
    this.offline = opts.offline || (() => false);
    this.timeout = opts.timeout || 60000;
    this.last = new Map(); // host → Zeit der letzten Abfrage
    this.blocked = new Map(); // host → gesperrt bis (nach Rate-Limit)
    this.queue = new Map(); // host → Promise-Kette (eine Abfrage nach der anderen je Adresse)
    this.count = 0;
  }

  policy(host) { return HOSTS[host] || DEFAULT; }

  /** Ist die Adresse gerade wegen eines Abfragelimits gesperrt? → Zeitpunkt oder null */
  blockedUntil(host) { const t = this.blocked.get(host); return t && t > this.now() ? t : null; }

  /** JSON holen (GET oder POST mit body). Wirft Fehler mit code: HW_OFFLINE, RATE_LIMIT, HTTP_<status>. */
  json(url, { method = 'GET', body = null } = {}) {
    const host = new URL(url).hostname;
    const prev = this.queue.get(host) || Promise.resolve();
    const run = prev.catch(() => {}).then(() => this.one(host, url, method, body));
    this.queue.set(host, run.catch(() => {}));
    return run;
  }

  async one(host, url, method, body) {
    if (this.offline()) throw Object.assign(new Error(`Offline mode is on – no connection to ${host}.`), { code: 'HW_OFFLINE' });
    const until = this.blockedUntil(host);
    if (until) throw Object.assign(new Error(`${host} asked for a break (rate limit) – next try after ${new Date(until).toISOString()}.`), { code: 'RATE_LIMIT', until });
    const pol = this.policy(host);
    for (let attempt = 0; ; attempt++) {
      const wait = (this.last.get(host) || 0) + pol.gap - this.now();
      if (wait > 0) await this.sleep(wait);
      this.last.set(host, this.now());
      this.count++;
      let res;
      try {
        res = await this.fetch(url, {
          method,
          headers: { 'User-Agent': UA, Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}) },
          body: body ? JSON.stringify(body) : undefined,
          signal: typeof AbortSignal !== 'undefined' && AbortSignal.timeout ? AbortSignal.timeout(pol.timeout || this.timeout) : undefined,
        });
      } catch (e) {
        if (e && e.code === 'HW_OFFLINE') throw e; // Hostwerks Wächter um fetch
        // Abgebrochene Verbindungen kommen bei der NVD ohne Schlüssel immer wieder vor – mehrmals mit Pause versuchen
        if (attempt >= pol.backoff.length - 1) throw Object.assign(new Error(`${host} is not reachable: ${e.message}`), { code: 'NETWORK' });
        await this.sleep(pol.backoff[attempt]);
        continue;
      }
      if (res.status === 429 || res.status === 403 || res.status === 503) {
        if (attempt >= pol.backoff.length) {
          const until = this.now() + pol.pause;
          this.blocked.set(host, until);
          throw Object.assign(new Error(`${host} answers ${res.status} (rate limit) – trying again later.`), { code: 'RATE_LIMIT', status: res.status, until });
        }
        const ra = Number(res.headers && typeof res.headers.get === 'function' ? res.headers.get('retry-after') : NaN);
        await this.sleep(Number.isFinite(ra) && ra > 0 ? Math.min(ra * 1000, 5 * 60000) : pol.backoff[attempt]);
        continue;
      }
      if (res.status === 404) return null;
      if (!res.ok) throw Object.assign(new Error(`${host} answers ${res.status}`), { code: `HTTP_${res.status}`, status: res.status });
      return res.json();
    }
  }
}

module.exports = { Net, HOSTS };
