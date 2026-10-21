'use strict';
// Netz mit Drosselung/Rückoff/Offline und die vier Quellen mit Zwischenspeicher – alles gegen Attrappen
const test = require('node:test');
const assert = require('node:assert');
const { Net } = require('../server/net');
const { Store } = require('../server/store');
const { Sources, reduceNvd, reduceOsv, nvdDate } = require('../server/sources');
const { clock, fakeFetch, tmpDir, cleanup, nvdCve } = require('./helpers');

test.after(cleanup);

test('Net: NVD gedrosselt (≥ 6,5 s Abstand), eine Abfrage nach der anderen', async () => {
  const c = clock();
  const f = fakeFetch(() => ({ ok: 1 }));
  const net = new Net({ fetch: f, now: c.now, sleep: c.sleep });
  await Promise.all([1, 2, 3].map((i) => net.json(`https://services.nvd.nist.gov/rest/json/cves/2.0?i=${i}`)));
  assert.strictEqual(f.calls.length, 3);
  assert.deepStrictEqual(c.sleeps, [6500, 6500]);
});

test('Net: Rückoff bei 429 mit Retry-After, dann Erfolg', async () => {
  const c = clock();
  let n = 0;
  const f = fakeFetch(() => (++n === 1 ? { status: 429, headers: { 'retry-after': '7' } } : { status: 200, body: { results: [] } }));
  const net = new Net({ fetch: f, now: c.now, sleep: c.sleep });
  const r = await net.json('https://api.osv.dev/v1/querybatch', { method: 'POST', body: { queries: [] } });
  assert.deepStrictEqual(r, { results: [] });
  assert.ok(c.sleeps.includes(7000), 'Retry-After beachtet');
  assert.strictEqual(f.calls[0].method, 'POST');
});

test('Net: 403 dreimal → wachsend warten, dann Pause für diese Adresse (RATE_LIMIT)', async () => {
  const c = clock();
  const f = fakeFetch(() => ({ status: 403 }));
  const net = new Net({ fetch: f, now: c.now, sleep: c.sleep });
  await assert.rejects(net.json('https://services.nvd.nist.gov/x'), (e) => e.code === 'RATE_LIMIT');
  assert.strictEqual(f.calls.length, 4);
  assert.ok(c.sleeps.includes(30000) && c.sleeps.includes(60000) && c.sleeps.includes(120000));
  assert.ok(net.blockedUntil('services.nvd.nist.gov'));
  // Während der Pause: kein weiterer Versuch
  await assert.rejects(net.json('https://services.nvd.nist.gov/y'), (e) => e.code === 'RATE_LIMIT');
  assert.strictEqual(f.calls.length, 4);
  // Andere Adressen sind nicht betroffen
  const g = fakeFetch(() => ({ ok: 1 }));
  net.fetch = g;
  assert.deepStrictEqual(await net.json('https://api.first.org/data/v1/epss?cve=CVE-2021-1'), { ok: 1 });
  // Nach der Pause wieder frei
  c.t += 31 * 60000;
  assert.strictEqual(net.blockedUntil('services.nvd.nist.gov'), null);
});

test('Net: Offline-Modus fragt gar nicht erst', async () => {
  const f = fakeFetch(() => ({ ok: 1 }));
  const net = new Net({ fetch: f, offline: () => true });
  await assert.rejects(net.json('https://api.osv.dev/v1/vulns/X'), (e) => e.code === 'HW_OFFLINE');
  assert.strictEqual(f.calls.length, 0);
});

test('Net: 404 → null, 500 → Fehler, Netzfehler → ein zweiter Versuch', async () => {
  const c = clock();
  let n = 0;
  const net = new Net({ fetch: fakeFetch((u) => (u.endsWith('404') ? { status: 404 } : u.endsWith('500') ? { status: 500 } : (++n === 1 ? new Error('ECONNRESET') : { status: 200, body: 'ok' }))), now: c.now, sleep: c.sleep });
  assert.strictEqual(await net.json('https://api.osv.dev/404'), null);
  await assert.rejects(net.json('https://api.osv.dev/500'), (e) => e.status === 500);
  assert.strictEqual(await net.json('https://api.osv.dev/flaky'), 'ok');
});

test('reduceNvd/reduceOsv: nur das Nötige, fremde Knoten als Bedingung', () => {
  const v = nvdCve('CVE-2024-4577', { matches: [{ criteria: 'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*', versionStartIncluding: '8.3.0', versionEndExcluding: '8.3.8' }], operator: 'AND', extraNode: { operator: 'OR', cpeMatch: [{ vulnerable: false, criteria: 'cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*' }] } });
  const r = reduceNvd(v.cve, ['cpe:2.3:a:php:php']);
  assert.strictEqual(r.details, 'A flaw.');
  assert.deepStrictEqual(r.others, ['microsoft windows']);
  assert.strictEqual(r.configurations[0].nodes.length, 2);
  assert.strictEqual(r.configurations[0].nodes[1].cpeMatch.length, 0);
  assert.deepStrictEqual(r.metrics[0], { version: '3.1', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', score: 7.5, source: 'nvd@nist.gov' });
  assert.deepStrictEqual(r.cwe, ['CWE-22']);
  const o = reduceOsv({ id: 'GHSA-1', aliases: ['CVE-2021-23337'], summary: 'Command Injection in lodash', details: 'x'.repeat(5000), severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' }], database_specific: { severity: 'HIGH', cwe_ids: ['CWE-77'] }, affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }, { package: { ecosystem: 'npm', name: 'other' } }] }, new Set(['npm|lodash']));
  assert.strictEqual(o.affected.length, 1);
  assert.strictEqual(o.details.length, 3000);
  assert.strictEqual(o.dbSeverity, 'HIGH');
  assert.strictEqual(nvdDate(Date.parse('2026-10-21T08:00:00Z')), '2026-10-21T08:00:00.000+00:00');
});

/** OSV-Attrappe: lodash 4.17.20 hat eine Lücke. */
function osvRoute(log) {
  return (url, opts) => {
    if (url.endsWith('/querybatch')) {
      const b = JSON.parse(opts.body);
      log.push(b.queries.length);
      return { results: b.queries.map((q) => (q.package.name === 'lodash' && q.version === '4.17.20' ? { vulns: [{ id: 'GHSA-35jh-r3h4-6jhm', modified: '2026-01-01T00:00:00Z' }] } : {})) };
    }
    if (url.includes('/vulns/GHSA-35jh-r3h4-6jhm')) return { id: 'GHSA-35jh-r3h4-6jhm', aliases: ['CVE-2021-23337'], summary: 'Command Injection in lodash', modified: '2026-01-01T00:00:00Z', affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }] };
    return { status: 404 };
  };
}

test('OSV: gebündelt abfragen, Details nur einmal, innerhalb eines Tages aus dem Speicher', async () => {
  const c = clock();
  const log = [];
  const f = fakeFetch(osvRoute(log));
  const src = new Sources({ net: new Net({ fetch: f, now: c.now, sleep: c.sleep }), store: new Store(tmpDir()), now: c.now });
  const pkgs = [{ ecosystem: 'npm', name: 'lodash', version: '4.17.20' }, { ecosystem: 'npm', name: 'express', version: '4.19.2' }, { ecosystem: 'npm', name: 'lodash', version: '4.17.20' }];
  await src.osvRefresh(pkgs);
  assert.deepStrictEqual(log, [2], 'ein Bündel, Doppelte zusammengelegt');
  assert.deepStrictEqual(src.osvIds(pkgs[0]), ['GHSA-35jh-r3h4-6jhm']);
  assert.deepStrictEqual(src.osvIds(pkgs[1]), []);
  assert.strictEqual(src.osvVuln('GHSA-35jh-r3h4-6jhm').summary, 'Command Injection in lodash');
  assert.ok(src.status().osv.at);
  const before = f.calls.length;
  await src.osvRefresh(pkgs); // frisch → keine Abfrage
  assert.strictEqual(f.calls.length, before);
  c.t += 21 * 3600000; // ein Tag später: neu fragen, Details aber nicht neu holen (modified gleich)
  await src.osvRefresh(pkgs);
  assert.deepStrictEqual(log, [2, 2]);
  assert.strictEqual(f.calls.filter((x) => x.url.includes('/vulns/')).length, 1);
});

test('Ausfall: letzter Stand bleibt, Fehler steht im Zustand', async () => {
  const c = clock();
  const dir = tmpDir();
  const ok = new Sources({ net: new Net({ fetch: fakeFetch(osvRoute([])), now: c.now, sleep: c.sleep }), store: new Store(dir), now: c.now });
  const pkgs = [{ ecosystem: 'npm', name: 'lodash', version: '4.17.20' }];
  await ok.osvRefresh(pkgs);
  c.t += 25 * 3600000;
  const down = new Sources({ net: new Net({ fetch: fakeFetch(() => ({ status: 500 })), now: c.now, sleep: c.sleep }), store: new Store(dir), now: c.now });
  await down.osvRefresh(pkgs);
  assert.deepStrictEqual(down.osvIds(pkgs[0]), ['GHSA-35jh-r3h4-6jhm']);
  assert.match(down.status().osv.error, /500/);
  const off = new Sources({ net: new Net({ fetch: fakeFetch(() => ({})), offline: () => true }), store: new Store(dir), now: c.now });
  await off.kevRefresh();
  assert.strictEqual(off.status().kev.offline, true);
  assert.strictEqual(off.osvVuln('GHSA-35jh-r3h4-6jhm').id, 'GHSA-35jh-r3h4-6jhm');
});

test('NVD: erst alles (seitenweise), dann nur Änderungen seit dem letzten Abruf', async () => {
  const c = clock();
  const seen = [];
  const route = (url) => {
    const u = new URL(url);
    seen.push(Object.fromEntries(u.searchParams));
    if (!u.searchParams.get('lastModStartDate')) {
      const start = Number(u.searchParams.get('startIndex'));
      const all = [nvdCve('CVE-2021-41773', { matches: [{ criteria: 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*' }] }), nvdCve('CVE-2021-42013', { matches: [{ criteria: 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*' }] }), nvdCve('CVE-2017-1', { matches: [{ criteria: 'cpe:2.3:a:apache:http_server:2.2.0:*:*:*:*:*:*:*' }] })];
      return { resultsPerPage: 2, startIndex: start, totalResults: 3, vulnerabilities: all.slice(start, start + 2) };
    }
    return { resultsPerPage: 1, startIndex: 0, totalResults: 1, vulnerabilities: [nvdCve('CVE-2021-41773', { matches: [{ criteria: 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*' }], score: 7.6 })] };
  };
  const src = new Sources({ net: new Net({ fetch: fakeFetch(route), now: c.now, sleep: c.sleep }), store: new Store(tmpDir()), now: c.now });
  const P = ['cpe:2.3:a:apache:http_server'];
  await src.nvdRefreshAll([{ prefixes: P }]);
  assert.strictEqual(seen.length, 2, 'zwei Seiten');
  assert.strictEqual(seen[0].virtualMatchString, 'cpe:2.3:a:apache:http_server');
  assert.ok('noRejected' in seen[0]);
  assert.strictEqual(seen[1].startIndex, '2');
  assert.strictEqual(src.nvdCves(P).length, 3);
  await src.nvdRefreshAll([{ prefixes: P }]); // frisch → nichts
  assert.strictEqual(seen.length, 2);
  c.t += 21 * 3600000;
  await src.nvdRefreshAll([{ prefixes: P }]);
  assert.strictEqual(seen.length, 3);
  assert.ok(seen[2].lastModStartDate && seen[2].lastModEndDate, 'nur Änderungen');
  assert.strictEqual(src.nvdCves(P).length, 3, 'alte Einträge bleiben');
  assert.strictEqual(src.nvdCves(P).find((x) => x.id === 'CVE-2021-41773').metrics[0].score, 7.6);
  c.t += 31 * 86400000; // nach 30 Tagen wieder komplett
  await src.nvdRefreshAll([{ prefixes: P }]);
  assert.ok(!seen[3].lastModStartDate);
});

test('KEV und EPSS: zusammenführen, gebündelt, unbekannte CVEs merken', async () => {
  const c = clock();
  const epssCalls = [];
  const route = (url) => {
    if (url.includes('cisa.gov')) return { catalogVersion: '2026.10.20', vulnerabilities: [{ cveID: 'CVE-2021-41773', dateAdded: '2021-11-03', dueDate: '2021-11-17', knownRansomwareCampaignUse: 'Known', vulnerabilityName: 'Apache HTTP Server Path Traversal', requiredAction: 'Apply updates.' }] };
    if (url.includes('api.first.org')) {
      const ids = new URL(url).searchParams.get('cve').split(',');
      epssCalls.push(ids.length);
      return { data: ids.filter((x) => x !== 'CVE-2099-0001').map((cve) => ({ cve, epss: '0.94', percentile: '0.999', date: '2026-10-20' })) };
    }
    return { status: 404 };
  };
  const src = new Sources({ net: new Net({ fetch: fakeFetch(route), now: c.now, sleep: c.sleep }), store: new Store(tmpDir()), now: c.now });
  await src.kevRefresh();
  assert.deepStrictEqual(src.kev().items['CVE-2021-41773'], { added: '2021-11-03', due: '2021-11-17', ransomware: true, name: 'Apache HTTP Server Path Traversal', action: 'Apply updates.' });
  const many = Array.from({ length: 170 }, (_, i) => `CVE-2021-${10000 + i}`).concat(['CVE-2099-0001', 'GHSA-xxxx', 'CVE-2021-10000']);
  await src.epssRefresh(many);
  assert.deepStrictEqual(epssCalls, [80, 80, 11], 'in Bündeln zu 80, Doppelte und Nicht-CVEs raus');
  assert.strictEqual(src.epss().items['CVE-2021-10001'].epss, 0.94);
  assert.strictEqual(src.epss().items['CVE-2099-0001'].epss, null);
  await src.epssRefresh(many);
  assert.deepStrictEqual(epssCalls, [80, 80, 11], 'am selben Tag nicht noch einmal');
});

test('NVD: ein Produkt scheitert → die anderen laufen weiter; Abfragelimit → Rest wird übersprungen', async () => {
  const c = clock();
  const route = (url) => {
    const p = new URL(url).searchParams.get('virtualMatchString');
    if (p === 'cpe:2.3:a:php:php') return { status: 500 };
    if (p === 'cpe:2.3:a:redis:redis') return { status: 429 };
    return { resultsPerPage: 1, totalResults: 1, vulnerabilities: [nvdCve('CVE-2021-41773', { matches: [{ criteria: `${p}:2.4.49:*:*:*:*:*:*:*` }] })] };
  };
  const f = fakeFetch(route);
  const src = new Sources({ net: new Net({ fetch: f, now: c.now, sleep: c.sleep }), store: new Store(tmpDir()), now: c.now });
  const done = await src.nvdRefreshAll([{ prefixes: ['cpe:2.3:a:php:php'] }, { prefixes: ['cpe:2.3:a:apache:http_server'] }]);
  assert.deepStrictEqual(done.map((x) => x.prefix), ['cpe:2.3:a:apache:http_server']);
  assert.match(src.status().nvd.error, /php php: .*500/);
  assert.ok(src.status().nvd.at, 'Teilerfolg zählt');
  const g = fakeFetch(route);
  const src2 = new Sources({ net: new Net({ fetch: g, now: c.now, sleep: c.sleep }), store: new Store(tmpDir()), now: c.now });
  await src2.nvdRefreshAll([{ prefixes: ['cpe:2.3:a:redis:redis'] }, { prefixes: ['cpe:2.3:a:apache:http_server'] }]);
  assert.strictEqual(g.calls.filter((x) => x.url.includes('apache')).length, 0, 'nach dem Limit keine weitere Abfrage');
  assert.match(src2.status().nvd.error, /rate limit/);
});
