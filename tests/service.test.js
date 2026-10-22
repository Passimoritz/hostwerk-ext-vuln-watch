'use strict';
// Die ganze Runde mit nachgebautem Hostwerk und Attrappen der vier Quellen: Bestand → Abgleich → KEV/EPSS → Funde,
// Update-Knopf, „Betrifft mich das?“, Ausnahmen, Benachrichtigung genau einmal, Offline-Modus
const test = require('node:test');
const assert = require('node:assert');
const { createService } = require('../server/index');
const { assess, summarize } = require('../server/assess');
const { item } = require('../server/inventory');
const { hintText, fixText, pkgCommand } = require('../server/texts');
const { clock, fakeFetch, tmpDir, cleanup, nvdCve } = require('./helpers');

test.after(cleanup);

const APACHE_2449 = { criteria: 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*' };
const PHP_RANGE = { criteria: 'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*', versionStartIncluding: '8.1.0', versionEndExcluding: '8.1.29' };

/** Antworten der Quellen: Apache 2.4.49 (zwei CVEs, eine ausgenutzt), PHP 8.1.0 (eine nur mit Windows), lodash im Projekt. */
function sources() {
  return (url, opts) => {
    if (url.startsWith('https://services.nvd.nist.gov/')) {
      const p = new URL(url).searchParams.get('virtualMatchString');
      if (p === 'cpe:2.3:a:apache:http_server') return { resultsPerPage: 3, totalResults: 3, vulnerabilities: [
        nvdCve('CVE-2021-41773', { matches: [APACHE_2449], text: 'A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49.' }),
        nvdCve('CVE-2021-40438', { matches: [{ criteria: 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*', versionEndExcluding: '2.4.49' }, { criteria: 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*' }], vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H', score: 9.0, text: 'SSRF in mod_proxy.' }),
        nvdCve('CVE-2021-44790', { matches: [{ criteria: 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*', versionEndIncluding: '2.4.51' }], vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', score: 9.8, text: 'A buffer overflow in mod_lua r:parsebody.' }),
      ] };
      if (p === 'cpe:2.3:a:php:php') return { resultsPerPage: 1, totalResults: 1, vulnerabilities: [
        nvdCve('CVE-2024-4577', { matches: [PHP_RANGE], operator: 'AND', extraNode: { operator: 'OR', cpeMatch: [{ vulnerable: false, criteria: 'cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*' }] }, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', score: 9.8, text: 'In PHP when using Apache and PHP-CGI on Windows, an attacker may pass options.' }),
      ] };
      return { resultsPerPage: 0, totalResults: 0, vulnerabilities: [] };
    }
    if (url.endsWith('/v1/querybatch')) {
      const b = JSON.parse(opts.body);
      return { results: b.queries.map((q) => (q.package.name === 'lodash' && q.version === '4.17.20' ? { vulns: [{ id: 'GHSA-35jh-r3h4-6jhm', modified: '2026-01-01T00:00:00Z' }] } : {})) };
    }
    if (url.includes('/v1/vulns/GHSA-35jh-r3h4-6jhm')) return { id: 'GHSA-35jh-r3h4-6jhm', aliases: ['CVE-2021-23337'], summary: 'Command Injection in lodash', details: 'lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.', modified: '2026-01-01T00:00:00Z', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' }], affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }] };
    if (url.includes('/v1/vulns/')) return { status: 404 };
    if (url.includes('cisa.gov')) return { vulnerabilities: [{ cveID: 'CVE-2021-41773', dateAdded: '2021-11-03', knownRansomwareCampaignUse: 'Known', requiredAction: 'Apply updates per vendor instructions.' }] };
    if (url.includes('api.first.org')) return { data: new URL(url).searchParams.get('cve').split(',').map((cve) => ({ cve, epss: cve === 'CVE-2021-41773' ? '0.944' : '0.02', percentile: '0.99', date: '2026-10-20' })) };
    return { status: 404 };
  };
}

function fakeHost({ settings = {}, pending = [], eol = null } = {}) {
  const data = tmpDir('vw-svc');
  const sent = []; const toasts = []; const watchers = []; const notes = [];
  const fill = (s, v) => (v ? String(s).replace(/\{(\w+)\}/g, (m, k) => (v[k] !== undefined ? String(v[k]) : m)) : String(s));
  const host = {
    id: 'vuln-watch', t: fill, lang: () => 'de', broadcast: (m) => toasts.push(m), watcher: (w) => watchers.push(w), log: () => {},
    core: () => ({ isOffline: () => false }),
    notifications: { register: () => 'ext:vuln-watch:new-findings', notify: (id, m) => notes.push({ id, ...m }) },
    ctx: {
      paths: { data },
      extMarket: { settingsFor: () => settings },
      monitor: { send: async (title, text, o) => { sent.push({ title, text, ...o }); return []; } },
      patchUpdates: { pending },
      eol: eol ? { info: eol } : undefined,
    },
  };
  return { host, sent, toasts, watchers, notes, data };
}

/** Bestand ohne Hostwerk: Apache 2.4.49 (nur mod_rewrite geladen), PHP 8.1.0, MariaDB nur lokal, Projekt mit lodash. */
const inventory = async () => ({ items: [
  item({ id: 'web:apache', area: 'web', kind: 'web', product: 'apache', name: 'Apache', version: '2.4.49', updateKey: 'web-apache', href: '#/web/apache', modules: ['rewrite', 'proxy'] }),
  item({ id: 'php:8.1.0', area: 'php', kind: 'php', product: 'php', name: 'PHP 8.1', version: '8.1.0', updateKey: 'php-8.1', href: '#/web/php' }),
  item({ id: 'db:mariadb', area: 'dbs', kind: 'db', product: 'mariadb', name: 'MariaDB', version: '10.6.12', updateKey: 'db-mariadb', exposure: { local: true } }),
  item({ id: 'project:shop', area: 'projects', kind: 'project', product: null, name: 'shop', version: null, packages: [{ ecosystem: 'npm', name: 'lodash', version: '4.17.20', dev: false, file: 'package-lock.json' }, { ecosystem: 'npm', name: 'jest', version: '29.0.0', dev: true }] }),
  item({ id: 'game:v', area: 'games', kind: 'game', product: null, name: 'Valheim', version: null, why: 'no-version' }),
], notes: [] });

test('Runde: Funde mit CVSS, KEV, EPSS, Behebung und Hinweisen', async () => {
  const c = clock();
  const f = fakeFetch(sources());
  const pending = [{ key: 'web-apache', current: '2.4.49', latest: '2.4.62' }, { key: 'php-8.1', current: '8.1.0', latest: '8.1.31' }];
  const eol = (p, v) => (p === 'php' ? { state: 'eol', eolAt: Date.parse('2025-12-31'), daysLeft: -294, cycle: '8.1', recommended: '8.4', label: 'PHP' } : p === 'mariadb' ? { state: 'soon', daysLeft: 40, cycle: '10.6', recommended: '11.8' } : { state: 'ok' });
  const fh = fakeHost({ pending, eol });
  const svc = createService(fh.host, { fetch: f, now: c.now, sleep: c.sleep, collect: inventory, platform: 'linux' });
  const r = await svc.run();
  const by = (k) => r.findings.find((x) => x.key === k);

  const a = by('web:apache|CVE-2021-41773');
  assert.ok(a, 'Apache 2.4.49 ist betroffen');
  assert.strictEqual(a.level, 'high');
  assert.strictEqual(a.score, 7.5);
  assert.deepStrictEqual(a.kev && a.kev.ransomware, true);
  assert.strictEqual(a.epss.epss, 0.944);
  assert.deepStrictEqual(a.fix, { kind: 'patch', key: 'web-apache', to: '2.4.62', href: '#/web/apache' });
  assert.strictEqual(r.findings[0].key, a.key, 'ausgenutzt steht oben');
  assert.ok(by('web:apache|CVE-2021-40438').hints.some((h) => h.code === 'module-on' && h.module === 'mod_proxy'));
  assert.ok(by('web:apache|CVE-2021-44790').hints.some((h) => h.code === 'module-off' && h.module === 'mod_lua'));
  assert.strictEqual(by('web:apache|CVE-2021-44790').fixed, null, 'versionEndIncluding nennt keine behobene Version');

  const php = by('php:8.1.0|CVE-2024-4577');
  assert.strictEqual(php.level, 'critical');
  assert.strictEqual(php.fixed, '8.1.29');
  assert.strictEqual(php.fix.kind, 'patch');
  assert.ok(php.hints.some((h) => h.code === 'conditional' && h.others.includes('microsoft windows')));
  assert.ok(php.hints.some((h) => h.code === 'other-os' && h.os === 'Windows'));
  const phpEol = by('php:8.1.0|eol');
  assert.strictEqual(phpEol.kind, 'eol');
  assert.strictEqual(phpEol.level, 'high');
  assert.strictEqual(phpEol.fix.to, '8.4');
  assert.strictEqual(by('db:mariadb|eol').level, 'medium');

  const lo = by('project:shop|npm|lodash|4.17.20|CVE-2021-23337');
  assert.ok(lo, 'Projekt-Abhängigkeit über OSV, zusammengelegt über die CVE');
  assert.strictEqual(lo.id, 'CVE-2021-23337');
  assert.deepStrictEqual(lo.ids, ['CVE-2021-23337', 'GHSA-35jh-r3h4-6jhm']);
  assert.strictEqual(lo.fixed, '4.17.21');
  assert.strictEqual(lo.score, 7.2, 'Wert aus dem Vektor berechnet');
  assert.strictEqual(lo.fix.kind, 'manual');
  assert.strictEqual(pkgCommand(lo.pkg, lo.fixed), 'npm install lodash@4.17.21');

  assert.deepStrictEqual(r.unchecked.map((x) => x.id), ['game:v']);
  assert.strictEqual(r.overall, 'critical');
  assert.strictEqual(r.counts.kev, 1);
  assert.strictEqual(r.counts.eol, 2);
  assert.ok(r.counts.fixable >= 3);
  // Erster Lauf: nur das Ausgenutzte wird gemeldet (kein Überfall mit dem Altbestand), gebündelt in EINER Meldung
  assert.strictEqual(fh.notes.length, 1);
  assert.match(fh.notes[0].title, /1 actively exploited/);
  assert.match(fh.notes[0].text, /CVE-2021-41773/);
  assert.strictEqual(fh.sent.length, 1);
  assert.strictEqual(fh.sent[0].push, false, 'Push kommt schon über den eigenen Anlass');
  assert.strictEqual(fh.watchers.at(-1).state, 'alert');

  // Zweiter Lauf am nächsten Tag: Bekanntes wird nicht noch einmal gemeldet
  c.t += 21 * 3600000;
  await svc.run();
  assert.strictEqual(fh.notes.length, 1);

  // Liste ohne Langtext, Detail mit Text und Links
  const v = svc.view();
  assert.ok(v.findings.every((x) => x.details === undefined && x.refs === undefined));
  assert.match(svc.detail(a.key).details, /path normalization/);
  assert.ok(svc.detail(a.key).refs.length);
  assert.strictEqual(v.lang, 'de');
  assert.ok(v.inventory.find((x) => x.id === 'project:shop').packages === 2);
});

test('Neue kritische Funde nach dem ersten Lauf werden einmal gemeldet; Ausnahmen zählen nicht', async () => {
  const c = clock();
  const fh = fakeHost();
  let php = '8.1.30'; // erst nicht betroffen
  const inv = async () => ({ items: [item({ id: 'php:x', area: 'php', kind: 'php', product: 'php', name: 'PHP 8.1', version: php })], notes: [] });
  const svc = createService(fh.host, { fetch: fakeFetch(sources()), now: c.now, sleep: c.sleep, collect: inv, platform: 'win32' });
  await svc.run();
  assert.strictEqual(fh.notes.length, 0);
  php = '8.1.0';
  c.t += 21 * 3600000;
  const r = await svc.run();
  assert.strictEqual(fh.notes.length, 1);
  assert.match(fh.notes[0].title, /1 new critical/);
  const k = r.findings.find((x) => x.id === 'CVE-2024-4577').key;
  assert.ok(!r.findings.find((x) => x.key === k).hints.some((h) => h.code === 'other-os'), 'unter Windows kein „anderes System“');
  // Ausnahme mit Grund und Datum → zählt nicht mehr, Ampel wird grün
  const ig = { ...svc.ignores(), [k]: { reason: 'nur intern', until: c.t + 86400000, at: c.t } };
  svc.store.set('ignores', ig);
  svc.reassess();
  let v = svc.view();
  assert.strictEqual(v.counts.critical, 0);
  assert.strictEqual(v.counts.ignored, 1);
  assert.strictEqual(v.overall, 'ok');
  assert.strictEqual(v.findings.find((x) => x.key === k).ignored.reason, 'nur intern');
  // Datum vorbei → wieder da (mit Merker „Ausnahme abgelaufen“)
  c.t += 2 * 86400000;
  svc.reassess();
  v = svc.view();
  assert.strictEqual(v.counts.critical, 1);
  assert.strictEqual(v.findings.find((x) => x.key === k).expiredIgnore, true);
});

test('Offline-Modus: keine Abfrage, der letzte Stand bleibt sichtbar', async () => {
  const c = clock();
  const fh = fakeHost();
  let offline = false;
  const f = fakeFetch(sources());
  const svc = createService(fh.host, { fetch: f, now: c.now, sleep: c.sleep, collect: inventory, offline: () => offline, platform: 'linux' });
  await svc.run();
  const before = f.calls.length;
  const n = svc.view().findings.length;
  assert.ok(n > 0);
  offline = true;
  c.t += 25 * 3600000;
  await svc.run({ force: true });
  assert.strictEqual(f.calls.length, before, 'kein einziger Netzaufruf');
  const v = svc.view();
  assert.strictEqual(v.offline, true);
  assert.strictEqual(v.findings.length, n);
  assert.strictEqual(v.sources.nvd.offline, true);
  assert.ok(v.sources.nvd.at, 'Zeit des letzten guten Abrufs bleibt');
});

test('assess: Texte für Hinweise und Behebung, Ampel ohne Funde', () => {
  const t = (s, v) => (v ? String(s).replace(/\{(\w+)\}/g, (m, k) => (v[k] !== undefined ? String(v[k]) : m)) : s);
  assert.match(hintText({ code: 'distro', distro: 'debian' }, t), /Debian/);
  assert.match(hintText({ code: 'local-only' }, t), /only listens on this computer/);
  assert.match(fixText({ kind: 'vuln', fix: { kind: 'manual', to: '8.3.12', series: true } }, t), /newer series/);
  assert.match(fixText({ kind: 'eol', fix: { kind: 'manual', to: '8.4' } }, t), /series 8\.4/);
  assert.strictEqual(summarize([]).overall, 'ok');
  // Datenbank nur lokal + Netz-Angriff → Hinweis; System-Paket → Hinweis
  const db = item({ id: 'db:m', area: 'dbs', kind: 'db', product: 'mariadb', name: 'M', version: '10.6.12-0+deb12u1', exposure: { local: true } });
  const src = { osvIds: () => null, osvVuln: () => null, nvdCves: () => [{ id: 'CVE-1', source: 'nvd', details: 'x', metrics: [{ vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', score: 7.5 }], configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*', versionEndExcluding: '10.6.13' }] }] }] }] };
  const r = assess({ items: [db], src, now: 1 });
  assert.deepStrictEqual(r.findings[0].hints.map((h) => h.code), ['local-only', 'distro']);
  assert.strictEqual(r.findings[0].fix.kind, 'manual');
  assert.strictEqual(r.findings[0].fixed, '10.6.13');
});

test('Stabile Dienste (SDK 3.3): Updates, KI und Offline über host – Interna bleiben unberührt', async () => {
  const c = clock();
  const fh = fakeHost({ pending: [] }); // Kern-Interna: leer – alles muss über die stabilen Dienste kommen
  const applied = [];
  const sdkPending = [{ key: 'php-8.1', component: 'php', label: 'PHP 8.1', current: '8.1.0', latest: '8.1.29' }];
  Object.assign(fh.host, {
    supports: (n) => ['updates.pending', 'updates.apply', 'ai.quick', 'net.offline'].includes(n),
    updates: { pending: async () => sdkPending, apply: async (k) => { applied.push(k); return { ok: true, skipped: false, error: null }; } },
    ai: { quick: { ready: async () => true, run: async (task, o) => ({ text: `${task}:${o.lang}` }) } },
    net: { offline: () => false },
    core: () => { throw new Error('Kern-Interna dürfen nicht gefragt werden'); },
  });
  fh.host.ctx.patchUpdates = { pending: [], apply: async () => { throw new Error('alter Weg'); } };
  const svc = createService(fh.host, { fetch: fakeFetch(sources()), now: c.now, sleep: c.sleep, collect: inventory, platform: 'linux' });
  await svc.run();
  const php = svc.view().findings.find((f) => f.cve === 'CVE-2024-4577');
  assert.ok(php && php.fix && php.fix.kind === 'patch' && php.fix.key === 'php-8.1', 'Behebung aus host.updates.pending()');
  assert.deepStrictEqual(await svc.applyUpdate('php-8.1'), { ok: true, skipped: false, error: null });
  assert.deepStrictEqual(applied, ['php-8.1']);
  assert.strictEqual((await svc.aiQuick().run('summarize', { lang: 'de' })).text, 'summarize:de');
  assert.strictEqual(svc.view().offline, false);
  cleanup();
});

test('Ältere Hostwerk-Version ohne stabile Dienste: Rückfall auf die bisherigen Wege', async () => {
  const c = clock();
  const fh = fakeHost({ pending: [{ key: 'php-8.1', current: '8.1.0', latest: '8.1.29' }] });
  const applied = [];
  fh.host.ctx.patchUpdates.apply = async (k) => { applied.push(k); return { ok: true }; };
  const svc = createService(fh.host, { fetch: fakeFetch(sources()), now: c.now, sleep: c.sleep, collect: inventory, platform: 'linux' });
  await svc.run();
  assert.ok(svc.view().findings.some((f) => f.fix && f.fix.kind === 'patch'));
  await svc.applyUpdate('php-8.1');
  assert.deepStrictEqual(applied, ['php-8.1']);
  assert.strictEqual(svc.aiQuick(), null, 'ohne KI im Kontext: nicht bereit');
  cleanup();
});
