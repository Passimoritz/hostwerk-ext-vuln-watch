'use strict';
// Versionen vergleichen und gegen betroffene Bereiche prüfen (OSV-Ereignisse, NVD-cpeMatch)
const test = require('node:test');
const assert = require('node:assert');
const V = require('../server/version');

test('clean: Hostwerk-, Debian-, Ubuntu-, Alpine- und RHEL-Angaben', () => {
  assert.deepStrictEqual(V.clean('2.4.62-system'), { raw: '2.4.62-system', upstream: '2.4.62', distro: 'system' });
  assert.strictEqual(V.clean('2.4.62-1~deb12u2').upstream, '2.4.62');
  assert.strictEqual(V.clean('2.4.62-1~deb12u2').distro, 'debian');
  assert.strictEqual(V.clean('1:10.11.6-0+deb12u1').upstream, '10.11.6');
  assert.strictEqual(V.clean('8.1.2-1ubuntu2.18').distro, 'ubuntu');
  assert.strictEqual(V.clean('7.2.4-r0').distro, 'alpine');
  assert.strictEqual(V.clean('16.4-1.pgdg120+1').upstream, '16.4');
  assert.strictEqual(V.clean('8.0.36-1.el9').distro, 'rhel');
  assert.strictEqual(V.clean('v20.11.1').upstream, '20.11.1');
  assert.strictEqual(V.clean('1.0.0-rc1').upstream, '1.0.0-rc1');
  assert.strictEqual(V.clean('1.0.0-rc1').distro, null);
  assert.strictEqual(V.clean('').upstream, '');
  assert.strictEqual(V.precision('8.2'), 2);
  assert.strictEqual(V.precision('7'), 1);
});

test('cmp: Zahl für Zahl, Vorabversionen und Nachträge', () => {
  assert.strictEqual(V.cmp('8.3.10', '8.3.9'), 1);
  assert.strictEqual(V.cmp('8.3.9', '8.3.10'), -1);
  assert.strictEqual(V.cmp('2.4.49', '2.4.49'), 0);
  assert.strictEqual(V.cmp('8.3', '8.3.0'), 0);
  assert.strictEqual(V.cmp('1.0.0-rc1', '1.0.0'), -1);
  assert.strictEqual(V.cmp('1.0.0-rc2', '1.0.0-rc10'), -1);
  assert.strictEqual(V.cmp('3.12.0b2', '3.12.0'), -1);
  assert.strictEqual(V.cmp('1.0.0-alpha', '1.0.0-beta'), -1);
  assert.strictEqual(V.cmp('1.1.1w', '1.1.1v'), 1); // OpenSSL-Stil: Buchstaben-Nachträge zählen aufsteigend
  assert.strictEqual(V.cmp('10.11.10', '10.11.9'), 1);
  assert.strictEqual(V.cmp('v1.2.3', '1.2.3'), 0);
});

test('osvAffected: SEMVER-Bereich mit introduced/fixed', () => {
  const aff = { ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] };
  assert.deepStrictEqual(V.osvAffected(aff, '4.17.20'), { hit: true, fixed: '4.17.21', introduced: '0' });
  assert.strictEqual(V.osvAffected(aff, '4.17.21').hit, false);
  assert.strictEqual(V.osvAffected(aff, '4.18.0').hit, false);
});

test('osvAffected: mehrere Reihen (8.3.10 behoben, 8.3.9 betroffen)', () => {
  const aff = { ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '8.2.0' }, { fixed: '8.2.25' }, { introduced: '8.3.0' }, { fixed: '8.3.10' }] }] };
  assert.strictEqual(V.osvAffected(aff, '8.3.9').hit, true);
  assert.strictEqual(V.osvAffected(aff, '8.3.9').fixed, '8.3.10');
  assert.strictEqual(V.osvAffected(aff, '8.3.10').hit, false);
  assert.strictEqual(V.osvAffected(aff, '8.2.24').fixed, '8.2.25');
  assert.strictEqual(V.osvAffected(aff, '8.1.9').hit, false);
});

test('osvAffected: last_affected, offenes Ende und versions-Liste', () => {
  assert.strictEqual(V.osvAffected({ ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '1.0' }, { last_affected: '1.4.2' }] }] }, '1.4.2').hit, true);
  assert.strictEqual(V.osvAffected({ ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '1.0' }, { last_affected: '1.4.2' }] }] }, '1.4.3').hit, false);
  const open = V.osvAffected({ ranges: [{ type: 'SEMVER', events: [{ introduced: '2.0.0' }] }] }, '2.5.0');
  assert.strictEqual(open.hit, true);
  assert.strictEqual(open.fixed, null);
  // Nur versions-Liste (GIT-Bereiche zählen nicht) – Fix-Version aus anderen Bereichen
  const list = V.osvAffected({ versions: ['1.2.3', '1.2.4'], ranges: [{ type: 'GIT', events: [{ introduced: 'abc' }, { fixed: 'def' }] }] }, '1.2.4');
  assert.strictEqual(list.hit, true);
});

const conf = (...matches) => [{ nodes: [{ operator: 'OR', negate: false, cpeMatch: matches.map((m) => ({ vulnerable: true, ...m })) }] }];
const APACHE = ['cpe:2.3:a:apache:http_server'];

test('nvdMatch: feste Version und Bereiche (Start/Ende einschließlich/ausschließlich)', () => {
  assert.strictEqual(V.nvdMatch(conf({ criteria: 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*' }), APACHE, '2.4.49').hit, true);
  assert.strictEqual(V.nvdMatch(conf({ criteria: 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*' }), APACHE, '2.4.50').hit, false);
  const range = conf({ criteria: 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*', versionStartIncluding: '2.4.0', versionEndExcluding: '2.4.52' });
  assert.deepStrictEqual(V.nvdMatch(range, APACHE, '2.4.51'), { hit: true, fixed: '2.4.52', conditional: false });
  assert.strictEqual(V.nvdMatch(range, APACHE, '2.4.52').hit, false);
  assert.strictEqual(V.nvdMatch(range, APACHE, '2.2.34').hit, false);
  const incl = conf({ criteria: 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*', versionStartExcluding: '2.4.10', versionEndIncluding: '2.4.20' });
  assert.strictEqual(V.nvdMatch(incl, APACHE, '2.4.10').hit, false);
  assert.strictEqual(V.nvdMatch(incl, APACHE, '2.4.20').hit, true);
  assert.strictEqual(V.nvdMatch(incl, APACHE, '2.4.20').fixed, null);
  // Distributions-Version wird auf Upstream zurückgeführt
  assert.strictEqual(V.nvdMatch(range, APACHE, '2.4.51-1~deb11u1').hit, true);
  // anderes Produkt, nicht verwundbar markiert, „alle Versionen“ ohne Grenzen → kein Treffer
  assert.strictEqual(V.nvdMatch(conf({ criteria: 'cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*' }), APACHE, '1.20.0').hit, false);
  assert.strictEqual(V.nvdMatch([{ nodes: [{ cpeMatch: [{ vulnerable: false, criteria: 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*' }] }] }], APACHE, '2.4.49').hit, false);
  assert.strictEqual(V.nvdMatch(conf({ criteria: 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*' }), APACHE, '2.4.49').hit, false);
});

test('nvdMatch: Update-Feld im CPE (5.3.0:rc1) und UND-Verknüpfung (nur mit Windows)', () => {
  assert.strictEqual(V.nvdMatch(conf({ criteria: 'cpe:2.3:a:php:php:5.3.0:rc1:*:*:*:*:*:*' }), ['cpe:2.3:a:php:php'], '5.3.0-rc1').hit, true);
  assert.strictEqual(V.nvdMatch(conf({ criteria: 'cpe:2.3:a:php:php:5.3.0:rc1:*:*:*:*:*:*' }), ['cpe:2.3:a:php:php'], '5.3.0').hit, false);
  const and = [{ operator: 'AND', nodes: [
    { operator: 'OR', cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*', versionStartIncluding: '8.3.0', versionEndExcluding: '8.3.8' }] },
    { operator: 'OR', cpeMatch: [] },
  ] }];
  assert.deepStrictEqual(V.nvdMatch(and, ['cpe:2.3:a:php:php'], '8.3.7'), { hit: true, fixed: '8.3.8', conditional: true });
});
