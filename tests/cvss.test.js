'use strict';
// CVSS lesen, rechnen (3.0/3.1), in Worte fassen (3.x, 4.0, 2.0) und die beste Angabe wählen
const test = require('node:test');
const assert = require('node:assert');
const C = require('../server/cvss');

test('parse: 3.1, 4.0 und alte 2.0-Vektoren', () => {
  const p = C.parse('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  assert.strictEqual(p.version, '3.1');
  assert.strictEqual(p.metrics.AV, 'N');
  assert.strictEqual(C.parse('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N').version, '4.0');
  assert.strictEqual(C.parse('AV:N/AC:L/Au:N/C:C/I:C/A:C').version, '2.0');
  assert.strictEqual(C.parse('Unsinn'), null);
  assert.strictEqual(C.parse(''), null);
});

test('score3: bekannte Werte nach der FIRST-Formel', () => {
  const s = (v) => { const p = C.parse(v); return C.score3(p.metrics, p.version); };
  assert.strictEqual(s('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.strictEqual(s('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10); // Log4Shell
  assert.strictEqual(s('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'), 7.5); // Apache 2.4.49 Pfad-Durchquerung
  assert.strictEqual(s('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'), 6.1); // typisches XSS
  assert.strictEqual(s('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'), 7.8);
  assert.strictEqual(s('CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N'), 2);
  assert.strictEqual(s('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'), 0);
  assert.strictEqual(s('CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'), 8.8);
  assert.strictEqual(C.score3({ AV: 'N' }), null);
  assert.strictEqual(C.roundup(4.000002, '3.1'), 4);
  assert.strictEqual(C.roundup(4.02, '3.1'), 4.1);
});

test('level und levelFromText', () => {
  assert.strictEqual(C.level(9.8), 'critical');
  assert.strictEqual(C.level(9.0), 'critical');
  assert.strictEqual(C.level(7.0), 'high');
  assert.strictEqual(C.level(6.9), 'medium');
  assert.strictEqual(C.level(0.1), 'low');
  assert.strictEqual(C.level(0), 'none');
  assert.strictEqual(C.level(null), 'unknown');
  assert.strictEqual(C.levelFromText('MODERATE'), 'medium');
  assert.strictEqual(C.levelFromText('HIGH'), 'high');
  assert.strictEqual(C.levelFromText(undefined), 'unknown');
});

test('explain: Merkmale in Worten mit Risiko (3.1, 4.0, 2.0) und Übersetzer', () => {
  const e = C.explain(C.parse('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'));
  assert.deepStrictEqual(e.map((x) => x.key), ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']);
  assert.strictEqual(e[0].value, 'Over the network – also from the internet');
  assert.strictEqual(e[0].risk, 'high');
  assert.strictEqual(e.find((x) => x.key === 'PR').value, 'No – anyone can try');
  const v4 = C.explain(C.parse('CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N'));
  assert.ok(v4.some((x) => x.key === 'AT' && x.risk === 'low'));
  assert.ok(v4.some((x) => x.key === 'UI' && x.value === 'Yes – someone has to do something deliberately'));
  assert.ok(v4.some((x) => x.key === 'SC' && x.value === 'Other systems stay unaffected'));
  const v2 = C.explain(C.parse('AV:N/AC:M/Au:N/C:P/I:P/A:C'));
  assert.deepStrictEqual(v2.map((x) => x.value), ['Over the network – also from the internet', 'Medium – needs some conditions', 'No – anyone can try', 'Partly', 'Partly', 'Completely']);
  const de = C.explain(C.parse('CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'), (s) => `[${s}]`);
  assert.strictEqual(de[0].label, '[Attack vector]');
  assert.strictEqual(de[0].risk, 'mid');
  assert.strictEqual(C.remoteNoAuth(C.parse('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')), true);
  assert.strictEqual(C.remoteNoAuth(C.parse('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H')), false);
});

test('best: 4.0 mit Wert vor 3.1, fehlender 3.x-Wert wird berechnet, 4.0 ohne Wert nach 3.x', () => {
  const b = C.best([
    { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', score: 9.8, source: 'nvd' },
    { vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', score: 9.3, source: 'cna' },
  ]);
  assert.strictEqual(b.version, '4.0');
  assert.strictEqual(b.score, 9.3);
  assert.strictEqual(b.level, 'critical');
  const c = C.best([
    { vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', score: null },
    { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', score: null },
  ]);
  assert.strictEqual(c.version, '3.1');
  assert.strictEqual(c.score, 7.5);
  assert.strictEqual(c.level, 'high');
  assert.strictEqual(C.best([{ vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' }]).level, 'unknown');
  assert.strictEqual(C.best([]), null);
});
