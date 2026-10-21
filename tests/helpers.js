'use strict';
// Attrappen für die Tests: Uhr, Warten und fetch mit Antworten je Adresse (kein echtes Netz)
const fs = require('fs');
const os = require('os');
const path = require('path');

/** Uhr, die nur beim Warten weiterläuft – so sind Drosselung und Rückoff ohne echte Wartezeit prüfbar. */
function clock(start = Date.parse('2026-10-21T08:00:00Z')) {
  const c = { t: start, sleeps: [] };
  c.now = () => c.t;
  c.sleep = async (ms) => { c.sleeps.push(ms); c.t += ms; };
  return c;
}

/** fetch-Attrappe: route(url, opts) → { status, body, headers } oder Body direkt; jede Abfrage landet in calls. */
function fakeFetch(route) {
  const calls = [];
  const fn = async (url, opts = {}) => {
    calls.push({ url, method: opts.method || 'GET', body: opts.body ? JSON.parse(opts.body) : null });
    let r = await route(url, opts);
    if (r instanceof Error) throw r;
    if (!r || r.status === undefined) r = { status: 200, body: r };
    const headers = r.headers || {};
    return { status: r.status, ok: r.status >= 200 && r.status < 300, headers: { get: (k) => headers[k.toLowerCase()] ?? null }, json: async () => r.body };
  };
  fn.calls = calls;
  return fn;
}

const temp = [];
function tmpDir(tag = 'vw') { const d = fs.mkdtempSync(path.join(os.tmpdir(), `hw-${tag}-`)); temp.push(d); return d; }
function cleanup() { for (const d of temp.splice(0)) fs.rmSync(d, { recursive: true, force: true }); }

/** NVD-Eintrag im Format der API 2.0 */
function nvdCve(id, { matches, vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', score = 7.5, text = 'A flaw.', modified = '2026-01-01T00:00:00.000', operator, extraNode } = {}) {
  const nodes = [{ operator: 'OR', negate: false, cpeMatch: matches.map((m) => ({ vulnerable: true, ...m })) }];
  if (extraNode) nodes.push(extraNode);
  return { cve: {
    id, published: '2021-10-05T09:15:07.593', lastModified: modified, vulnStatus: 'Analyzed',
    descriptions: [{ lang: 'en', value: text }, { lang: 'es', value: 'Un fallo.' }],
    metrics: { cvssMetricV31: [{ source: 'nvd@nist.gov', type: 'Primary', cvssData: { version: '3.1', vectorString: vector, baseScore: score } }] },
    weaknesses: [{ description: [{ lang: 'en', value: 'CWE-22' }] }],
    configurations: [{ operator, nodes }],
    references: [{ url: `https://example.org/${id}`, tags: ['Vendor Advisory'] }],
  } };
}

module.exports = { clock, fakeFetch, tmpDir, cleanup, nvdCve };
