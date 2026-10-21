'use strict';
/*
 * CVSS lesen, rechnen und in Worte fassen – ohne Hostwerk testbar.
 *
 *   parse('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H') → { version: '3.1', metrics: { AV: 'N', … } }
 *   score3(metrics, '3.1')                                → 9.8 (Basiswert nach der FIRST-Formel, auch für 3.0)
 *   level(9.8)                                            → 'critical' (kritisch ≥ 9 · hoch ≥ 7 · mittel ≥ 4 · niedrig > 0)
 *   explain(parsed)                                       → [{ key, label, value, risk: 'high'|'mid'|'low' }] – Texte englisch,
 *                                                           Deutsch aus locales/de.json (host.t bzw. t in der Oberfläche)
 * CVSS 4.0: Den Basiswert liefert die Quelle (NVD); lokal lässt er sich nur mit der großen Tabelle der FIRST-Spezifikation
 * berechnen – die steckt hier bewusst nicht drin. Fehlt der Wert, zählt die Stufe aus der Quelle (z. B. „HIGH“).
 */

/** Vektor zerlegen. Ohne Präfix (alte NVD-v2-Vektoren „AV:N/AC:L/Au:N/…“) gilt Version 2.0. */
function parse(vector) {
  const s = String(vector || '').trim();
  if (!s) return null;
  const m = /^CVSS:(\d\.\d)\/(.*)$/.exec(s);
  const version = m ? m[1] : (/\bAu:[MSN]\b/.test(s) ? '2.0' : null);
  if (!version) return null;
  const metrics = {};
  for (const part of (m ? m[2] : s).split('/')) { const [k, v] = part.split(':'); if (k && v) metrics[k] = v; }
  return { version, vector: s, metrics };
}

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
};

/** Aufrunden auf eine Stelle (CVSS 3.1: ohne Gleitkomma-Fehler; 3.0: einfaches Aufrunden). */
function roundup(x, version) {
  if (version === '3.0') return Math.ceil(x * 10) / 10;
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

/** Basiswert CVSS 3.0/3.1 – null, wenn ein Pflichtwert fehlt. */
function score3(m, version = '3.1') {
  const need = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
  if (!m || need.some((k) => !m[k])) return null;
  const changed = m.S === 'C';
  const pr = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR];
  const av = W.AV[m.AV]; const ac = W.AC[m.AC]; const ui = W.UI[m.UI];
  const c = W.CIA[m.C]; const i = W.CIA[m.I]; const a = W.CIA[m.A];
  if ([pr, av, ac, ui, c, i, a].some((x) => x === undefined)) return null;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  const expl = 8.22 * av * ac * pr * ui;
  if (impact <= 0) return 0;
  return changed ? roundup(Math.min(1.08 * (impact + expl), 10), version) : roundup(Math.min(impact + expl, 10), version);
}

/** Stufe zu einem Basiswert. */
function level(score) {
  if (score == null || Number.isNaN(Number(score))) return 'unknown';
  const s = Number(score);
  if (s >= 9) return 'critical';
  if (s >= 7) return 'high';
  if (s >= 4) return 'medium';
  if (s > 0) return 'low';
  return 'none';
}

/** Stufe aus einer Textangabe der Quelle (GHSA „HIGH“, „MODERATE“ …). */
function levelFromText(t) {
  const s = String(t || '').toUpperCase();
  if (s === 'CRITICAL') return 'critical';
  if (s === 'HIGH') return 'high';
  if (s === 'MODERATE' || s === 'MEDIUM') return 'medium';
  if (s === 'LOW') return 'low';
  return 'unknown';
}

/*
 * Erklärungen je Merkmal: [Bezeichnung, { Wert: [Text, Risiko] }]. Risiko „high“ = macht es gefährlicher.
 * Die Texte sind Englisch (Quelltext) – Deutsch steht in locales/de.json.
 */
const EXPLAIN = {
  AV: ['Attack vector', { N: ['Over the network – also from the internet', 'high'], A: ['Only from the same network (LAN, Wi-Fi)', 'mid'], L: ['Only with access to this computer', 'low'], P: ['Only with physical access to the device', 'low'] }],
  AC: ['Attack complexity', { L: ['Easy – no special conditions needed', 'high'], H: ['Hard – needs special conditions', 'low'] }],
  AT: ['Attack requirements', { N: ['None', 'high'], P: ['Only under certain circumstances (e.g. a race)', 'low'] }],
  PR: ['Login needed', { N: ['No – anyone can try', 'high'], L: ['Yes – a normal user account', 'mid'], H: ['Yes – an administrator account', 'low'] }],
  UI: ['Someone has to help', { N: ['No – works without anyone clicking', 'high'], R: ['Yes – someone has to open or click something', 'low'], P: ['Yes – someone has to take part actively', 'low'], A: ['Yes – someone has to do something deliberately', 'low'] }],
  S: ['Reaches beyond the program', { U: ['No – stays within the affected program', 'low'], C: ['Yes – can affect other parts of the system', 'high'] }],
  C: ['Confidentiality', { H: ['Data can be read completely', 'high'], L: ['Some data can be read', 'mid'], N: ['No data is revealed', 'low'] }],
  I: ['Integrity', { H: ['Data can be changed at will', 'high'], L: ['Some data can be changed', 'mid'], N: ['Nothing can be changed', 'low'] }],
  A: ['Availability', { H: ['The service can be stopped completely', 'high'], L: ['The service can be slowed down', 'mid'], N: ['The service keeps running', 'low'] }],
  VC: ['Confidentiality', { H: ['Data can be read completely', 'high'], L: ['Some data can be read', 'mid'], N: ['No data is revealed', 'low'] }],
  VI: ['Integrity', { H: ['Data can be changed at will', 'high'], L: ['Some data can be changed', 'mid'], N: ['Nothing can be changed', 'low'] }],
  VA: ['Availability', { H: ['The service can be stopped completely', 'high'], L: ['The service can be slowed down', 'mid'], N: ['The service keeps running', 'low'] }],
  SC: ['Other systems: confidentiality', { H: ['Data of other systems can be read', 'high'], L: ['Some data of other systems can be read', 'mid'], N: ['Other systems stay unaffected', 'low'] }],
  SI: ['Other systems: integrity', { H: ['Other systems can be changed', 'high'], L: ['Other systems can be changed a little', 'mid'], N: ['Other systems stay unaffected', 'low'] }],
  SA: ['Other systems: availability', { H: ['Other systems can be stopped', 'high'], L: ['Other systems can be slowed down', 'mid'], N: ['Other systems stay unaffected', 'low'] }],
  // CVSS 2 (alte Einträge)
  Au: ['Login needed', { N: ['No – anyone can try', 'high'], S: ['Yes – one login', 'mid'], M: ['Yes – several logins', 'low'] }],
};
const V2_CIA = { N: ['None', 'low'], P: ['Partly', 'mid'], C: ['Completely', 'high'] };
const V2_LABEL = { C: 'Confidentiality', I: 'Integrity', A: 'Availability' };
const V2_AC = { L: ['Easy – no special conditions needed', 'high'], M: ['Medium – needs some conditions', 'mid'], H: ['Hard – needs special conditions', 'low'] };
const ORDER = ['AV', 'AC', 'AT', 'PR', 'Au', 'UI', 'S', 'C', 'I', 'A', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'];

/** Merkmale in Worten. t = Übersetzer (text) → text; ohne t bleiben die Texte englisch. */
function explain(p, t = (s) => s) {
  if (!p || !p.metrics) return [];
  const out = [];
  for (const k of ORDER) {
    const v = p.metrics[k];
    if (!v) continue;
    let label; let pair;
    if (p.version === '2.0' && ['C', 'I', 'A'].includes(k)) { label = V2_LABEL[k]; pair = V2_CIA[v]; }
    else if (p.version === '2.0' && k === 'AC') { label = EXPLAIN.AC[0]; pair = V2_AC[v]; }
    else if (EXPLAIN[k]) { label = EXPLAIN[k][0]; pair = EXPLAIN[k][1][v]; }
    if (!label || !pair) continue;
    out.push({ key: k, code: `${k}:${v}`, label: t(label), value: t(pair[0]), risk: pair[1] });
  }
  return out;
}

/** Netz-Angriff ohne Anmeldung und ohne Mithilfe? (für „Betrifft mich das?“ und die Kurzfassung) */
function remoteNoAuth(p) {
  if (!p || !p.metrics) return false;
  const m = p.metrics;
  return m.AV === 'N' && (m.PR === 'N' || m.Au === 'N') && (m.UI === 'N' || m.UI == null);
}

/**
 * Bestes CVSS aus mehreren Angaben wählen: { version, vector, score, level, source }.
 * Vorrang: 4.0 mit Wert > 3.1 > 3.0 > 4.0 ohne Wert > 2.0. Fehlt der Wert bei 3.x, wird er berechnet.
 */
function best(list) {
  const rank = (x) => (x.version === '4.0' && x.score != null ? 5 : x.version === '3.1' ? 4 : x.version === '3.0' ? 3 : x.version === '4.0' ? 2 : 1);
  const norm = (list || []).map((x) => {
    const p = parse(x.vector);
    if (!p) return null;
    let score = x.score != null && !Number.isNaN(Number(x.score)) ? Number(x.score) : null;
    if (score == null && p.version.startsWith('3')) score = score3(p.metrics, p.version);
    return { version: p.version, vector: p.vector, score, level: score != null ? level(score) : 'unknown', source: x.source || null };
  }).filter(Boolean);
  norm.sort((a, b) => rank(b) - rank(a));
  return norm[0] || null;
}

module.exports = { parse, score3, roundup, level, levelFromText, explain, remoteNoAuth, best, EXPLAIN };
