'use strict';
/*
 * Versionen vergleichen und gegen betroffene Bereiche prüfen – ohne Hostwerk testbar.
 *
 *   clean('2.4.62-system')           → { upstream: '2.4.62', distro: 'system', raw }
 *   clean('2.4.62-1~deb12u2')        → { upstream: '2.4.62', distro: 'debian', raw }
 *   cmp('8.3.10', '8.3.9')           → 1   (Zahl für Zahl, nie als Text)
 *   osvAffected(affected, version)   → { hit, fixed, introduced }   (OSV: versions-Liste, SEMVER/ECOSYSTEM-Ereignisse)
 *   nvdMatch(configurations, prefixes, version) → { hit, fixed, conditional }   (NVD 2.0: cpeMatch mit versionStart/End)
 *
 * Distributions-Pakete (Debian, Ubuntu, Alpine, RHEL, „-system“ von Hostwerk) behalten die Upstream-Nummer, spielen aber
 * Sicherheits-Fixes nach – deshalb merkt sich clean() die Herkunft, damit die Oberfläche ehrlich „vielleicht schon behoben“ sagt.
 */

/** Upstream-Version und Herkunft aus einer installierten Versionsangabe. */
function clean(raw) {
  let s = String(raw == null ? '' : raw).trim();
  const out = { raw: s, upstream: '', distro: null };
  if (!s) return out;
  s = s.replace(/^[vV](?=\d)/, '');
  if (/-system$/i.test(s)) { out.distro = 'system'; s = s.replace(/-system$/i, ''); }
  // Epoche (Debian „1:10.11.6-0+deb12u1“)
  s = s.replace(/^\d+:(?=\d)/, '');
  const m = /^(\d+(?:\.\d+)*)(.*)$/.exec(s);
  if (!m) { out.upstream = s; return out; }
  const rest = m[2];
  if (/deb\d|\+deb|~deb|debian/i.test(rest)) out.distro = out.distro || 'debian';
  else if (/ubuntu/i.test(rest)) out.distro = out.distro || 'ubuntu';
  else if (/^-r\d+$/i.test(rest)) out.distro = out.distro || 'alpine';
  else if (/\.el\d|\.fc\d|\.amzn/i.test(rest)) out.distro = out.distro || 'rhel';
  else if (/pgdg/i.test(rest)) out.distro = out.distro || 'debian';
  if (out.distro) { out.upstream = m[1]; return out; }
  // Vorabversionen und Build-Angaben bleiben Teil der Version (1.0.0-rc1, 3.12.0b2, 7.2.4)
  out.upstream = (m[1] + rest).replace(/\+.*$/, '');
  return out;
}

/** Wie viele Zahlen-Teile hat die Version? „8.2“ → 2 (für „ungenau, nur Reihe bekannt“). */
const precision = (v) => (String(clean(v).upstream).match(/^\d+(?:\.\d+)*/) || [''])[0].split('.').filter(Boolean).length;

const PRE = /^(dev|alpha|a|beta|b|pre|preview|rc|c|snapshot|m|milestone|ea)$/i;
const POST = /^(post|p|pl|patch|sp|r|final|ga|release)$/i;

/** Version in Vergleichsteile zerlegen: Zahlen bleiben Zahlen, Wörter Vorab-/Nachtrags-Marken. */
function parts(v) {
  const s = String(v).toLowerCase().replace(/^v(?=\d)/, '').replace(/\+.*$/, '');
  const m = /^(\d+(?:\.\d+)*)(.*)$/.exec(s);
  if (!m) return { nums: [], tail: s ? [s] : [] };
  const nums = m[1].split('.').map(Number);
  const tail = m[2].replace(/^[-._~]/, '').split(/[-._~]|(?<=\d)(?=[a-z])|(?<=[a-z])(?=\d)/).filter(Boolean);
  return { nums, tail };
}

/** Rang eines Zusatzes: Vorabversion < (nichts) < Nachtrag. */
function tailRank(tail) {
  if (!tail.length) return 0;
  const w = tail[0];
  if (PRE.test(w)) return -1;
  if (POST.test(w) || /^\d+$/.test(w)) return 1;
  return -1; // unbekanntes Wort (z. B. „beta“-Varianten) – lieber als Vorabversion werten
}

/** Vergleich zweier Versionen: -1, 0, 1. Robust für 8.3.10 vs 8.3.9, 1.0.0-rc1 vs 1.0.0, 3.12.0b2 vs 3.12.0. */
function cmp(a, b) {
  const x = parts(a); const y = parts(b);
  const n = Math.max(x.nums.length, y.nums.length);
  for (let i = 0; i < n; i++) { const p = x.nums[i] || 0; const q = y.nums[i] || 0; if (p !== q) return p < q ? -1 : 1; }
  const rx = tailRank(x.tail); const ry = tailRank(y.tail);
  if (rx !== ry) return rx < ry ? -1 : 1;
  const m = Math.max(x.tail.length, y.tail.length);
  for (let i = 0; i < m; i++) {
    const p = x.tail[i]; const q = y.tail[i];
    if (p === undefined) return -1;
    if (q === undefined) return 1;
    if (p === q) continue;
    const pn = /^\d+$/.test(p); const qn = /^\d+$/.test(q);
    if (pn && qn) return Number(p) < Number(q) ? -1 : 1;
    if (pn !== qn) return pn ? 1 : -1;
    return p < q ? -1 : 1;
  }
  return 0;
}

/** Gleiche Version (8.3 = 8.3.0)? */
const same = (a, b) => cmp(a, b) === 0;

/**
 * OSV „affected“-Eintrag (nur dieses Paket) gegen eine Version prüfen.
 * Reihenfolge: ausdrückliche versions-Liste (am verlässlichsten), dann SEMVER/ECOSYSTEM-Bereiche. GIT-Bereiche lassen sich
 * ohne Commit nicht prüfen – sie zählen nur, wenn die versions-Liste die Version nennt.
 */
function osvAffected(affected, version) {
  const v = clean(version).upstream;
  const res = { hit: false, fixed: null, introduced: null };
  if (!affected || !v) return res;
  const list = Array.isArray(affected.versions) ? affected.versions : [];
  if (list.some((x) => same(clean(x).upstream, v))) res.hit = true;
  for (const r of Array.isArray(affected.ranges) ? affected.ranges : []) {
    if (!r || !['SEMVER', 'ECOSYSTEM'].includes(r.type)) continue;
    // Ereignisse nach Version sortiert abarbeiten: introduced öffnet, fixed/last_affected schließt
    const evs = (r.events || []).map((e) => {
      const [k, val] = Object.entries(e)[0] || [];
      return { k, val: k === 'introduced' && (val === '0' || val === 0) ? '0' : String(val || '') };
    }).filter((e) => e.k && e.val);
    let open = null;
    for (const e of evs) {
      if (e.k === 'introduced') { open = e.val; continue; }
      if (open == null) continue;
      const lo = open === '0' || cmp(v, open) >= 0;
      if (e.k === 'fixed' && lo && cmp(v, e.val) < 0) { res.hit = true; res.fixed = e.val; res.introduced = open; }
      if (e.k === 'last_affected' && lo && cmp(v, e.val) <= 0) { res.hit = true; res.introduced = open; }
      if (e.k === 'limit') continue; // nur für GIT-Bereiche
      open = null;
    }
    if (open != null && (open === '0' || cmp(v, open) >= 0)) { res.hit = true; res.introduced = open; } // noch ohne Fix
  }
  // Behobene Version für Treffer aus der versions-Liste: kleinste Fix-Version oberhalb der eigenen
  if (res.hit && !res.fixed) {
    const fixes = [];
    for (const r of affected.ranges || []) for (const e of r.events || []) if (e.fixed && cmp(e.fixed, v) > 0 && !/^[0-9a-f]{12,}$/i.test(e.fixed)) fixes.push(String(e.fixed));
    fixes.sort(cmp);
    res.fixed = fixes[0] || null;
  }
  return res;
}

/** CPE 2.3 zerlegen: cpe:2.3:a:apache:http_server:2.4.49:*:… → { part, vendor, product, version, update } */
function cpeParts(cpe) {
  const p = String(cpe || '').split(/(?<!\\):/);
  return { part: p[2], vendor: p[3], product: p[4], version: p[5], update: p[6] };
}

/** Ein cpeMatch-Eintrag gegen die eigene Version. */
function cpeMatchHit(m, version) {
  const c = cpeParts(m.criteria);
  const v = clean(version).upstream;
  if (c.version && c.version !== '*' && c.version !== '-') {
    // Feste Version im CPE (2.4.49), ggf. mit Update-Feld (5.3.0:rc1)
    const full = c.update && c.update !== '*' && c.update !== '-' ? `${c.version}-${c.update}` : c.version;
    return { hit: same(full.replace(/\\/g, ''), v), fixed: null };
  }
  if (c.version === '-') return { hit: false, fixed: null };
  const has = (k) => m[k] != null && m[k] !== '';
  if (!['versionStartIncluding', 'versionStartExcluding', 'versionEndIncluding', 'versionEndExcluding'].some(has)) return { hit: false, fixed: null }; // „alle Versionen“ ist zu ungenau
  if (has('versionStartIncluding') && cmp(v, m.versionStartIncluding) < 0) return { hit: false, fixed: null };
  if (has('versionStartExcluding') && cmp(v, m.versionStartExcluding) <= 0) return { hit: false, fixed: null };
  if (has('versionEndIncluding') && cmp(v, m.versionEndIncluding) > 0) return { hit: false, fixed: null };
  if (has('versionEndExcluding') && cmp(v, m.versionEndExcluding) >= 0) return { hit: false, fixed: null };
  return { hit: true, fixed: has('versionEndExcluding') ? String(m.versionEndExcluding) : null };
}

/**
 * NVD-Konfigurationen gegen ein Produkt prüfen. prefixes = ['cpe:2.3:a:apache:http_server'].
 * conditional = Treffer nur in einer UND-Verknüpfung (z. B. „nur auf Windows“ oder „nur zusammen mit Modul X“).
 */
function nvdMatch(configurations, prefixes, version) {
  const res = { hit: false, fixed: null, conditional: false };
  const ours = (crit) => prefixes.some((p) => String(crit || '').startsWith(`${p}:`));
  let plain = false;
  for (const conf of Array.isArray(configurations) ? configurations : []) {
    const nodes = conf.nodes || [];
    const and = String(conf.operator || '').toUpperCase() === 'AND' && nodes.length > 1;
    for (const node of nodes) {
      if (node.negate) continue;
      for (const m of node.cpeMatch || []) {
        if (!m.vulnerable || !ours(m.criteria)) continue;
        const r = cpeMatchHit(m, version);
        if (!r.hit) continue;
        res.hit = true;
        if (!and) plain = true;
        if (r.fixed && (!res.fixed || cmp(r.fixed, res.fixed) < 0)) res.fixed = r.fixed;
      }
    }
  }
  res.conditional = res.hit && !plain;
  return res;
}

module.exports = { clean, cmp, same, precision, osvAffected, cpeParts, cpeMatchHit, nvdMatch };
