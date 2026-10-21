'use strict';
/*
 * Bestand + Quellen → Funde. Ohne Netz und ohne Hostwerk testbar (alles kommt als Daten herein).
 *
 *   assess({ items, src, kev, epss, eol, pending, ignores, platform, now }) → { findings, counts, overall, unchecked }
 *
 * Ein Fund je (Dienst × Schwachstelle); dieselbe Lücke aus OSV (GHSA-…) und NVD (CVE-…) wird über die CVE-Nummer
 * zusammengelegt. Dazu kommen „Lebensende“-Funde aus Hostwerks Lebensende-Wache. „Betrifft mich das?“-Hinweise nur dort,
 * wo sie sich ehrlich ableiten lassen (Codes in hints – die Texte stehen in texts.js).
 */
const { PRODUCTS, MC_LOG4SHELL } = require('./catalog');
const { cmp, osvAffected, nvdMatch } = require('./version');
const C = require('./cvss');

const RANK = { critical: 4, high: 3, medium: 2, low: 1, none: 0, unknown: 0 };
const CVE_RE = /^CVE-\d{4}-\d+$/;

/** Titel: Zusammenfassung oder der erste Satz der Beschreibung. */
function titleOf(v) {
  if (v.summary) return v.summary;
  const d = String(v.details || '').replace(/\s+/g, ' ').trim();
  const m = /^(.{20,200}?[.!?])(\s|$)/.exec(d);
  return m ? m[1] : d.slice(0, 160);
}

/** Lebensende-Stand → Stufe. */
const EOL_LEVEL = { eol: 'high', soon: 'medium' };

function hintsFor(item, v, ctx) {
  const h = [];
  const cv = ctx.cvss;
  const p = cv ? C.parse(cv.vector) : null;
  const text = `${v.summary || ''} ${v.details || ''}`;
  if (item.exposure && item.exposure.local && p && p.metrics.AV === 'N') h.push({ code: 'local-only' });
  if (item.ver && item.ver.distro) h.push({ code: 'distro', distro: item.ver.distro });
  if (ctx.conditional) h.push({ code: 'conditional', others: v.others || [] });
  if (item.product === 'apache' && Array.isArray(item.modules)) {
    const mods = [...new Set([...text.matchAll(/\bmod_([a-z][a-z0-9_]+)\b/gi)].map((m) => m[1].toLowerCase()))];
    if (mods.length) {
      const on = mods.filter((m) => item.modules.includes(m));
      h.push(on.length ? { code: 'module-on', module: `mod_${on[0]}` } : { code: 'module-off', module: `mod_${mods[0]}` });
    }
  }
  const win = /\b(on|for) (Microsoft )?Windows\b|\bWindows (systems|platforms|hosts|only|installations)\b/i.test(text);
  const mac = /\bon macOS\b/i.test(text);
  if (win && !/\b(Linux|Unix|macOS)\b/i.test(text) && ctx.platform && ctx.platform !== 'win32') h.push({ code: 'other-os', os: 'Windows' });
  if (mac && !win && ctx.platform && ctx.platform !== 'darwin') h.push({ code: 'other-os', os: 'macOS' });
  if (ctx.pkg && ctx.pkg.dev) h.push({ code: 'dev-only' });
  if (item.external) h.push({ code: 'external' });
  return h;
}

/** Weg zur Behebung: Hostwerk spielt selbst ein (patch), Hostwerk-Update (app), von Hand (manual) oder (noch) keiner. */
function fixFor(item, fixed, pending, pkg) {
  if (pkg) return { kind: fixed ? 'manual' : 'none', to: fixed || null, href: item.href, tool: pkg.ecosystem };
  if (item.appUpdate) return { kind: 'app', to: fixed || null, href: '#/settings/updates' };
  const u = item.updateKey ? (pending || []).find((x) => x.key === item.updateKey) : null;
  if (u && !u.skipped && (!fixed || cmp(u.latest, fixed) >= 0)) return { kind: 'patch', key: u.key, to: u.latest, href: item.href };
  if (fixed) return { kind: 'manual', to: fixed, href: item.href, series: !!(u && cmp(u.latest, fixed) < 0) };
  return { kind: 'none', to: null, href: item.href };
}

/** Alle Kandidaten (OSV + NVD + Regeln) für einen Dienst. */
function candidates(item, src) {
  const out = [];
  const p = item.product ? PRODUCTS[item.product] : null;
  const version = item.ver.upstream;
  if (item.packages) {
    for (const pkg of item.packages) {
      for (const id of src.osvIds(pkg) || []) {
        const v = src.osvVuln(id);
        if (!v || v.withdrawn) continue;
        const aff = (v.affected || []).find((a) => a.package && a.package.ecosystem === pkg.ecosystem && a.package.name === pkg.name);
        const r = aff ? osvAffected(aff, pkg.version) : { fixed: null };
        out.push({ v, fixed: r.fixed, introduced: r.introduced || null, pkg });
      }
    }
    return out;
  }
  if (!p || item.why) return out;
  if (p.osv) {
    for (const id of src.osvIds({ ...p.osv, version }) || []) {
      const v = src.osvVuln(id);
      if (!v || v.withdrawn) continue;
      const aff = (v.affected || []).find((a) => a.package && a.package.ecosystem === p.osv.ecosystem && a.package.name === p.osv.name);
      const r = aff ? osvAffected(aff, version) : { fixed: null };
      out.push({ v, fixed: r.fixed, introduced: r.introduced || null });
    }
  }
  if (p.nvd) {
    for (const v of src.nvdCves(p.nvd)) {
      const r = nvdMatch(v.configurations, p.nvd, version);
      if (r.hit) out.push({ v, fixed: r.fixed, conditional: r.conditional });
    }
  }
  if (item.product === 'minecraft' && cmp(version, MC_LOG4SHELL.from) >= 0 && cmp(version, MC_LOG4SHELL.to) <= 0) {
    const v = src.osvVuln(MC_LOG4SHELL.id) || { id: MC_LOG4SHELL.id, source: 'osv', aliases: [MC_LOG4SHELL.cve], summary: 'Remote code execution in Log4j 2 (Log4Shell)', details: '', metrics: [{ version: '3.1', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', score: 10, source: 'nvd' }], refs: [] };
    out.push({ v, fixed: MC_LOG4SHELL.fixed, rule: 'mc-log4shell' });
  }
  return out;
}

function assess({ items, src, kev = {}, epss = {}, eol = null, pending = [], ignores = {}, platform = null, now = Date.now(), seen = {} }) {
  const findings = [];
  const unchecked = [];
  for (const item of items) {
    if (item.why && !item.packages) unchecked.push({ id: item.id, name: item.name, version: item.version || null, why: item.why, area: item.area, kind: item.kind });
    // Zusammenlegen je CVE (oder Eintrags-Id, wenn es keine CVE gibt) – je Paket getrennt
    const merged = new Map();
    for (const c of candidates(item, src)) {
      const cve = CVE_RE.test(c.v.id) ? c.v.id : (c.v.aliases || []).find((a) => CVE_RE.test(a)) || null;
      const k = `${c.pkg ? `${c.pkg.ecosystem}|${c.pkg.name}|${c.pkg.version}|` : ''}${cve || c.v.id}`;
      const cur = merged.get(k);
      if (!cur) { merged.set(k, { ...c, cve, ids: [c.v.id], recs: [c.v] }); continue; }
      cur.ids.push(c.v.id); cur.recs.push(c.v);
      if (c.fixed && (!cur.fixed || cmp(c.fixed, cur.fixed) < 0)) cur.fixed = c.fixed;
      if (c.conditional === false) cur.conditional = false;
    }
    for (const [k, c] of merged) {
      const recs = c.recs;
      const metrics = recs.flatMap((r) => r.metrics || []);
      const cvss = C.best(metrics);
      const dbLevel = recs.map((r) => C.levelFromText(r.dbSeverity)).find((x) => x !== 'unknown') || 'unknown';
      const level = cvss && cvss.level !== 'unknown' ? cvss.level : dbLevel;
      // Text: OSV-Zusammenfassung ist meist kürzer und klarer, NVD-Beschreibung ausführlicher
      const osv = recs.find((r) => r.source === 'osv');
      const nvd = recs.find((r) => r.source === 'nvd');
      const main = osv || nvd;
      const k2 = c.cve && kev[c.cve] ? kev[c.cve] : null;
      const ep = c.cve && epss[c.cve] && epss[c.cve].epss != null ? epss[c.cve] : null;
      const key = `${item.id}|${k}`;
      const ign = ignores[key];
      const ignored = ign && (!ign.until || ign.until > now) ? ign : null;
      const hints = hintsFor(item, { ...main, details: [osv && osv.details, nvd && nvd.details].filter(Boolean).join(' '), others: (nvd && nvd.others) || [] }, { cvss, conditional: c.conditional, platform, pkg: c.pkg });
      if (c.rule === 'mc-log4shell') hints.push({ code: ['paper', 'spigot', 'purpur', 'folia'].includes(item.flavor) ? 'mc-patched-builds' : 'mc-vanilla' });
      findings.push({
        key, kind: 'vuln', item: item.id, area: item.area, itemKind: item.kind, itemName: item.name, product: item.product, version: item.version || null,
        pkg: c.pkg ? { ecosystem: c.pkg.ecosystem, name: c.pkg.name, version: c.pkg.version, dev: !!c.pkg.dev, file: c.pkg.file } : null,
        id: c.cve || c.v.id, cve: c.cve, ids: [...new Set([c.cve, ...c.ids].filter(Boolean))],
        title: titleOf(main), summary: (osv && osv.summary) || null, details: (nvd && nvd.details) || (osv && osv.details) || '',
        published: (nvd && nvd.published) || (osv && osv.published) || null, modified: [nvd && nvd.modified, osv && osv.modified].filter(Boolean).sort().pop() || null,
        level, score: cvss ? cvss.score : null, vector: cvss ? cvss.vector : null, cvssVersion: cvss ? cvss.version : null,
        cwe: [...new Set(recs.flatMap((r) => r.cwe || []))].slice(0, 4),
        kev: k2, epss: ep ? { epss: ep.epss, pct: ep.pct, date: ep.date } : null,
        fixed: c.fixed || null, introduced: c.introduced || null,
        fix: fixFor(item, c.fixed, pending, c.pkg),
        hints, sources: [...new Set(recs.map((r) => r.source))],
        refs: [...new Map(recs.flatMap((r) => r.refs || []).map((r) => [r.url, r])).values()].slice(0, 12),
        ignored: ignored ? { reason: ignored.reason || '', until: ignored.until || null, at: ignored.at || null } : null,
        expiredIgnore: !!(ign && !ignored),
        firstSeen: seen[key] || now,
      });
    }
    // Lebensende (Hostwerks eigene Wache, endoflife.date)
    const p = item.product ? PRODUCTS[item.product] : null;
    if (eol && p && p.eol && item.version) {
      let info = null;
      try { info = eol(p.eol, item.ver.upstream || item.version); } catch { /* unbekannt */ }
      if (info && EOL_LEVEL[info.state]) {
        const key = `${item.id}|eol`;
        const ign = ignores[key];
        const ignored = ign && (!ign.until || ign.until > now) ? ign : null;
        findings.push({
          key, kind: 'eol', item: item.id, area: item.area, itemKind: item.kind, itemName: item.name, product: item.product, version: item.version,
          id: 'EOL', cve: null, ids: [], title: null, details: '', level: EOL_LEVEL[info.state], score: null, vector: null,
          eol: { state: info.state, eolAt: info.eolAt || null, daysLeft: info.daysLeft ?? null, cycle: info.cycle || null, recommended: info.recommended || null, label: info.label || null },
          kev: null, epss: null, fixed: null, fix: { kind: item.appUpdate ? 'app' : 'manual', to: info.recommended || null, href: item.appUpdate ? '#/settings/updates' : item.href },
          hints: item.external ? [{ code: 'external' }] : [], sources: ['endoflife.date'], refs: [], ignored: ignored ? { reason: ignored.reason || '', until: ignored.until || null, at: ignored.at || null } : null,
          expiredIgnore: !!(ign && !ignored), firstSeen: seen[key] || now,
        });
      }
    }
  }
  // Ordnung: ausgenutzt zuerst, dann Stufe, Wert, EPSS
  findings.sort((a, b) => (b.kev ? 1 : 0) - (a.kev ? 1 : 0) || RANK[b.level] - RANK[a.level] || (b.score || 0) - (a.score || 0) || ((b.epss && b.epss.epss) || 0) - ((a.epss && a.epss.epss) || 0) || String(a.id).localeCompare(String(b.id)));
  return { findings, unchecked, ...summarize(findings) };
}

/** Zahlen je Stufe (ohne Ausnahmen) und Ampel. */
function summarize(findings) {
  const active = findings.filter((f) => !f.ignored);
  const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, kev: 0, eol: 0, fixable: 0, ignored: findings.length - active.length, total: active.length };
  for (const f of active) {
    if (f.kind === 'eol') counts.eol++;
    else counts[f.level in counts ? f.level : 'unknown']++;
    if (f.kev) counts.kev++;
    if (f.fix && f.fix.kind === 'patch') counts.fixable++;
  }
  // Ampel: die schwerste offene Sache zählt; „wird ausgenutzt“ ist immer kritisch, Unbekanntes mindestens „niedrig“
  const top = Math.max(0, ...active.map((f) => RANK[f.level] || (f.level === 'unknown' ? 1 : 0)));
  const overall = counts.kev ? 'critical' : ['ok', 'low', 'medium', 'high', 'critical'][top];
  return { counts, overall };
}

module.exports = { assess, summarize, candidates, hintsFor, fixFor, titleOf, RANK };
