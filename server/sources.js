'use strict';
/*
 * Die freien Quellen – alle ohne Schlüssel, alle mit Zwischenspeicher (store.js), alle gebündelt und gedrosselt (net.js):
 *   OSV.dev    POST /v1/querybatch (bis 500 Pakete je Abfrage) + GET /v1/vulns/<id> nur für neue/geänderte Einträge
 *   NVD 2.0    /rest/json/cves/2.0?virtualMatchString=<cpe> – je Produkt EINMAL alle CVEs (250 je Seite), danach nur
 *              Änderungen seit dem letzten Abruf (lastModStartDate); alle 30 Tage frisch von vorn (räumt Zurückgezogenes auf)
 *   CISA KEV   ein JSON-Feed mit allen bekannt ausgenutzten Lücken (einmal am Tag)
 *   FIRST EPSS /data/v1/epss?cve=a,b,… – Wahrscheinlichkeit der Ausnutzung in den nächsten 30 Tagen (gebündelt, einmal am Tag)
 * Jede Quelle merkt sich ihren Zustand ({ at, ok, error }) – fällt sie aus, gilt der letzte gute Stand weiter.
 */

const OSV = 'https://api.osv.dev/v1';
const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS = 'https://api.first.org/data/v1/epss';

const HOUR = 3600000;
const DAY = 24 * HOUR;
const FRESH = 20 * HOUR; // „einmal am Tag“ mit etwas Luft, damit der Tagesrhythmus nicht wandert
const NVD_FULL = 30 * DAY;
const NVD_MAX_RANGE = 120 * DAY; // NVD erlaubt höchstens 120 Tage je Änderungs-Abfrage
const NVD_PAGE = 250; // kleine Seiten: alte PHP-CVEs listen Hunderte Versionen – große Seiten brechen ohne Schlüssel oft ab
const MAX_DETAILS = 400; // OSV-Einzelabrufe je Lauf – der Rest folgt im nächsten
const TEXT = 3000;

const cut = (s, n = TEXT) => { const t = String(s || '').trim(); return t.length > n ? `${t.slice(0, n - 1)}…` : t; };
const slug = (prefix) => prefix.split(':').slice(3, 5).join('_');

/** NVD-Datum: 2026-10-21T08:00:00.000+00:00 (das „+“ kodiert URLSearchParams als %2B). */
const nvdDate = (t) => `${new Date(t).toISOString().slice(0, 23)}+00:00`;

/** NVD-Eintrag auf das Nötige kürzen. prefixes = CPE-Präfixe des Produkts (für die Konfigurationen). */
function reduceNvd(cve, prefixes) {
  const ours = (c) => prefixes.some((p) => String(c || '').startsWith(`${p}:`));
  const metrics = [];
  const m = cve.metrics || {};
  for (const [key, ver] of [['cvssMetricV40', '4.0'], ['cvssMetricV31', '3.1'], ['cvssMetricV30', '3.0'], ['cvssMetricV2', '2.0']]) {
    const list = Array.isArray(m[key]) ? m[key] : [];
    const pick = list.find((x) => x.type === 'Primary') || list[0];
    if (pick && pick.cvssData && pick.cvssData.vectorString) metrics.push({ version: ver, vector: pick.cvssData.vectorString, score: pick.cvssData.baseScore ?? null, source: pick.source || 'nvd' });
  }
  const others = new Set();
  const configurations = (cve.configurations || []).map((c) => ({
    operator: c.operator || null,
    nodes: (c.nodes || []).map((n) => {
      const mine = (n.cpeMatch || []).filter((x) => ours(x.criteria));
      if (!mine.length) for (const x of (n.cpeMatch || []).slice(0, 3)) { const p = String(x.criteria).split(':'); if (p[3] && p[4]) others.add(`${p[3]} ${p[4]}`.replace(/_/g, ' ')); }
      return { negate: !!n.negate, operator: n.operator || 'OR', cpeMatch: mine.map((x) => ({ vulnerable: !!x.vulnerable, criteria: x.criteria, versionStartIncluding: x.versionStartIncluding, versionStartExcluding: x.versionStartExcluding, versionEndIncluding: x.versionEndIncluding, versionEndExcluding: x.versionEndExcluding })) };
    }),
  }));
  const en = (cve.descriptions || []).find((d) => d.lang === 'en');
  return {
    id: cve.id, source: 'nvd', published: cve.published || null, modified: cve.lastModified || null, status: cve.vulnStatus || null,
    summary: null, details: cut(en && en.value), metrics, configurations, others: [...others].slice(0, 4),
    cwe: [...new Set((cve.weaknesses || []).flatMap((w) => (w.description || []).map((d) => d.value)).filter((x) => /^CWE-\d+$/.test(x)))].slice(0, 4),
    refs: (cve.references || []).slice(0, 10).map((r) => ({ url: r.url, tags: (r.tags || []).slice(0, 3) })),
  };
}

/** OSV-Eintrag kürzen – „affected“ nur für die abgefragten Pakete (keys = Set „ökosystem|name“). */
function reduceOsv(v, keys) {
  const sev = (v.severity || []).filter((s) => s && /^CVSS_V[234]$/.test(s.type) && s.score).map((s) => ({ version: s.type === 'CVSS_V4' ? '4.0' : s.type === 'CVSS_V2' ? '2.0' : null, vector: s.score, score: null, source: 'osv' }));
  const affected = (v.affected || []).filter((a) => a.package && (!keys || keys.has(`${a.package.ecosystem}|${a.package.name}`))).map((a) => ({
    package: { ecosystem: a.package.ecosystem, name: a.package.name },
    ranges: (a.ranges || []).filter((r) => r.type !== 'GIT').map((r) => ({ type: r.type, events: (r.events || []).slice(0, 60) })),
    versions: (a.versions || []).slice(-500),
  }));
  const ds = v.database_specific || {};
  return {
    id: v.id, source: 'osv', aliases: (v.aliases || []).slice(0, 8), published: v.published || null, modified: v.modified || null, withdrawn: v.withdrawn || null,
    summary: cut(v.summary, 300) || null, details: cut(v.details), metrics: sev, dbSeverity: ds.severity || null,
    cwe: (ds.cwe_ids || []).slice(0, 4), affected, refs: (v.references || []).slice(0, 10).map((r) => ({ url: r.url, tags: r.type ? [r.type] : [] })),
  };
}

class Sources {
  /** { net, store, now } */
  constructor({ net, store, now }) {
    this.net = net;
    this.store = store;
    this.now = now || (() => Date.now());
  }

  status() { return this.store.get('status', () => ({})); }
  mark(src, patch) {
    const s = { ...this.status() };
    s[src] = { ...(s[src] || {}), ...patch };
    this.store.set('status', s);
  }
  /** Fehler festhalten, letzten guten Stand behalten. */
  fail(src, e) { this.mark(src, { error: String((e && e.message) || e).slice(0, 300), offline: !!(e && e.code === 'HW_OFFLINE'), errorAt: this.now() }); }
  ok(src, extra = {}) { this.mark(src, { at: this.now(), error: null, offline: false, ...extra }); }

  /* ---------------- OSV ---------------- */
  osvKey(p) { return `${p.ecosystem}|${p.name}|${p.version}`; }
  osvIds(p) { const q = this.store.get('osv-queries', () => ({})); return (q[this.osvKey(p)] || {}).ids || null; }
  osvVuln(id) { return (this.store.get('osv-vulns', () => ({})))[id] || null; }

  /** Pakete abfragen (gebündelt), dann Details für neue oder geänderte Einträge holen. */
  async osvRefresh(pkgs, { force = false } = {}) {
    const now = this.now();
    const queries = { ...this.store.get('osv-queries', () => ({})) };
    const uniq = new Map();
    for (const p of pkgs) if (p && p.ecosystem && p.name && p.version) uniq.set(this.osvKey(p), p);
    const due = [...uniq.entries()].filter(([k]) => force || !queries[k] || now - queries[k].at > FRESH);
    const seen = new Map(); // id → modified
    try {
      for (let i = 0; i < due.length; i += 500) {
        const chunk = due.slice(i, i + 500);
        const r = await this.net.json(`${OSV}/querybatch`, { method: 'POST', body: { queries: chunk.map(([, p]) => ({ package: { ecosystem: p.ecosystem, name: p.name }, version: p.version })) } });
        const results = (r && r.results) || [];
        for (let j = 0; j < chunk.length; j++) {
          const [k, p] = chunk[j];
          const ids = [];
          let res = results[j] || {};
          for (let page = 0; page < 5; page++) {
            for (const v of res.vulns || []) { ids.push(v.id); seen.set(v.id, v.modified || null); }
            if (!res.next_page_token) break;
            const more = await this.net.json(`${OSV}/querybatch`, { method: 'POST', body: { queries: [{ package: { ecosystem: p.ecosystem, name: p.name }, version: p.version, page_token: res.next_page_token }] } });
            res = (more && more.results && more.results[0]) || {};
          }
          queries[k] = { at: now, ids: [...new Set(ids)] };
        }
        this.store.set('osv-queries', queries);
      }
      // Details: alles, was wir brauchen, aber noch nicht (oder veraltet) kennen
      const vulns = { ...this.store.get('osv-vulns', () => ({})) };
      const keys = new Set([...uniq.values()].map((p) => `${p.ecosystem}|${p.name}`));
      const want = new Set();
      for (const k of uniq.keys()) for (const id of (queries[k] || {}).ids || []) want.add(id);
      const todo = [...want].filter((id) => !vulns[id] || (seen.has(id) && seen.get(id) && seen.get(id) !== vulns[id].modified));
      let fetched = 0;
      for (const id of todo.slice(0, MAX_DETAILS)) {
        const v = await this.net.json(`${OSV}/vulns/${encodeURIComponent(id)}`);
        if (v) { vulns[id] = reduceOsv(v, keys); fetched++; }
        if (fetched % 50 === 0) this.store.set('osv-vulns', vulns);
      }
      this.store.set('osv-vulns', vulns);
      this.ok('osv', { packages: uniq.size, queried: due.length, details: fetched, pending: Math.max(0, todo.length - MAX_DETAILS) });
    } catch (e) { this.store.set('osv-queries', queries); this.fail('osv', e); }
  }

  /** Einzelnen OSV-Eintrag sicherstellen (z. B. Log4Shell für Minecraft). */
  async osvEnsure(ids) {
    const vulns = { ...this.store.get('osv-vulns', () => ({})) };
    const missing = ids.filter((id) => !vulns[id]);
    if (!missing.length) return;
    try {
      for (const id of missing) { const v = await this.net.json(`${OSV}/vulns/${encodeURIComponent(id)}`); if (v) vulns[id] = reduceOsv(v, null); }
      this.store.set('osv-vulns', vulns);
    } catch (e) { this.fail('osv', e); }
  }

  /* ---------------- NVD ---------------- */
  nvdCache(prefix) { return this.store.get(`nvd-${slug(prefix)}`, () => ({ at: null, fullAt: null, cves: {} })); }

  /** Alle CVEs eines Produkts: voll (selten) oder nur Änderungen seit dem letzten Abruf. */
  async nvdRefresh(prefix, prefixes, { force = false } = {}) {
    const now = this.now();
    const c = this.nvdCache(prefix);
    const full = !c.fullAt || now - c.fullAt > NVD_FULL || !c.at || now - c.at > NVD_MAX_RANGE - DAY;
    if (!full && !force && now - c.at < FRESH) return { skipped: true };
    const params = { virtualMatchString: prefix };
    if (!full) Object.assign(params, { lastModStartDate: nvdDate(c.at - HOUR), lastModEndDate: nvdDate(now) });
    const cves = full ? {} : { ...c.cves };
    let start = 0; let total = 0; let got = 0;
    do {
      const qs = `${new URLSearchParams({ ...params, resultsPerPage: String(NVD_PAGE), startIndex: String(start) })}&noRejected`; // Schalter ohne Wert
      const r = await this.net.json(`${NVD}?${qs}`);
      if (!r) break;
      total = r.totalResults || 0;
      for (const v of r.vulnerabilities || []) { if (v && v.cve && v.cve.id) { cves[v.cve.id] = reduceNvd(v.cve, prefixes); got++; } }
      start += r.resultsPerPage || NVD_PAGE;
    } while (start < total);
    const next = { at: now, fullAt: full ? now : c.fullAt, cves };
    this.store.set(`nvd-${slug(prefix)}`, next);
    return { full, got, total: Object.keys(cves).length };
  }

  /** Alle gebrauchten Produkte nacheinander (gedrosselt). products = [{ prefixes }]. */
  async nvdRefreshAll(products, opts = {}) {
    const done = [];
    const failed = [];
    let stop = null;
    for (const p of products) {
      for (const prefix of p.prefixes) {
        if (stop) { failed.push(prefix); continue; }
        try { done.push({ prefix, ...(await this.nvdRefresh(prefix, p.prefixes, opts)) }); } catch (e) {
          failed.push(prefix);
          // Abfragelimit oder Offline: die übrigen Produkte gar nicht erst versuchen; sonst (Zeitüberschreitung …) weiter
          if (e && (e.code === 'RATE_LIMIT' || e.code === 'HW_OFFLINE')) stop = e;
          else this.fail('nvd', Object.assign(new Error(`${prefix.split(':').slice(3, 5).join(' ')}: ${e.message}`), { code: e.code }));
        }
      }
    }
    if (stop) this.fail('nvd', stop);
    else if (!failed.length) this.ok('nvd', { products: products.length });
    else if (done.length) this.mark('nvd', { at: this.now(), failed: failed.length }); // Teilerfolg: Fehler bleibt sichtbar
    return done;
  }

  /** Alle CVEs eines Produkts aus dem Speicher (alle Präfixe zusammen). */
  nvdCves(prefixes) {
    const out = new Map();
    for (const p of prefixes) for (const [id, v] of Object.entries(this.nvdCache(p).cves || {})) if (!out.has(id)) out.set(id, v);
    return [...out.values()];
  }

  /* ---------------- CISA KEV ---------------- */
  kev() { return this.store.get('kev', () => ({ at: null, items: {} })); }
  async kevRefresh({ force = false } = {}) {
    const c = this.kev();
    if (!force && c.at && this.now() - c.at < FRESH) return;
    try {
      const r = await this.net.json(KEV);
      if (!r || !Array.isArray(r.vulnerabilities)) throw new Error('KEV feed has an unexpected format');
      const items = {};
      for (const v of r.vulnerabilities) if (v && v.cveID) items[v.cveID] = { added: v.dateAdded || null, due: v.dueDate || null, ransomware: v.knownRansomwareCampaignUse === 'Known', name: cut(v.vulnerabilityName, 200), action: cut(v.requiredAction, 300) };
      this.store.set('kev', { at: this.now(), version: r.catalogVersion || null, items });
      this.ok('kev', { count: Object.keys(items).length });
    } catch (e) { this.fail('kev', e); }
  }

  /* ---------------- FIRST EPSS ---------------- */
  epss() { return this.store.get('epss', () => ({ items: {} })); }
  async epssRefresh(cves, { force = false } = {}) {
    const now = this.now();
    const c = this.epss();
    const items = { ...c.items };
    const due = [...new Set(cves)].filter((id) => /^CVE-\d{4}-\d+$/.test(id) && (force || !items[id] || now - items[id].at > FRESH));
    try {
      for (let i = 0; i < due.length; i += 80) {
        const chunk = due.slice(i, i + 80);
        const r = await this.net.json(`${EPSS}?cve=${chunk.join(',')}`);
        const got = new Set();
        for (const d of (r && r.data) || []) { items[d.cve] = { epss: Number(d.epss), pct: Number(d.percentile), date: d.date || null, at: now }; got.add(d.cve); }
        for (const id of chunk) if (!got.has(id)) items[id] = { epss: null, pct: null, date: null, at: now }; // EPSS kennt (noch) keinen Wert
      }
      this.store.set('epss', { items });
      if (due.length || !this.status().epss) this.ok('epss', { count: Object.keys(items).length });
    } catch (e) { this.store.set('epss', { items }); this.fail('epss', e); }
  }
}

module.exports = { Sources, reduceNvd, reduceOsv, nvdDate, URLS: { OSV, NVD, KEV, EPSS }, FRESH };
