'use strict';
/*
 * Schwachstellen-Wache – Server-Teil (native Erweiterung, läuft als Teil von Hostwerk).
 *   GET    /api/vuln-watch              → { at, running, overall, counts, findings (ohne Langtext), unchecked, inventory, sources, settings }
 *   POST   /api/vuln-watch/refresh      → jetzt prüfen (Quellen nur, wenn fällig; force: true holt alles neu)
 *   GET    /api/vuln-watch/detail?key=  → ein Fund mit Beschreibung und Links
 *   PUT    /api/vuln-watch/ignore       → { key, reason, until } Ausnahme setzen · DELETE …/ignore?key= aufheben
 *   POST   /api/vuln-watch/update       → { key } Sicherheits-Update über Hostwerk einspielen (patchUpdates.apply), dann neu prüfen
 *   GET    /api/vuln-watch/ai           → { ready } · POST /api/vuln-watch/ai { key } → { text } KI-Kurzfassung in der Oberflächensprache
 * Täglich im Hintergrund: Bestand ermitteln (inventory.js), Quellen nachfragen (sources.js – OSV, NVD, CISA KEV, FIRST EPSS,
 * gedrosselt und zwischengespeichert), bewerten (assess.js), neue kritische oder ausgenutzte Funde gebündelt melden.
 * Offline-Modus: keine Abfragen, der letzte Stand bleibt sichtbar. Daten: data/vuln-watch/
 */
const path = require('path');
const { Store } = require('./store');
const { Net } = require('./net');
const { Sources } = require('./sources');
const { collect } = require('./inventory');
const { assess, summarize } = require('./assess');
const { PRODUCTS, MC_LOG4SHELL } = require('./catalog');
const { LEVEL_LABEL } = require('./texts');

const HOUR = 3600000;
const DUE = 20 * HOUR;

/** Liste für die Oberfläche: ohne Langtext und Links (die kommen über /detail). */
const slim = (f) => { const { details: _d, refs: _r, ...rest } = f; return rest; }; // eslint-disable-line no-unused-vars

/** io (Tests): { fetch, now, sleep, offline, collect, platform } */
function createService(host, io = {}) {
  const { ctx } = host;
  const now = io.now || (() => Date.now());
  const store = new Store(path.join(ctx.paths.data, 'vuln-watch'));
  const offline = io.offline || (() => { try { return host.core('download').isOffline(); } catch { return false; } });
  const net = new Net({ fetch: io.fetch, now, sleep: io.sleep, offline });
  const src = new Sources({ net, store, now });
  const settings = () => {
    let s = {};
    try { s = ctx.extMarket.settingsFor(host.id) || {}; } catch { /* Standard */ }
    return { notify: s.notify !== false, projects: s.projects !== false, notifyHigh: s.notifyHigh === true };
  };
  const state = () => store.get('state', () => ({ at: null, findings: [], unchecked: [], counts: null, overall: null, notified: {}, seen: {} }));
  const ignores = () => store.get('ignores', () => ({}));

  // Eigener Benachrichtigungs-Anlass (SDK 2.10, Hostwerk 2.12+) – sonst direkt über den Monitor
  let ownEvent = false;
  try { if (host.notifications && typeof host.notifications.register === 'function') { host.notifications.register('new-findings', { de: 'Neue kritische oder ausgenutzte Schwachstellen', en: 'New critical or exploited vulnerabilities' }, { on: true }); ownEvent = true; } } catch { /* ältere Hostwerk-Version */ }

  const ownVersions = () => ({ node: process.versions.node, electron: process.versions.electron || null });
  const pending = () => { try { return (ctx.patchUpdates && ctx.patchUpdates.pending) || []; } catch { return []; } };
  const eolInfo = () => (ctx.eol && typeof ctx.eol.info === 'function' ? (p, v) => ctx.eol.info(p, v) : null);
  const platform = io.platform || process.platform;

  /** Bewerten aus Bestand + Zwischenspeicher (ohne Netz). */
  const evaluate = (items) => {
    const st = state();
    const kev = src.kev().items || {};
    const epss = src.epss().items || {};
    return assess({ items, src, kev, epss, eol: eolInfo(), pending: pending(), ignores: ignores(), platform, now: now(), seen: st.seen || {} });
  };

  /** Neue kritische/ausgenutzte Funde gebündelt melden – jeder Fund nur einmal. */
  const alert = (fresh) => {
    if (!fresh.length) return;
    const kevN = fresh.filter((f) => f.kev).length;
    const title = kevN
      ? host.t('{n} actively exploited vulnerabilities in your services', { n: kevN })
      : host.t('{n} new critical vulnerabilities in your services', { n: fresh.length });
    const lines = fresh.slice(0, 6).map((f) => `• ${f.itemName}${f.pkg ? ` (${f.pkg.name} ${f.pkg.version})` : ''}: ${f.id}${f.score != null ? ` ${f.score}` : ''}${f.kev ? ` – ${host.t('actively exploited')}` : ''}`);
    if (fresh.length > 6) lines.push(host.t('… and {n} more', { n: fresh.length - 6 }));
    const text = lines.join('\n');
    const kind = 'error';
    try { if (ownEvent) host.notifications.notify('new-findings', { title, text, kind, url: '/ext/vuln-watch' }); } catch { /* optional */ }
    try { if (ctx.monitor) ctx.monitor.send(title, text, { kind, event: 'vuln-watch', force: true, push: !ownEvent }).catch(() => {}); } catch { /* optional */ }
    host.broadcast({ type: 'toast', kind: 'error', text: `${title}` });
  };

  let running = null;
  const run = ({ force = false } = {}) => {
    if (running) return running;
    running = (async () => {
      const cfg = settings();
      const inv = await (io.collect || collect)(ctx, { projects: cfg.projects, ownVersions: ownVersions() });
      const items = inv.items;
      store.set('inventory', items);
      if (offline()) {
        for (const s of ['osv', 'nvd', 'kev', 'epss']) src.fail(s, Object.assign(new Error('Offline mode is on.'), { code: 'HW_OFFLINE' }));
      } else {
        // OSV: Programme mit Paket-Eintrag (Caddy, Go, Electron) + Projekt-Abhängigkeiten, alles in einem Bündel
        const pkgs = [];
        for (const it of items) {
          if (it.packages) pkgs.push(...it.packages);
          const p = it.product && PRODUCTS[it.product];
          if (p && p.osv && !it.why) pkgs.push({ ...p.osv, version: it.ver.upstream });
        }
        if (pkgs.length) await src.osvRefresh(pkgs, { force });
        if (items.some((it) => it.product === 'minecraft' && !it.why)) await src.osvEnsure([MC_LOG4SHELL.id]);
        // NVD: nur Produkte, die hier wirklich laufen – je Produkt ein (seltener) Abruf
        const used = [...new Set(items.filter((it) => !it.why && it.product && PRODUCTS[it.product].nvd).map((it) => it.product))];
        if (used.length) await src.nvdRefreshAll(used.map((p) => ({ prefixes: PRODUCTS[p].nvd })), { force });
        await src.kevRefresh({ force });
        // EPSS für alle CVEs, die gerade zutreffen
        const pre = evaluate(items);
        await src.epssRefresh(pre.findings.map((f) => f.cve).filter(Boolean), { force });
      }
      const r = evaluate(items);
      const st = state();
      const seen = {};
      for (const f of r.findings) seen[f.key] = f.firstSeen;
      const notified = { ...(st.notified || {}) };
      const isNew = (f) => !f.ignored && !notified[f.key] && f.kind === 'vuln' && (f.kev || f.level === 'critical' || (cfg.notifyHigh && f.level === 'high'));
      const fresh = r.findings.filter(isNew);
      // Erster Lauf überhaupt: nicht mit dem ganzen Altbestand überfallen – nur Ausgenutztes melden
      const first = !st.at;
      if (cfg.notify) alert(first ? fresh.filter((f) => f.kev) : fresh);
      for (const f of fresh) notified[f.key] = now();
      for (const k of Object.keys(notified)) if (!seen[k]) delete notified[k]; // behoben → darf wieder melden, falls es zurückkommt
      const next = { at: now(), findings: r.findings, unchecked: r.unchecked, counts: r.counts, overall: r.overall, notified, seen, notes: inv.notes || [] };
      store.set('state', next);
      try {
        const c = r.counts;
        host.watcher({
          id: 'vulns', label: host.t('Vulnerabilities'), href: '/ext/vuln-watch',
          state: r.overall === 'critical' || r.overall === 'high' ? 'alert' : 'ok',
          detail: c.total ? host.t('{critical} critical · {high} high · {kev} exploited', { critical: c.critical, high: c.high, kev: c.kev }) : host.t('No known vulnerabilities'),
        });
      } catch { /* Wächter sind optional */ }
      return next;
    })().finally(() => { running = null; });
    return running;
  };

  /** Neu bewerten ohne Netz (nach Ausnahmen) – mit dem zuletzt ermittelten Bestand. */
  const reassess = () => {
    const items = store.get('inventory', () => []);
    const r = evaluate(items);
    const st = state();
    store.set('state', { ...st, findings: r.findings, unchecked: r.unchecked, counts: r.counts, overall: r.overall });
  };

  const view = () => {
    const st = state();
    const items = store.get('inventory', () => []);
    const blocked = {};
    for (const h of ['services.nvd.nist.gov', 'api.osv.dev', 'www.cisa.gov', 'api.first.org']) { const u = net.blockedUntil(h); if (u) blocked[h] = u; }
    return {
      at: st.at, running: !!running, offline: offline(), overall: st.overall, counts: st.counts || summarize([]).counts,
      findings: (st.findings || []).map(slim), unchecked: st.unchecked || [],
      inventory: items.map((it) => ({ id: it.id, area: it.area, kind: it.kind, name: it.name, version: it.version || null, product: it.product, label: it.product && PRODUCTS[it.product] ? PRODUCTS[it.product].label : null, why: it.why, packages: it.packages ? it.packages.length : null, files: it.files || null, image: it.image || null, distro: it.ver ? it.ver.distro : null, local: !!(it.exposure && it.exposure.local), href: it.href })),
      sources: src.status(), blocked, settings: settings(), levels: LEVEL_LABEL, lang: typeof host.lang === 'function' ? host.lang() : 'de',
    };
  };

  const detail = (key) => (state().findings || []).find((f) => f.key === key) || null;

  return { run, view, detail, reassess, settings, store, src, net, ignores, due: () => !state().at || now() - state().at > DUE };
}

function activate(host) {
  const svc = createService(host);
  const r = host.router;
  r.get('/vuln-watch', (req, res) => res.json(svc.view()));
  r.post('/vuln-watch/refresh', async (req, res, next) => { try { await svc.run({ force: !!(req.body && req.body.force) }); res.json(svc.view()); } catch (e) { next(e); } });
  r.get('/vuln-watch/detail', (req, res) => { const f = svc.detail(String(req.query.key || '')); if (!f) throw host.error(404, 'Finding not found – check again.'); res.json(f); });
  r.put('/vuln-watch/ignore', (req, res) => {
    const b = req.body || {};
    const key = String(b.key || '');
    if (!svc.detail(key)) throw host.error(404, 'Finding not found – check again.');
    const until = b.until ? Date.parse(b.until) : null;
    if (b.until && !Number.isFinite(until)) throw host.error(400, 'Invalid date.');
    const ig = { ...svc.ignores() };
    ig[key] = { reason: String(b.reason || '').slice(0, 300), until: until || null, at: Date.now() };
    svc.store.set('ignores', ig);
    svc.reassess();
    res.json(svc.view());
  });
  r.delete('/vuln-watch/ignore', (req, res) => {
    const ig = { ...svc.ignores() };
    delete ig[String(req.query.key || '')];
    svc.store.set('ignores', ig);
    svc.reassess();
    res.json(svc.view());
  });
  r.post('/vuln-watch/update', async (req, res, next) => {
    try {
      const key = String((req.body || {}).key || '');
      const f = (svc.view().findings || []).find((x) => x.fix && x.fix.kind === 'patch' && x.fix.key === key);
      if (!f) throw host.error(404, 'Hostwerk cannot install an update for this right now.');
      if (!host.ctx.patchUpdates || typeof host.ctx.patchUpdates.apply !== 'function') throw host.error(409, 'Security updates are not available in this Hostwerk version.');
      const r2 = await host.ctx.patchUpdates.apply(key);
      await svc.run();
      res.json({ result: { ok: !!r2.ok, skipped: !!r2.skipped, error: r2.error || null }, ...svc.view() });
    } catch (e) { next(e); }
  });
  r.get('/vuln-watch/ai', async (req, res) => {
    let ready = false;
    try { ready = !!(host.ctx.ai && host.ctx.ai.quick && await host.ctx.ai.quick.ready()); } catch { /* aus */ }
    res.json({ ready });
  });
  r.post('/vuln-watch/ai', async (req, res, next) => {
    try {
      const f = svc.detail(String((req.body || {}).key || ''));
      if (!f) throw host.error(404, 'Finding not found – check again.');
      const q = host.ctx.ai && host.ctx.ai.quick;
      if (!q) throw host.error(409, 'The AI assistant is not ready.');
      const lang = host.lang();
      const text = `${f.id}${f.score != null ? ` (CVSS ${f.score})` : ''} – ${f.itemName} ${f.pkg ? `${f.pkg.name} ${f.pkg.version}` : f.version || ''}\n${f.title || ''}\n${f.details || ''}`;
      const out = await q.run('summarize', { text, lang, context: 'Security vulnerability (CVE) in a service the user runs – say what an attacker could do and who is affected, in plain words.' });
      res.json({ text: out.text, lang });
    } catch (e) { next(e); }
  });

  // Erster Lauf ein paar Minuten nach dem Start (Hostwerk startet gerade Dienste), dann stündlich prüfen, ob ein Tag um ist
  let timer = null;
  const tick = () => { if (svc.due()) svc.run().catch((e) => host.log('run failed:', e.message)); };
  const first = setTimeout(() => { tick(); timer = setInterval(tick, HOUR); if (timer.unref) timer.unref(); }, 3 * 60000);
  if (first.unref) first.unref();
  host.on('shutdown', () => { clearTimeout(first); clearInterval(timer); });
}

function deactivate() {}

module.exports = { activate, deactivate, createService };
