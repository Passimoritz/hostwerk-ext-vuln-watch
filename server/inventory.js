'use strict';
/*
 * Bestand: alles, was in Hostwerk installiert ist oder läuft – mit Version. Nur lesen, nichts starten.
 * Quellen sind Hostwerks eigene Verwaltungen (dieselben, die auch /overview, Sicherheits-Updates und die Lebensende-Wache
 * nutzen): ctx.web, ctx.dbm, ctx.services.php, ctx.apps (+ Laufzeiten), ctx.minecraft, ctx.games, ctx.devtools.
 * Seit 1.2 (Hostwerk mit SDK 3.3) über die stabilen Dienste, wo vorhanden: opts.sdk = host – host.minecraft.addons()
 * für Plugin-Versionen, host.images.list() für Images aus Compose-Stapeln und Docker-Spiele-Servern; sonst wie bisher.
 *
 * Eintrag: { id, area, kind, product, name, version, ver: clean(version), href, updateKey, exposure, modules, packages, why }
 *   area     – Bereich in Hostwerk (web, dbs, php, runtimes, minecraft, apps, games, system, projects) für Filter und Reiter
 *   product  – Schlüssel aus catalog.PRODUCTS (oder null = keine Schwachstellen-Datenbank)
 *   updateKey – Schlüssel bei Hostwerks Sicherheits-Updates (php-8.3, db-<id>, web-<id>) – dann kann Hostwerk selbst einspielen
 *   exposure – { local: true } wenn der Dienst nur auf diesem Rechner lauscht (ehrlich nur, wo Hostwerk das festlegt)
 *   why      – Grund, warum nicht geprüft wird ('no-version', 'no-database', 'imprecise')
 */
const fs = require('fs');
const path = require('path');
const { PRODUCTS, dockerImage } = require('./catalog');
const { clean, precision } = require('./version');
const deps = require('./deps');

const safe = (fn, fallback) => { try { const v = fn(); return v === undefined ? fallback : v; } catch { return fallback; } };

/** Geladene Apache-Module aus der erzeugten und der eigenen Konfiguration (LoadModule-Zeilen). */
function apacheModules(ctx, inst, readFile) {
  const dir = safe(() => ctx.paths.configDir(inst.id), null);
  if (!dir) return null;
  const mods = new Set();
  let found = false;
  for (const f of ['httpd.conf', 'eigene-einstellungen.conf']) {
    let text;
    try { text = readFile(path.join(dir, f)); } catch { continue; }
    found = true;
    for (const m of String(text).matchAll(/^\s*LoadModule\s+(\w+?)_module\b/gim)) mods.add(m[1].toLowerCase());
  }
  return found ? [...mods] : null;
}

function item(base) {
  const ver = clean(base.version);
  const p = base.product ? PRODUCTS[base.product] : null;
  let why = base.why || null;
  if (!why && !base.packages) {
    if (!p || (!p.nvd && !p.osv && base.product !== 'minecraft')) why = 'no-database';
    else if (!ver.upstream || !/^\d/.test(ver.upstream)) why = 'no-version';
    else if (base.product !== 'minecraft' && precision(ver.upstream) < 2) why = 'imprecise';
  }
  return { exposure: null, modules: null, updateKey: null, href: null, ...base, ver, why };
}

/** Stabiler Dienst vorhanden UND erlaubt? (host.supports, SDK 3.3 – ältere Hostwerk-Versionen: nein) */
const can = (sdk, name) => { try { return !!(sdk && typeof sdk.supports === 'function' && sdk.supports(name)); } catch { return false; } };

/**
 * Bestand ermitteln. opts: { projects: true, plugins: true, readFile, readdir, ownVersions: { node, electron }, sdk }
 * Gibt { items, notes } zurück – notes erklären Lücken (z. B. Erweiterung „Spiele-Server“ ohne Versionen).
 */
async function collect(ctx, opts = {}) {
  const readFile = opts.readFile || ((f) => fs.readFileSync(f, 'utf8'));
  const readdir = opts.readdir || ((d) => fs.readdirSync(d));
  const items = [];
  const notes = [];

  // Webserver
  for (const i of safe(() => ctx.web.list(), [])) {
    const product = ['apache', 'nginx', 'caddy'].includes(i.type) ? i.type : null;
    items.push(item({
      id: `web:${i.id}`, area: 'web', kind: 'web', product, name: i.name || i.id, version: i.version, href: `#/web/${encodeURIComponent(i.id)}`,
      updateKey: `web-${i.id}`, modules: product === 'apache' ? apacheModules(ctx, i, readFile) : null, external: !!i.external,
    }));
  }
  // PHP (je installierte Version; Sicherheits-Updates je Reihe)
  for (const v of safe(() => ctx.services.php.installed(), [])) {
    const branch = String(v).split('.').slice(0, 2).join('.');
    items.push(item({ id: `php:${v}`, area: 'php', kind: 'php', product: 'php', name: `PHP ${branch}`, version: v, href: '#/web/php', updateKey: `php-${branch}` }));
  }
  // Datenbanken
  for (const i of safe(() => ctx.dbm.list(), [])) {
    const product = { mariadb: 'mariadb', mysql: 'mysql', postgres: 'postgres', mongodb: 'mongodb', redis: 'redis' }[i.type] || null;
    const lan = !!(i.options && i.options.lan);
    items.push(item({
      id: `db:${i.id}`, area: 'dbs', kind: 'db', product, name: i.name || i.id, version: i.version, href: `#/dbs/${encodeURIComponent(i.id)}`,
      updateKey: `db-${i.id}`, exposure: i.external ? null : { local: !lan }, external: !!i.external, dbType: i.type,
    }));
  }
  // Laufzeiten, die Hostwerk für Apps geladen hat (Node, Python, Go, Java …)
  const rt = safe(() => ctx.apps.runtimes, null);
  for (const id of ['node', 'python', 'go', 'java', 'bun', 'deno', 'dotnet']) {
    for (const r of safe(() => (rt ? rt.managedAll(id) : []), [])) {
      const product = PRODUCTS[id] ? id : null;
      items.push(item({ id: `runtime:${id}:${r.version}`, area: 'runtimes', kind: 'runtime', product, name: `${PRODUCTS[id] ? PRODUCTS[id].label : id} ${r.version}`, version: r.version, href: '#/apps/laufzeiten' }));
    }
  }
  // Java für Minecraft (nur Hauptversion bekannt → Lebensende ja, Schwachstellen nein)
  for (const m of safe(() => ctx.services.java.installed(), [])) {
    if (!items.some((x) => x.product === 'java' && String(x.version).split('.')[0] === String(m))) items.push(item({ id: `java:${m}`, area: 'runtimes', kind: 'runtime', product: 'java', name: `Java ${m}`, version: String(m), href: '#/mc', why: 'no-database' }));
  }
  // Docker-Apps: Image:Tag – offizielle Images mit Versionsnummer im Tag werden wie das Programm geprüft
  for (const a of safe(() => ctx.apps.list(), [])) {
    if (a.kind !== 'docker' || !a.image) continue;
    const d = dockerImage(a.image);
    items.push(item({
      id: `docker:${a.id}`, area: 'apps', kind: 'docker', product: d && d.product, name: a.name || a.id, version: d && d.version, image: a.image, href: `#/apps/${encodeURIComponent(a.id)}`,
      why: !d || !d.product ? 'no-database' : !d.version ? 'no-version' : null,
    }));
  }
  // Minecraft-Server und ihre Plugins/Mods (Versionen aus plugin.yml & Co.)
  const sdk = opts.sdk || null;
  for (const s of safe(() => ctx.minecraft.list(), [])) {
    items.push(item({ id: `mc:${s.id}`, area: 'minecraft', kind: 'minecraft', product: 'minecraft', name: s.name || s.id, version: s.version, flavor: s.type, build: s.build || null, href: `#/mc/${encodeURIComponent(s.id)}` }));
    if (opts.plugins === false) continue;
    if (can(sdk, 'minecraft.addons')) {
      // Stabiler Dienst (SDK 3.3): Name und Version aus plugin.yml/mods.toml, nur lesen
      let list = [];
      try { list = await sdk.minecraft.addons(s.id); } catch { list = []; }
      for (const a of (list || []).filter((x) => /\.jar$/i.test(x.file)).slice(0, 200)) {
        items.push(item({ id: `mc:${s.id}:${a.file}`, area: 'minecraft', kind: 'plugin', product: null, name: a.name || a.file.replace(/\.jar$/i, ''), version: a.version || null, parent: `mc:${s.id}`, href: `#/mc/${encodeURIComponent(s.id)}`, why: 'no-database' }));
      }
      continue;
    }
    const dir = safe(() => ctx.minecraft.addonDir(s.id), null);
    const files = dir ? safe(() => readdir(dir).filter((f) => /\.jar$/i.test(f)), []) : [];
    for (const f of files.slice(0, 200)) {
      let meta = null;
      try { meta = ctx.minecraft.readMeta ? await ctx.minecraft.readMeta(path.join(dir, f)) : null; } catch { /* unlesbar */ }
      const name = (meta && meta.name) || f.replace(/\.jar$/i, '');
      items.push(item({ id: `mc:${s.id}:${f}`, area: 'minecraft', kind: 'plugin', product: null, name, version: meta && meta.version, parent: `mc:${s.id}`, href: `#/mc/${encodeURIComponent(s.id)}`, why: 'no-database' }));
    }
  }
  // Spiele-Server (Erweiterung „Spiele-Server“) – ab deren 1.10 mit Steam-Build-ID. Für Spiele gibt es keine
  // Schwachstellen-Datenbank: mit Version „ohne Prüfung“ (no-database), ohne Version wie bisher (no-version)
  for (const g of safe(() => (ctx.games && typeof ctx.games.summary === 'function' ? ctx.games.summary() : []), [])) {
    const version = g.version ? String(g.version) : null;
    items.push(item({ id: `game:${g.id}`, area: 'games', kind: 'game', product: null, name: g.name || g.game || g.id, version, versionKind: g.versionKind || null, game: g.game, image: g.image || null, href: `#/spiele/${encodeURIComponent(g.id)}`, why: version ? 'no-database' : 'no-version' }));
  }
  // Images aus Compose-Stapeln und Docker-Spiele-Servern (stabiler Dienst, SDK 3.3) – offizielle Images mit Versionsnummer
  // im Tag werden wie das Programm geprüft, alle anderen erscheinen ehrlich „ohne Prüfung“. Docker-Apps stehen schon oben.
  if (can(sdk, 'images.list')) {
    let imgs = [];
    try { imgs = await sdk.images.list(); } catch { imgs = []; }
    const seen = new Set();
    for (const i of imgs || []) {
      if (!i || !i.image || i.source === 'app') continue;
      const key = `${i.source}:${i.owner}:${i.image}`;
      if (seen.has(key)) continue; seen.add(key);
      const d = i.tag ? dockerImage(`${i.repo}:${i.tag}`) : null;
      items.push(item({
        id: `image:${i.source}:${i.owner}:${i.service || i.repo}`, area: i.source === 'game' ? 'games' : 'apps', kind: 'docker', product: d && d.product, name: i.name || i.image, version: d && d.version, image: i.image,
        href: i.source === 'game' ? `#/spiele/${encodeURIComponent(i.owner)}` : '#/apps', parent: i.source === 'game' ? `game:${i.owner}` : null,
        why: !d || !d.product ? 'no-database' : !d.version ? 'no-version' : null,
      }));
    }
  }
  // Hostwerk selbst: eigene Node-Laufzeit und Electron
  const own = opts.ownVersions || {};
  if (own.node) items.push(item({ id: 'hostwerk:node', area: 'system', kind: 'hostwerk', product: 'node', name: 'Hostwerk (Node.js)', version: own.node, href: '#/settings/updates', appUpdate: true }));
  if (own.electron) items.push(item({ id: 'hostwerk:electron', area: 'system', kind: 'hostwerk', product: 'electron', name: 'Hostwerk (Electron)', version: own.electron, href: '#/settings/updates', appUpdate: true }));
  // Projekt-Abhängigkeiten (Sperrdateien)
  if (opts.projects !== false) {
    for (const p of safe(() => (ctx.devtools && typeof ctx.devtools.list === 'function' ? ctx.devtools.list() : []), [])) {
      if (!p || !p.path) continue;
      const r = deps.readProject(p.path, readFile);
      if (!r.files.length) continue;
      items.push(item({ id: `project:${p.id}`, area: 'projects', kind: 'project', product: null, name: p.name || path.basename(p.path), version: null, dir: p.path, files: r.files, packages: r.packages, href: '#/projects', notes: r.notes }));
    }
  }
  if (!items.length) notes.push('empty');
  return { items, notes };
}

module.exports = { collect, apacheModules, item };
