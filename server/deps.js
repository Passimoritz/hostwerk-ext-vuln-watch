'use strict';
/*
 * Abhängigkeiten eines Projekts aus seinen Sperrdateien – nur lesen, nie installieren:
 *   package-lock.json (npm, lockfileVersion 1–3) · composer.lock (Packagist) · poetry.lock / requirements.txt mit == (PyPI)
 *   go.mod (Go) · Cargo.lock (crates.io)
 * Ergebnis: [{ ecosystem, name, version, dev, file }] – dev = nur zum Entwickeln (devDependencies, packages-dev, …).
 * Sperrdateien sind die Wahrheit über die eingebauten Versionen; package.json/composer.json allein nennen nur Bereiche.
 */
const fs = require('fs');
const path = require('path');

const MAX_PER_PROJECT = 3000;

/** package-lock.json → npm-Pakete (v2/v3: „packages“, v1: verschachtelte „dependencies“). */
function npmLock(text) {
  const j = JSON.parse(text);
  const out = [];
  if (j.packages && typeof j.packages === 'object') {
    for (const [key, p] of Object.entries(j.packages)) {
      if (!key || !p || !p.version || p.link) continue;
      const name = p.name || key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
      if (!name || /^(file|link|git|https?):/.test(p.version)) continue;
      out.push({ ecosystem: 'npm', name, version: p.version, dev: !!(p.dev || p.devOptional) });
    }
    return out;
  }
  const walk = (deps) => {
    for (const [name, p] of Object.entries(deps || {})) {
      if (p && p.version && !/^(file|link|git|https?):/.test(p.version)) out.push({ ecosystem: 'npm', name, version: p.version, dev: !!p.dev });
      if (p && p.dependencies) walk(p.dependencies);
    }
  };
  walk(j.dependencies);
  return out;
}

/** composer.lock → Packagist-Pakete. */
function composerLock(text) {
  const j = JSON.parse(text);
  const take = (list, dev) => (Array.isArray(list) ? list : []).filter((p) => p && p.name && p.version && !/^dev-/.test(p.version)).map((p) => ({ ecosystem: 'Packagist', name: p.name, version: String(p.version).replace(/^v(?=\d)/, ''), dev }));
  return [...take(j.packages, false), ...take(j['packages-dev'], true)];
}

/** poetry.lock / Cargo.lock: [[package]]-Blöcke mit name = "…" und version = "…" (einfaches TOML reicht). */
function tomlPackages(text, ecosystem) {
  const out = [];
  for (const block of String(text).split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const body = block.split(/^\[(?!\[package)/m)[0];
    const name = (/^name\s*=\s*"([^"]+)"/m.exec(body) || [])[1];
    const version = (/^version\s*=\s*"([^"]+)"/m.exec(body) || [])[1];
    const cat = (/^category\s*=\s*"([^"]+)"/m.exec(body) || [])[1];
    if (name && version) out.push({ ecosystem, name, version, dev: cat === 'dev' });
  }
  return out;
}

/** requirements.txt: nur feste Versionen (paket==1.2.3) – Bereiche lassen sich nicht ehrlich prüfen. */
function requirements(text) {
  const out = [];
  for (const line of String(text).split(/\r?\n/)) {
    const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([0-9][^\s;#,]*)/.exec(line);
    if (m) out.push({ ecosystem: 'PyPI', name: m[1].toLowerCase().replace(/[._]+/g, '-'), version: m[2], dev: false });
  }
  return out;
}

/** go.mod: require-Zeilen (einzeln und im Block). „// indirect“ zählt mit. */
function goMod(text) {
  const out = [];
  const add = (mod, ver) => { if (mod && ver && /^v\d/.test(ver)) out.push({ ecosystem: 'Go', name: mod, version: ver.replace(/^v/, '').replace(/\+incompatible$/, ''), dev: false }); };
  const s = String(text);
  for (const m of s.matchAll(/^require\s+(\S+)\s+(\S+)/gm)) add(m[1], m[2]);
  for (const b of s.matchAll(/^require\s*\(([\s\S]*?)^\)/gm)) for (const line of b[1].split(/\r?\n/)) { const m = /^\s*(\S+)\s+(v\S+)/.exec(line); if (m) add(m[1], m[2]); }
  return out;
}

const FILES = [
  ['package-lock.json', npmLock],
  ['composer.lock', composerLock],
  ['poetry.lock', (t) => tomlPackages(t, 'PyPI')],
  ['requirements.txt', requirements],
  ['go.mod', goMod],
  ['Cargo.lock', (t) => tomlPackages(t, 'crates.io')],
];

/** Alle Sperrdateien direkt im Projektordner lesen. Fehlerhafte Dateien werden übersprungen (Hinweis in notes). */
function readProject(dir, readFile = (f) => fs.readFileSync(f, 'utf8')) {
  const packages = [];
  const files = [];
  const notes = [];
  for (const [name, parse] of FILES) {
    const f = path.join(dir, name);
    let text;
    try { text = readFile(f); } catch { continue; }
    try {
      const list = parse(text);
      files.push(name);
      for (const p of list) packages.push({ ...p, file: name });
    } catch (e) { notes.push(`${name}: ${String(e.message).slice(0, 120)}`); }
  }
  // Doppelte (gleiches Paket in derselben Version mehrfach im Baum) nur einmal; dev nur, wenn überall dev
  const by = new Map();
  for (const p of packages) {
    const k = `${p.ecosystem}|${p.name}|${p.version}`;
    if (!by.has(k)) by.set(k, p); else if (!p.dev) by.get(k).dev = false;
  }
  const list = [...by.values()];
  if (list.length > MAX_PER_PROJECT) notes.push(`truncated:${list.length}`);
  return { files, packages: list.slice(0, MAX_PER_PROJECT), notes };
}

module.exports = { npmLock, composerLock, tomlPackages, requirements, goMod, readProject, MAX_PER_PROJECT };
