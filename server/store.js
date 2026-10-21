'use strict';
/*
 * Zwischenspeicher auf der Platte: eine JSON-Datei je Quelle unter data/vuln-watch/ (Schreiben über .tmp + rename, damit
 * ein Absturz nie eine halbe Datei hinterlässt). Fällt eine Quelle aus, bleibt hier der letzte gute Stand.
 */
const fs = require('fs');
const path = require('path');

class Store {
  constructor(dir) {
    this.dir = dir;
    fs.mkdirSync(dir, { recursive: true });
    this.mem = new Map();
  }
  file(name) { return path.join(this.dir, `${name.replace(/[^\w.-]/g, '_')}.json`); }
  get(name, fallback) {
    if (this.mem.has(name)) return this.mem.get(name);
    let v;
    try { v = JSON.parse(fs.readFileSync(this.file(name), 'utf8')); } catch { v = typeof fallback === 'function' ? fallback() : fallback; }
    this.mem.set(name, v);
    return v;
  }
  set(name, value) {
    this.mem.set(name, value);
    const f = this.file(name);
    fs.writeFileSync(`${f}.tmp`, JSON.stringify(value));
    fs.renameSync(`${f}.tmp`, f);
    return value;
  }
}

module.exports = { Store };
