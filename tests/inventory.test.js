'use strict';
// Bestand aus einem nachgebauten Hostwerk und Abhängigkeiten aus Sperrdateien
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { collect } = require('../server/inventory');
const { dockerImage } = require('../server/catalog');
const D = require('../server/deps');

/** Hostwerk-Kontext mit allem, was die Erweiterung liest – Dateien kommen aus files (Pfad → Inhalt). */
function fakeCtx(files = {}) {
  return {
    paths: { configDir: (id) => path.join('/cfg', id) },
    web: { list: () => [
      { id: 'apache', name: 'Apache', type: 'apache', version: '2.4.49' },
      { id: 'ng', name: 'nginx', type: 'nginx', version: '1.24.0-system', external: { binDir: '/usr/sbin' } },
    ] },
    services: { php: { installed: () => ['8.3.9', '8.1.0'] }, java: { installed: () => [21, 17] } },
    dbm: { list: () => [
      { id: 'mariadb', name: 'MariaDB', type: 'mariadb', version: '11.4.2' },
      { id: 'pg', name: 'PostgreSQL', type: 'postgres', version: '16.4', options: { lan: true } },
      { id: 'garnet', name: 'Garnet', type: 'garnet', version: '1.0.0' },
    ] },
    apps: {
      runtimes: { managedAll: (id) => (id === 'node' ? [{ version: '20.11.1' }] : id === 'java' ? [{ version: '21.0.4' }] : []) },
      list: () => [
        { id: 'cache', name: 'Cache', kind: 'docker', image: 'redis:7.2.4-alpine' },
        { id: 'n8n', name: 'n8n', kind: 'docker', image: 'n8nio/n8n:latest' },
        { id: 'pg2', name: 'PG latest', kind: 'docker', image: 'postgres:latest' },
        { id: 'bot', name: 'Bot', kind: 'node', dir: '/proj/bot' },
      ],
    },
    minecraft: {
      list: () => [{ id: 'lobby', name: 'Lobby', type: 'paper', version: '1.17.1', build: 411 }],
      addonDir: () => '/mc/lobby/plugins',
      readMeta: async () => ({ name: 'LuckPerms', version: '5.4.102' }),
    },
    games: { summary: () => [{ id: 'valheim', name: 'Valheim', game: 'Valheim' }] },
    devtools: { list: () => [{ id: 'shop', name: 'shop', path: '/proj/shop' }, { id: 'empty', name: 'empty', path: '/proj/empty' }] },
    _files: files,
  };
}

test('Bestand: Webserver, PHP, Datenbanken, Laufzeiten, Docker, Minecraft, Spiele, Hostwerk, Projekte', async () => {
  const files = {
    [path.join('/cfg', 'apache', 'httpd.conf')]: 'LoadModule rewrite_module modules/mod_rewrite.so\nLoadModule proxy_module modules/mod_proxy.so\n# LoadModule lua_module x',
    [path.join('/proj/shop', 'package-lock.json')]: JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'shop' }, 'node_modules/lodash': { version: '4.17.20' }, 'node_modules/jest': { version: '29.0.0', dev: true } } }),
  };
  const readFile = (f) => { if (files[f] === undefined) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' }); return files[f]; };
  const { items } = await collect(fakeCtx(), { readFile, readdir: () => ['LuckPerms-5.4.102.jar', 'readme.txt'], ownVersions: { node: '24.1.0', electron: '38.2.0' }, plugins: true });
  const by = (id) => items.find((x) => x.id === id);

  assert.strictEqual(by('web:apache').product, 'apache');
  assert.deepStrictEqual(by('web:apache').modules.sort(), ['proxy', 'rewrite']);
  assert.strictEqual(by('web:apache').updateKey, 'web-apache');
  assert.strictEqual(by('web:ng').ver.distro, 'system');
  assert.strictEqual(by('web:ng').ver.upstream, '1.24.0');
  assert.strictEqual(by('web:ng').external, true);
  assert.strictEqual(by('php:8.3.9').updateKey, 'php-8.3');
  assert.strictEqual(by('php:8.1.0').why, null);
  assert.deepStrictEqual(by('db:mariadb').exposure, { local: true });
  assert.deepStrictEqual(by('db:pg').exposure, { local: false });
  assert.strictEqual(by('db:garnet').why, 'no-database');
  assert.strictEqual(by('runtime:node:20.11.1').product, 'node');
  assert.strictEqual(by('runtime:java:21.0.4').why, 'no-database'); // Java: nur Lebensende
  assert.ok(by('java:17'), 'Java 17 für Minecraft ohne App-Laufzeit');
  assert.ok(!by('java:21'), 'Java 21 schon als Laufzeit erfasst');
  assert.strictEqual(by('docker:cache').product, 'redis');
  assert.strictEqual(by('docker:cache').version, '7.2.4');
  assert.strictEqual(by('docker:n8n').why, 'no-database');
  assert.strictEqual(by('docker:pg2').why, 'no-version');
  assert.strictEqual(by('mc:lobby').product, 'minecraft');
  assert.strictEqual(by('mc:lobby').flavor, 'paper');
  assert.strictEqual(by('mc:lobby:LuckPerms-5.4.102.jar').name, 'LuckPerms');
  assert.strictEqual(by('mc:lobby:LuckPerms-5.4.102.jar').version, '5.4.102');
  assert.strictEqual(by('mc:lobby:LuckPerms-5.4.102.jar').why, 'no-database');
  assert.strictEqual(items.filter((x) => x.kind === 'plugin').length, 1);
  assert.strictEqual(by('game:valheim').why, 'no-version');
  assert.strictEqual(by('hostwerk:electron').product, 'electron');
  assert.strictEqual(by('hostwerk:node').appUpdate, true);
  const shop = by('project:shop');
  assert.deepStrictEqual(shop.files, ['package-lock.json']);
  assert.deepStrictEqual(shop.packages.map((p) => [p.name, p.version, p.dev]), [['lodash', '4.17.20', false], ['jest', '29.0.0', true]]);
  assert.ok(!by('project:empty'), 'Projekt ohne Sperrdatei bleibt draußen');
});

test('Bestand: fehlende Hostwerk-Teile brechen nichts (alte Version, Erweiterungen fehlen)', async () => {
  const { items, notes } = await collect({ paths: {} }, { readFile: () => { throw new Error('x'); } });
  assert.deepStrictEqual(items, []);
  assert.deepStrictEqual(notes, ['empty']);
});

test('dockerImage: offizielle Images mit Version, fremde und ohne Nummer', () => {
  assert.deepStrictEqual(dockerImage('redis:7.2.4-alpine'), { image: 'redis', tag: '7.2.4-alpine', product: 'redis', version: '7.2.4' });
  assert.strictEqual(dockerImage('library/php:8.2.12-apache').product, 'php');
  assert.strictEqual(dockerImage('docker.io/library/nginx:1.25').version, '1.25');
  assert.strictEqual(dockerImage('mariadb').tag, 'latest');
  assert.strictEqual(dockerImage('mariadb').version, null);
  assert.strictEqual(dockerImage('bitnami/redis:7.2.4').product, null);
  assert.strictEqual(dockerImage('localhost:5000/redis:7.2.4').product, null);
  assert.strictEqual(dockerImage('postgres:16.4@sha256:abc').version, '16.4');
  assert.strictEqual(dockerImage(''), null);
});

test('Sperrdateien: npm v1, Composer, poetry, requirements, go.mod, Cargo', () => {
  const v1 = D.npmLock(JSON.stringify({ lockfileVersion: 1, dependencies: { express: { version: '4.17.1', dependencies: { qs: { version: '6.7.0' } } }, mocha: { version: '10.0.0', dev: true }, local: { version: 'file:../x' } } }));
  assert.deepStrictEqual(v1.map((p) => `${p.name}@${p.version}${p.dev ? ' dev' : ''}`), ['express@4.17.1', 'qs@6.7.0', 'mocha@10.0.0 dev']);
  const v3 = D.npmLock(JSON.stringify({ packages: { 'node_modules/@babel/core': { version: '7.0.0' }, 'node_modules/a/node_modules/b': { version: '1.0.0', devOptional: true }, 'node_modules/linked': { link: true, resolved: 'x' } } }));
  assert.deepStrictEqual(v3.map((p) => p.name), ['@babel/core', 'b']);
  const c = D.composerLock(JSON.stringify({ packages: [{ name: 'guzzlehttp/guzzle', version: 'v7.4.0' }, { name: 'x/y', version: 'dev-main' }], 'packages-dev': [{ name: 'phpunit/phpunit', version: '9.5.0' }] }));
  assert.deepStrictEqual(c, [{ ecosystem: 'Packagist', name: 'guzzlehttp/guzzle', version: '7.4.0', dev: false }, { ecosystem: 'Packagist', name: 'phpunit/phpunit', version: '9.5.0', dev: true }]);
  const poetry = D.tomlPackages('[[package]]\nname = "django"\nversion = "3.2.0"\ncategory = "main"\n\n[package.dependencies]\nasgiref = ">=3"\n\n[[package]]\nname = "pytest"\nversion = "7.0.0"\ncategory = "dev"\n', 'PyPI');
  assert.deepStrictEqual(poetry.map((p) => [p.name, p.version, p.dev]), [['django', '3.2.0', false], ['pytest', '7.0.0', true]]);
  assert.deepStrictEqual(D.requirements('Flask==2.0.1\nrequests>=2\n# Kommentar\nJinja2[i18n] == 3.0.0 ; python_version>"3"\n').map((p) => `${p.name}@${p.version}`), ['flask@2.0.1', 'jinja2@3.0.0']);
  const go = D.goMod('module x\n\ngo 1.21\n\nrequire golang.org/x/net v0.17.0\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgithub.com/old/x v2.0.0+incompatible // indirect\n)\n');
  assert.deepStrictEqual(go.map((p) => `${p.name}@${p.version}`), ['golang.org/x/net@0.17.0', 'github.com/gin-gonic/gin@1.9.0', 'github.com/old/x@2.0.0']);
  assert.deepStrictEqual(D.tomlPackages('[[package]]\nname = "tokio"\nversion = "1.20.0"\n', 'crates.io').map((p) => p.ecosystem), ['crates.io']);
});

test('readProject: kaputte Datei wird übersprungen, Doppelte zusammengelegt', () => {
  const files = { [path.join('/p', 'package-lock.json')]: '{ kaputt', [path.join('/p', 'composer.lock')]: JSON.stringify({ packages: [{ name: 'a/b', version: '1.0.0' }], 'packages-dev': [{ name: 'a/b', version: '1.0.0' }] }) };
  const r = D.readProject('/p', (f) => { if (!(f in files)) throw new Error('ENOENT'); return files[f]; });
  assert.deepStrictEqual(r.files, ['composer.lock']);
  assert.strictEqual(r.packages.length, 1);
  assert.strictEqual(r.packages[0].dev, false);
  assert.match(r.notes[0], /package-lock\.json/);
});

test('Bestand über stabile Dienste (SDK 3.3): Plugins, Compose- und Spiele-Images, Spiele mit Build-ID', async () => {
  const ctx = fakeCtx();
  ctx.minecraft.addonDir = () => { throw new Error('Interna dürfen nicht gefragt werden'); };
  ctx.games = { summary: () => [{ id: 'valheim', name: 'Valheim', game: 'vhserver', version: '16450218', versionKind: 'steam-build', docker: true, image: 'gameservermanagers/gameserver:vh' }, { id: 'old', name: 'Alt', game: 'x' }] };
  const sdk = {
    supports: (n) => ['minecraft.addons', 'images.list'].includes(n),
    minecraft: { addons: async () => [{ file: 'LuckPerms.jar', name: 'LuckPerms', version: '5.4.102', enabled: true, kind: 'plugin' }, { file: 'Off.jar.disabled', name: 'Off', version: '1', enabled: false, kind: 'plugin' }] },
    images: { list: async () => [
      { source: 'app', owner: 'cache', name: 'Cache', image: 'redis:7.2.4-alpine', repo: 'redis', tag: '7.2.4-alpine', digest: null },
      { source: 'compose', owner: '/proj/stack', name: 'stack › db', image: 'postgres:16.4', repo: 'postgres', tag: '16.4', digest: null, service: 'db' },
      { source: 'compose', owner: '/proj/stack', name: 'stack › app', image: 'ghcr.io/acme/app:${TAG}', repo: 'ghcr.io/acme/app', tag: null, digest: null, service: 'app' },
      { source: 'game', owner: 'valheim', name: 'Valheim', image: 'gameservermanagers/gameserver:vh', repo: 'gameservermanagers/gameserver', tag: 'vh', digest: null },
    ] },
  };
  const { items } = await collect(ctx, { readFile: () => { throw new Error('x'); }, projects: false, sdk });
  const by = (id) => items.find((x) => x.id === id);
  assert.strictEqual(by('mc:lobby:LuckPerms.jar').version, '5.4.102');
  assert.ok(!items.some((x) => /Off\.jar/.test(x.id)), 'ausgeschaltete Plugins wie bisher nicht');
  assert.deepStrictEqual([by('game:valheim').version, by('game:valheim').why], ['16450218', 'no-database']);
  assert.strictEqual(by('game:old').why, 'no-version');
  const db = by('image:compose:/proj/stack:db');
  assert.deepStrictEqual([db.product, db.version, db.why, db.area], ['postgres', '16.4', null, 'apps']);
  assert.strictEqual(by('image:compose:/proj/stack:app').why, 'no-database');
  const gi = by('image:game:valheim:gameservermanagers/gameserver');
  assert.deepStrictEqual([gi.area, gi.why, gi.parent], ['games', 'no-database', 'game:valheim']);
  assert.strictEqual(items.filter((x) => x.image === 'redis:7.2.4-alpine').length, 1, 'Docker-Apps nicht doppelt');
});
