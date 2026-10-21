'use strict';
/*
 * Welche Quelle kennt welches Programm? Ein Eintrag je Produkt:
 *   nvd: CPE-Präfixe (vendor:product) für die NVD-API 2.0 – Server-Programme ohne OSV-Abdeckung
 *   osv: { ecosystem, name } für OSV.dev – Pakete aus npm, Packagist, PyPI, Go, crates.io, Maven
 *   eol: Produktname in Hostwerks Lebensende-Wache (services/eol.js) – nur für die Anzeige „Lebensende“
 * Programme ohne Eintrag (Garnet, Bun, Deno, .NET, Spiele-Server …) stehen im Bestand, werden aber nicht geprüft – ehrlich
 * mit „keine Schwachstellen-Datenbank“ statt still „alles gut“.
 */

const PRODUCTS = {
  apache: { label: 'Apache HTTP Server', nvd: ['cpe:2.3:a:apache:http_server'] },
  nginx: { label: 'nginx', nvd: ['cpe:2.3:a:f5:nginx', 'cpe:2.3:a:nginx:nginx'] },
  caddy: { label: 'Caddy', osv: { ecosystem: 'Go', name: 'github.com/caddyserver/caddy/v2' } },
  php: { label: 'PHP', nvd: ['cpe:2.3:a:php:php'], eol: 'php' },
  mariadb: { label: 'MariaDB', nvd: ['cpe:2.3:a:mariadb:mariadb'], eol: 'mariadb' },
  mysql: { label: 'MySQL', nvd: ['cpe:2.3:a:oracle:mysql', 'cpe:2.3:a:oracle:mysql_server'], eol: 'mysql' },
  postgres: { label: 'PostgreSQL', nvd: ['cpe:2.3:a:postgresql:postgresql'], eol: 'postgres' },
  mongodb: { label: 'MongoDB', nvd: ['cpe:2.3:a:mongodb:mongodb'], eol: 'mongodb' },
  redis: { label: 'Redis', nvd: ['cpe:2.3:a:redis:redis'] },
  node: { label: 'Node.js', nvd: ['cpe:2.3:a:nodejs:node.js'], eol: 'node' },
  python: { label: 'Python', nvd: ['cpe:2.3:a:python:python'] },
  go: { label: 'Go', osv: { ecosystem: 'Go', name: 'stdlib' } },
  electron: { label: 'Electron', osv: { ecosystem: 'npm', name: 'electron' }, eol: 'electron' },
  java: { label: 'Java', eol: 'java' },
  minecraft: { label: 'Minecraft server' },
};

/** Paket-Ökosysteme für Projekt-Abhängigkeiten (OSV-Schreibweise). */
const ECOSYSTEMS = { npm: 'npm', composer: 'Packagist', pypi: 'PyPI', go: 'Go', cargo: 'crates.io', maven: 'Maven' };

/** Offizielle Docker-Images → Produkt (Tag „8.2.12-apache“ → PHP 8.2.12). */
const DOCKER_IMAGES = {
  httpd: 'apache', nginx: 'nginx', caddy: 'caddy', php: 'php', mariadb: 'mariadb', mysql: 'mysql', postgres: 'postgres',
  mongo: 'mongodb', redis: 'redis', node: 'node', python: 'python', golang: 'go', 'eclipse-temurin': 'java', openjdk: 'java',
};

/** Image „library/redis:7.2.4-alpine“ → { image, tag, product, version } (version nur, wenn der Tag eine Nummer trägt). */
function dockerImage(ref) {
  const s = String(ref || '').trim();
  if (!s) return null;
  const at = s.indexOf('@');
  const noDigest = at >= 0 ? s.slice(0, at) : s;
  const slash = noDigest.lastIndexOf('/');
  const colon = noDigest.lastIndexOf(':');
  const tag = colon > slash ? noDigest.slice(colon + 1) : 'latest';
  const repo = colon > slash ? noDigest.slice(0, colon) : noDigest;
  const parts = repo.split('/');
  // Nur Docker-Hub-Bibliothek („redis“, „library/redis“, „docker.io/library/redis“) – fremde Images heißen nur zufällig gleich
  const official = parts.length === 1 || (parts.length === 2 && parts[0] === 'library') || (parts.length === 3 && /^(docker\.io|registry-1\.docker\.io)$/.test(parts[0]) && parts[1] === 'library');
  const name = parts[parts.length - 1];
  const product = official ? DOCKER_IMAGES[name] || null : null;
  const vm = /^v?(\d+(?:\.\d+)*)/.exec(tag);
  return { image: repo, tag, product, version: vm ? vm[1] : null };
}

/*
 * Log4Shell in Minecraft: Server 1.7 bis 1.18.0 bringen ein verwundbares log4j mit (CVE-2021-44228). Mojang hat 1.18.1
 * repariert, Paper/Spigot/Purpur haben auch ältere Reihen ab dem 10.12.2021 nachgebessert – deshalb nur als „vielleicht“.
 * Die Beschreibung kommt live aus OSV (GHSA-jfh8-c2jp-5v3q, log4j-core).
 */
const MC_LOG4SHELL = { id: 'GHSA-jfh8-c2jp-5v3q', cve: 'CVE-2021-44228', from: '1.7', to: '1.18.0', fixed: '1.18.1' };

module.exports = { PRODUCTS, ECOSYSTEMS, DOCKER_IMAGES, dockerImage, MC_LOG4SHELL };
