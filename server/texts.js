'use strict';
/*
 * Feste Texte – geteilt von Server (Benachrichtigungen, host.t) und Oberfläche (t aus @hostwerk/i18n).
 * Englisch ist der Quelltext, Deutsch steht in locales/de.json.
 */

const LEVEL_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'None', unknown: 'Unrated' };

const WHY = {
  'no-database': 'No vulnerability database for this program',
  'no-version': 'Version unknown',
  imprecise: 'Only the series is known – no exact version',
};

const DISTRO = { system: 'system package', debian: 'Debian', ubuntu: 'Ubuntu', alpine: 'Alpine', rhel: 'Red Hat' };

/** „Betrifft mich das?“ – ein Hinweis als Satz. */
function hintText(h, t) {
  switch (h.code) {
    case 'local-only': return t('The service only listens on this computer – an attack over the network does not reach it as long as it stays that way.');
    case 'distro': return t('Installed from the system ({distro}): distributions often ship security fixes without a new version number – check whether the package is already patched.', { distro: t(DISTRO[h.distro] || h.distro) });
    case 'conditional': return h.others && h.others.length ? t('Only affected together with: {others}.', { others: h.others.join(', ') }) : t('Only affected under certain conditions (together with other software).');
    case 'module-off': return t('Concerns {module} – this module is not loaded in this web server.', { module: h.module });
    case 'module-on': return t('Concerns {module} – this module is loaded in this web server.', { module: h.module });
    case 'other-os': return t('According to the description only {os} is affected – this computer runs a different system.', { os: h.os });
    case 'dev-only': return t('Only a development dependency – usually not part of what runs live.');
    case 'external': return t('Hostwerk did not install this program itself – updates come from wherever it was installed.');
    case 'mc-patched-builds': return t('Paper, Spigot, Purpur and Folia builds from 10 December 2021 on already contain the fix – updating to the latest build makes sure.');
    case 'mc-vanilla': return t('Fixed in Minecraft 1.18.1. Older versions need a newer server or the start option -Dlog4j2.formatMsgNoLookups=true.');
    default: return '';
  }
}

/** Weg zur Behebung als Satz. */
function fixText(f, t) {
  const x = f.fix || {};
  if (f.kind === 'eol') return x.kind === 'app' ? t('Comes with a Hostwerk update.') : x.to ? t('Switch to series {to} – it is still supported.', { to: x.to }) : t('Switch to a supported version.');
  if (x.kind === 'patch') return t('Hostwerk can install {to} itself – tested, with automatic rollback.', { to: x.to });
  if (x.kind === 'app') return x.to ? t('Fixed in {to} – comes with a Hostwerk update.', { to: x.to }) : t('Comes with a Hostwerk update.');
  if (x.kind === 'manual' && x.series) return t('Fixed in {to} – a newer series; switch over on the service page.', { to: x.to });
  if (x.kind === 'manual' && x.to) return t('Fixed in {to}.', { to: x.to });
  return t('No fixed version known yet.');
}

/** Befehl zum Aktualisieren eines Projekt-Pakets (nur Anzeige zum Kopieren). */
function pkgCommand(p, to) {
  if (!p) return null;
  const v = to ? `@${to}` : '@latest';
  if (p.ecosystem === 'npm') return `npm install ${p.name}${v}`;
  if (p.ecosystem === 'Packagist') return `composer require ${p.name}:${to ? `^${to}` : '*'} --update-with-dependencies`;
  if (p.ecosystem === 'PyPI') return `pip install "${p.name}${to ? `>=${to}` : ''}" --upgrade`;
  if (p.ecosystem === 'Go') return `go get ${p.name}${to ? `@v${to}` : '@latest'}`;
  if (p.ecosystem === 'crates.io') return `cargo update -p ${p.name}`;
  return null;
}

module.exports = { LEVEL_LABEL, WHY, DISTRO, hintText, fixText, pkgCommand };
