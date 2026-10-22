![Vulnerability watch](banner.svg)

# Vulnerability watch

Every known vulnerability (CVE, CVSS) of your services at a glance – web servers, PHP, databases, runtimes, Docker images, Minecraft and project dependencies, matched to the installed version. With “actively exploited” (CISA KEV), likelihood of exploitation (EPSS), end of life, one-click updates, exceptions and alerts. Free sources without keys: OSV.dev, NVD, CISA, FIRST.

[Deutsch](README.de.md) · An official [Hostwerk](https://github.com/Passimoritz/hostwerk-public) extension (SDK 2.7, native extension)

## What it does

- **Where:** System → Vulnerabilities, plus the tabs in Web servers and Databases – no own sidebar entry since 1.1.0; the full page stays under Extensions → Open
- **Overview** with a traffic light and the number of findings per level (critical · high · medium · low), actively exploited, end of life and “Hostwerk can fix” – each number is a filter
- **List** by service (services on the left, their findings on the right) or by severity (groups you can fold, urgent ones open) – the page stays put, only the lists scroll; with search (CVE, service, package) and filters: only exploited, only fixable, area, show ignored
- **Detail view** per vulnerability: CVSS base score (v3.1/v4.0 where available) with level, the vector in plain words (attack over the network? login needed? does someone have to click?), CISA KEV with date and ransomware use, EPSS, affected and fixed version, links to NVD, OSV and the vendor
- **Fix**: if Hostwerk’s security updates can install the fixed version (PHP, databases, web servers), there is an **Update now** button – tested, with automatic rollback. Otherwise the way there: newer series on the service page, a Hostwerk update, or the command for a project package (`npm install lodash@4.17.21` …)
- **Does this affect me?** – notes only where Hostwerk can honestly tell: service only listens on this computer, Apache module not loaded, only on Windows/macOS, only together with other software (NVD AND configurations), installed from the system (distributions patch without a new version number), development dependency only, Paper builds with the Log4Shell fix
- **Exceptions**: ignore a finding with a reason and an optional date – after the date it comes back on its own
- **In your language**: the interface in German and English, CVSS features explained in both languages. Descriptions are shown in the original (mostly English, clearly labelled); when Hostwerk’s AI assistant is ready, it adds a short summary in the interface language – marked as AI translation
- **End of life** from Hostwerk’s own end-of-life watch (endoflife.date) as its own kind of finding
- **Notifications** for new critical or actively exploited findings, bundled into one message (desktop, push, Discord, ntfy, mail – Settings → Notifications); the first check only reports exploited ones, not the whole backlog
- Dashboard tile and tabs under *Web servers* and *Databases*; also listed under *Live → Watchers*

## What is checked

| Service | Version from | Source |
|---|---|---|
| Apache, nginx | Hostwerk’s web servers | NVD (CPE `apache:http_server`, `f5:nginx`/`nginx:nginx`) |
| Caddy | Hostwerk’s web servers | OSV (Go module `github.com/caddyserver/caddy/v2`) |
| PHP (every installed version) | Hostwerk’s PHP | NVD (`php:php`) + end of life |
| MariaDB, MySQL, PostgreSQL, MongoDB, Redis | Hostwerk’s databases | NVD + end of life |
| Node.js, Python, Go | runtimes Hostwerk loaded for apps | NVD (`nodejs:node.js`, `python:python`), OSV (`Go/stdlib`) |
| Java | runtimes, Minecraft | end of life only |
| Docker apps, Compose stacks, game servers in Docker | `image:tag` of official images (`redis:7.2.4-alpine` → Redis 7.2.4) – Compose stacks and game-server images through Hostwerk 3.0+ | like the program |
| Minecraft servers | type and version | Log4Shell (1.7–1.18.0); plugins are listed with their version |
| Game servers | Steam build id (extension “Game servers” 1.10+) | listed with version, without check (no database for games) |
| Hostwerk itself | Node.js and Electron it runs on | NVD, OSV (`npm/electron`) + end of life |
| Projects | `package-lock.json`, `composer.lock`, `poetry.lock`, `requirements.txt` (`==`), `go.mod`, `Cargo.lock` | OSV (npm, Packagist, PyPI, Go, crates.io) |

Without a database or exact version (Garnet, Bun, Deno, .NET, game servers, Docker tags like `latest`, Minecraft plugins) a service is listed under *What is checked* as “without check” – unknown is never shown as “no vulnerabilities”.

## Sources – and why they need no maintenance

| Source | What | How often |
|---|---|---|
| [OSV.dev](https://osv.dev) | packages and Go modules: `POST /v1/querybatch` (up to 500 per request), details only for new or changed entries | daily |
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | server programs by CPE (`virtualMatchString`): once all CVEs of a product, then only changes since the last request (`lastModStartDate`); every 30 days from scratch | daily |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | one JSON feed with all known exploited vulnerabilities | daily |
| [FIRST EPSS](https://www.first.org/epss/) | likelihood of exploitation, 80 CVEs per request | daily |

No keys, no accounts. Requests are bundled and throttled (NVD without a key: at least 6.5 s apart), 403/429/503 are answered with a growing pause (Retry-After is respected), and a source that asked for a break is left alone for a while. All answers are stored – if a source is down, the last state stays visible. In Hostwerk’s **offline mode** nothing is requested at all. The version matching itself is code (CPE ranges and OSV events), not a list someone has to keep up to date.

## Limits

- Matching is by version number. Distributions (Debian, Ubuntu, Alpine, RHEL) often fix vulnerabilities without changing the upstream version – programs installed from the system get a note instead of a false all-clear.
- CVSS 4.0 base scores come from the source; without one, the level from the source counts (computing v4 locally would need FIRST’s large lookup table).
- NVD CPE data are sometimes incomplete or late for new CVEs; OSV covers packages better than server programs.
- No CPE/database for: Garnet, Bun, Deno, .NET, Java distributions (Temurin), game servers, Minecraft plugins.

## Requirements

Hostwerk 3.0 or newer. It uses Hostwerk’s stable services (SDK 3.3) – security updates (`read:updates`, `change:updates`), the AI assistant for short summaries (`use:ai`), plugin versions (`read:minecraft`) and Docker images (`read:apps`); all read only except installing an update you clicked.

## Install

In Hostwerk: **Extensions → Discover** and click “Install”.

Native extensions run as part of Hostwerk (own server and interface part). That is why Hostwerk only installs them from the official catalogue (with checksum) or in developer mode.

## Data

`data/vuln-watch/` – `state.json` (findings, what was already reported), `inventory.json`, `ignores.json` (exceptions) and one cache file per source (`osv-*.json`, `nvd-*.json`, `kev.json`, `epss.json`, `status.json`). Removing the extension keeps the folder.

## Develop

```bash
node --test tests/*.test.js          # inventory, version matching, CVSS, sources with cache/offline/throttling – against fakes
node build-native.js .               # build the interface (sdk/build-native.js from hostwerk-public)
node check.js . --strict             # same check as the catalogue (sdk/check.js)
```

Inventory in `server/inventory.js` and `server/deps.js`, version matching in `server/version.js`, CVSS in `server/cvss.js`, sources in `server/sources.js` (network: `server/net.js`), assessment in `server/assess.js`, interface in `ui/src`. Texts in the code are English, German is in `locales/de.json`.

## License

MIT
