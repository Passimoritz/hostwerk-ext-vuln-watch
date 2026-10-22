![Schwachstellen-Wache](banner.svg)

# Schwachstellen-Wache

Alle bekannten Schwachstellen (CVE, CVSS) deiner Dienste auf einen Blick – Webserver, PHP, Datenbanken, Laufzeiten, Docker-Images, Minecraft und Projekt-Abhängigkeiten, passend zur installierten Version. Mit „wird aktiv ausgenutzt“ (CISA KEV), Ausnutzungs-Wahrscheinlichkeit (EPSS), Lebensende, Update per Knopf, Ausnahmen und Benachrichtigung. Freie Quellen ohne Schlüssel: OSV.dev, NVD, CISA, FIRST.

[English](README.md) · Eine offizielle [Hostwerk](https://github.com/Passimoritz/hostwerk-public)-Erweiterung (SDK 2.7, native Erweiterung)

## Was sie kann

- **Wo:** System → Schwachstellen, dazu die Reiter in Webserver und Datenbanken – seit 1.1.0 ohne eigenen Seitenleisten-Eintrag; die ganze Seite bleibt unter Erweiterungen → Öffnen
- **Übersicht** mit Ampel und Zahlen je Stufe (kritisch · hoch · mittel · niedrig), aktiv ausgenutzt, Lebensende und „Hostwerk behebt selbst“ – jede Zahl ist ein Filter
- **Liste** nach Dienst (links die Dienste, rechts ihre Funde) oder nach Schwere (zuklappbare Gruppen, Dringendes offen) – die Seite bleibt stehen, nur die Listen scrollen; mit Suche (CVE, Dienst, Paket) und Filtern: nur ausgenutzte, nur behebbare, Bereich, Ignorierte zeigen
- **Detailansicht** je Schwachstelle: CVSS-Basiswert (v3.1/v4.0, wo vorhanden) mit Stufe, der Vektor in Worten (Angriff über das Netz? Anmeldung nötig? Muss jemand klicken?), CISA KEV mit Datum und Einsatz durch Erpressungs-Software, EPSS, betroffene und behobene Version, Links zu NVD, OSV und Hersteller
- **Behebung**: Kann Hostwerks Sicherheits-Update die behobene Version einspielen (PHP, Datenbanken, Webserver), gibt es den Knopf **Jetzt aktualisieren** – mit Probelauf und automatischem Rücksprung. Sonst den Weg dorthin: neuere Reihe auf der Seite des Dienstes, ein Hostwerk-Update oder der Befehl für ein Projekt-Paket (`npm install lodash@4.17.21` …)
- **Betrifft mich das?** – Hinweise nur dort, wo Hostwerk es ehrlich ableiten kann: Dienst lauscht nur auf diesem Rechner, Apache-Modul nicht geladen, nur unter Windows/macOS, nur zusammen mit anderer Software (UND-Konfigurationen der NVD), aus dem System installiert (Distributionen bessern ohne neue Versionsnummer nach), nur Entwicklungs-Abhängigkeit, Paper-Builds mit Log4Shell-Fix
- **Ausnahmen**: einen Fund mit Grund und optionalem Datum ignorieren – nach dem Datum ist er von selbst wieder da
- **In deiner Sprache**: Oberfläche auf Deutsch und Englisch, CVSS-Merkmale in beiden Sprachen erklärt. Beschreibungen stehen im Original (meist Englisch, klar gekennzeichnet); ist Hostwerks KI-Helfer bereit, ergänzt er eine kurze Zusammenfassung in der Oberflächensprache – gekennzeichnet als KI-Übersetzung
- **Lebensende** aus Hostwerks eigener Lebensende-Wache (endoflife.date) als eigene Art von Fund
- **Benachrichtigung** bei neuen kritischen oder aktiv ausgenutzten Funden, gebündelt in einer Meldung (Desktop, Push, Discord, ntfy, Mail – Einstellungen → Benachrichtigungen); die erste Prüfung meldet nur Ausgenutztes, nicht den ganzen Altbestand
- Kachel für die Übersicht und Reiter unter *Webserver* und *Datenbanken*; steht außerdem unter *Livebetrieb → Wächter*

## Was geprüft wird

| Dienst | Version aus | Quelle |
|---|---|---|
| Apache, nginx | Hostwerks Webservern | NVD (CPE `apache:http_server`, `f5:nginx`/`nginx:nginx`) |
| Caddy | Hostwerks Webservern | OSV (Go-Modul `github.com/caddyserver/caddy/v2`) |
| PHP (jede installierte Version) | Hostwerks PHP | NVD (`php:php`) + Lebensende |
| MariaDB, MySQL, PostgreSQL, MongoDB, Redis | Hostwerks Datenbanken | NVD + Lebensende |
| Node.js, Python, Go | Laufzeiten, die Hostwerk für Apps geladen hat | NVD (`nodejs:node.js`, `python:python`), OSV (`Go/stdlib`) |
| Java | Laufzeiten, Minecraft | nur Lebensende |
| Docker-Apps, Compose-Stapel, Spiele-Server in Docker | `image:tag` offizieller Images (`redis:7.2.4-alpine` → Redis 7.2.4) – Compose-Stapel und Spiele-Server-Images über Hostwerk 3.0+ | wie das Programm |
| Minecraft-Server | Art und Version | Log4Shell (1.7–1.18.0); Plugins stehen mit Version im Bestand |
| Spiele-Server | Steam-Build-ID (Erweiterung „Spiele-Server“ ab 1.10) | mit Version im Bestand, ohne Prüfung (keine Datenbank für Spiele) |
| Hostwerk selbst | Node.js und Electron, auf denen es läuft | NVD, OSV (`npm/electron`) + Lebensende |
| Projekte | `package-lock.json`, `composer.lock`, `poetry.lock`, `requirements.txt` (`==`), `go.mod`, `Cargo.lock` | OSV (npm, Packagist, PyPI, Go, crates.io) |

Ohne Datenbank oder genaue Version (Garnet, Bun, Deno, .NET, Spiele-Server, Docker-Tags wie `latest`, Minecraft-Plugins) steht ein Dienst unter *Was geprüft wird* als „ohne Prüfung“ – unbekannt erscheint nie als „keine Schwachstellen“.

## Quellen – und warum sie ohne Wartung laufen

| Quelle | Was | Wie oft |
|---|---|---|
| [OSV.dev](https://osv.dev) | Pakete und Go-Module: `POST /v1/querybatch` (bis 500 je Abfrage), Details nur für neue oder geänderte Einträge | täglich |
| [NVD-API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | Server-Programme über CPE (`virtualMatchString`): einmal alle CVEs eines Produkts, danach nur Änderungen seit dem letzten Abruf (`lastModStartDate`); alle 30 Tage von vorn | täglich |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | ein JSON-Feed mit allen bekannt ausgenutzten Schwachstellen | täglich |
| [FIRST EPSS](https://www.first.org/epss/) | Wahrscheinlichkeit einer Ausnutzung, 80 CVEs je Abfrage | täglich |

Keine Schlüssel, keine Konten. Abfragen werden gebündelt und gedrosselt (NVD ohne Schlüssel: mindestens 6,5 s Abstand), auf 403/429/503 folgt eine wachsende Pause (Retry-After wird beachtet), und eine Quelle, die um eine Pause bittet, bleibt eine Weile in Ruhe. Alle Antworten werden gespeichert – fällt eine Quelle aus, bleibt der letzte Stand sichtbar. Im **Offline-Modus** von Hostwerk wird gar nichts abgefragt. Der Abgleich der Versionen ist Code (CPE-Bereiche und OSV-Ereignisse), keine Liste, die jemand pflegen muss.

## Grenzen

- Abgeglichen wird über die Versionsnummer. Distributionen (Debian, Ubuntu, Alpine, RHEL) beheben Lücken oft, ohne die Upstream-Version zu ändern – aus dem System installierte Programme bekommen deshalb einen Hinweis statt einer falschen Entwarnung.
- CVSS-4.0-Basiswerte kommen von der Quelle; fehlt einer, zählt die Stufe der Quelle (v4 selbst zu berechnen bräuchte die große Tabelle von FIRST).
- CPE-Angaben der NVD sind manchmal lückenhaft oder kommen bei neuen CVEs spät; OSV deckt Pakete besser ab als Server-Programme.
- Keine CPE/Datenbank für: Garnet, Bun, Deno, .NET, Java-Distributionen (Temurin), Spiele-Server, Minecraft-Plugins.

## Voraussetzungen

Hostwerk 3.0 oder neuer. Sie nutzt Hostwerks stabile Dienste (SDK 3.3) – Sicherheits-Updates (`read:updates`, `change:updates`), den KI-Helfer für Kurzfassungen (`use:ai`), Plugin-Versionen (`read:minecraft`) und Docker-Images (`read:apps`); alles nur lesend außer dem Einspielen eines Updates, das du anklickst.

## Installieren

In Hostwerk: **Erweiterungen → Entdecken** und „Installieren“ klicken.

Native Erweiterungen laufen als Teil von Hostwerk (eigener Server- und Oberflächen-Teil). Deshalb installiert Hostwerk sie nur aus dem offiziellen Katalog (mit Prüfsumme) oder im Entwickler-Modus.

## Daten

`data/vuln-watch/` – `state.json` (Funde, was schon gemeldet wurde), `inventory.json`, `ignores.json` (Ausnahmen) und eine Zwischenspeicher-Datei je Quelle (`osv-*.json`, `nvd-*.json`, `kev.json`, `epss.json`, `status.json`). Beim Entfernen der Erweiterung bleibt der Ordner erhalten.

## Entwickeln

```bash
node --test tests/*.test.js          # Bestand, Versions-Abgleich, CVSS, Quellen mit Zwischenspeicher/Offline/Drosselung – gegen Attrappen
node build-native.js .               # Oberfläche bauen (sdk/build-native.js aus hostwerk-public)
node check.js . --strict             # dieselbe Prüfung wie der Katalog (sdk/check.js)
```

Bestand in `server/inventory.js` und `server/deps.js`, Versions-Abgleich in `server/version.js`, CVSS in `server/cvss.js`, Quellen in `server/sources.js` (Netz: `server/net.js`), Bewertung in `server/assess.js`, Oberfläche in `ui/src`. Texte im Code sind Englisch, Deutsch steht in `locales/de.json`.

## Lizenz

MIT
