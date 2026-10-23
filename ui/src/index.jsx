import { useEffect, useMemo, useState } from 'react';
import {
  Shield, ShieldAlert, ShieldCheck, RefreshCw, Search, Flame, Clock, Wrench, ExternalLink, Copy, EyeOff, Eye, Sparkles, Languages,
  Server, Database, Code, Box, Gamepad2, Cpu, FolderGit2, Monitor, Puzzle, ChevronRight, ArrowUpCircle, Info, CircleAlert,
  CircleCheck, CircleMinus, OctagonAlert, TriangleAlert, CircleHelp, Layers, ListTree,
} from 'lucide-react';
import { post, put, del, useApi, fmtDate, openExternal } from '@hostwerk/api';
import { Btn, Modal, Seg, Field, Empty, Loading, Callout, InfoTip, TileEmpty, toast } from '@hostwerk/ui';
import * as HUI from '@hostwerk/ui';
import { useFill } from './fill';
import { contextMenu } from '@hostwerk/kit';
import { t, pl } from '@hostwerk/i18n';
import { parse, explain } from '../../server/cvss';
import { LEVEL_LABEL, WHY, hintText, fixText, pkgCommand } from '../../server/texts';
import './style.css';

// Seitenblatt aus Hostwerk (neuere Versionen) – die Seite bleibt daneben sichtbar; ältere Versionen zeigen denselben Inhalt als Dialog
const Sheet = HUI.SideSheet || Modal;

/*
 * Schwachstellen-Wache: Ampel und Zahlen je Stufe, Liste nach Dienst oder nach Schwere, Filter und Suche, Detailansicht mit
 * CVSS in Worten, „wird ausgenutzt“ (CISA KEV), EPSS, Behebung (Update per Knopf), Ausnahmen und KI-Kurzfassung.
 * Dazu eine Kachel für die Übersicht und Reiter unter Webserver und Datenbanken. Texte englisch, Deutsch aus locales/de.json.
 */
const ORDER = ['critical', 'high', 'medium', 'low', 'unknown'];
const RANK = { critical: 4, high: 3, medium: 2, low: 1, none: 0, unknown: 0 };
const LEVEL_ICON = { critical: OctagonAlert, high: TriangleAlert, medium: CircleAlert, low: Info, unknown: CircleHelp, none: CircleHelp };
const LEVEL_BADGE = { critical: 'err', high: 'err', medium: 'warn', low: 'info', unknown: '', none: '' };
const AREA = {
  web: { label: 'Web servers', icon: Server }, php: { label: 'PHP', icon: Code }, dbs: { label: 'Databases', icon: Database },
  runtimes: { label: 'Runtimes', icon: Cpu }, apps: { label: 'Docker apps', icon: Box }, minecraft: { label: 'Minecraft', icon: Puzzle },
  games: { label: 'Game servers', icon: Gamepad2 }, system: { label: 'Hostwerk itself', icon: Monitor }, projects: { label: 'Projects', icon: FolderGit2 },
};
const OVERALL = {
  critical: { title: 'Act now', text: 'There are critical or actively exploited vulnerabilities.', light: 'red' },
  high: { title: 'Update soon', text: 'Serious vulnerabilities – plan the update for the next days.', light: 'red' },
  medium: { title: 'Plan an update', text: 'Moderate vulnerabilities or versions near their end of life.', light: 'yellow' },
  low: { title: 'Minor issues', text: 'Only low-risk findings.', light: 'green' },
  ok: { title: 'No known vulnerabilities', text: 'Nothing known affects the installed versions.', light: 'green' },
};
const SOURCES = [
  { id: 'osv', label: 'OSV.dev', tip: 'Open database for packages (npm, Composer, PyPI, Go, crates.io) – also Caddy, Go and Electron.' },
  { id: 'nvd', label: 'NVD', tip: 'US National Vulnerability Database – server programs by their CPE name (Apache, nginx, PHP, databases, Node.js, Python).' },
  { id: 'kev', label: 'CISA KEV', tip: 'List of vulnerabilities that are known to be exploited in real attacks.' },
  { id: 'epss', label: 'EPSS', tip: 'FIRST’s estimate how likely an exploitation is within the next 30 days.' },
];
const pct = (x) => (x == null ? '–' : x >= 0.1 ? `${Math.round(x * 100)} %` : `${(x * 100).toFixed(1)} %`);
const levelOf = (f) => f.level || 'unknown';
const copy = (s) => navigator.clipboard.writeText(s).then(() => toast.success('Copied')).catch(() => {});
const nvdUrl = (id) => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`;
const osvUrl = (id) => `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
const openUrl = (e, url) => { e.preventDefault(); openExternal(url).catch(() => window.open(url, '_blank', 'noopener')); };

function LevelBadge({ f, compact = false }) {
  const lv = levelOf(f);
  const Icon = LEVEL_ICON[lv] || CircleHelp;
  const label = f.kind === 'eol' ? t('End of life') : t(LEVEL_LABEL[lv] || 'Unrated');
  return (
    <span className={`badge ${f.kind === 'eol' ? 'warn' : LEVEL_BADGE[lv]} vw-level vw-level-${lv}`} title={label}>
      <Icon size={12} aria-hidden="true" />{compact ? null : label}{f.score != null ? <b className="vw-score">{f.score.toFixed(1)}</b> : null}
    </span>
  );
}

function Lights({ overall, size = 'md' }) {
  const on = (OVERALL[overall] || OVERALL.ok).light;
  return (
    <span className={`vw-lights vw-lights-${size}`} role="img" aria-label={t((OVERALL[overall] || OVERALL.ok).title)}>
      {['red', 'yellow', 'green'].map((c) => <span key={c} className={`vw-light vw-light-${c} ${c === on ? 'lit' : ''}`} />)}
    </span>
  );
}

/** Kurzer Text, was gefunden wurde – für Liste und Kachel. */
function titleOf(f) {
  if (f.kind === 'eol') return f.eol && f.eol.state === 'eol' ? t('Series {cycle} no longer gets security updates', { cycle: f.eol.cycle || '' }) : t('Support for series {cycle} ends in {n} days', { cycle: (f.eol && f.eol.cycle) || '', n: (f.eol && f.eol.daysLeft) ?? '?' });
  return f.title || f.id;
}

function SourceChips({ d }) {
  return (
    <div className="vw-sources" role="list" aria-label={t('Sources')}>
      {SOURCES.map((s) => {
        const st = (d.sources || {})[s.id] || {};
        const state = st.offline ? 'off' : st.error ? 'warn' : st.at ? 'ok' : 'none';
        const Icon = state === 'ok' ? CircleCheck : state === 'none' ? CircleMinus : CircleAlert;
        const when = st.at ? t('updated {when}', { when: fmtDate(st.at) }) : t('not loaded yet');
        const tip = `${t(s.tip)} · ${when}${st.error ? ` · ${st.offline ? t('Offline mode – the last state stays visible.') : `${t('Last attempt failed:')} ${t(st.error)}`}` : ''}`;
        return <span key={s.id} role="listitem" className={`chip vw-src vw-src-${state}`} title={tip}><Icon size={12} aria-hidden="true" />{s.label}</span>;
      })}
    </div>
  );
}

function Summary({ d, filter, setFilter }) {
  const c = d.counts || {};
  const o = OVERALL[d.overall] || OVERALL.ok;
  const stat = (key, label, n, Icon, cls) => (
    <button type="button" className={`card stat vw-stat ${cls} ${filter === key ? 'on' : ''}`} aria-pressed={filter === key} onClick={() => setFilter(filter === key ? null : key)} title={t('Show only these')}>
      <div className="k"><Icon aria-hidden="true" />{label}</div>
      <div className="v">{n || 0}</div>
    </button>
  );
  // Eine Leiste statt zwei hoher Blöcke: Ampel + Urteil links (Erklärung als ⓘ), daneben die Zähler als Filter-Knöpfe
  return (
    <div className="vw-summary">
      <div className={`card vw-overall vw-overall-${d.overall || 'ok'}`}>
        <Lights overall={d.overall || 'ok'} size="sm" />
        <div className="grow vw-overall-text">
          <h2 className="row-tight">{t(o.title)}<InfoTip pop title={t(o.title)}>{t(o.text)}</InfoTip></h2>
          <p className="tiny muted">{d.at ? t('Checked {when}', { when: fmtDate(d.at) }) : t('Not checked yet')}</p>
        </div>
      </div>
      {/* Neuere Hostwerk-Versionen: Kern-Kennzahlleiste (StatBar) – sonst die eigenen Zähler-Knöpfe */}
      {HUI.StatBar ? (
        <HUI.StatBar label={t('Counts')} className="vw-statbar" items={[
          ['critical', t('Critical'), c.critical, OctagonAlert, 'err'], ['high', t('High'), c.high, TriangleAlert, 'err'], ['medium', t('Medium'), c.medium, CircleAlert, 'warn'],
          ['low', t('Low'), (c.low || 0) + (c.unknown || 0), Info, null], ['kev', t('Exploited'), c.kev, Flame, 'err'], ['eol', t('End of life'), c.eol, Clock, 'warn'], ['fixable', t('Hostwerk can fix'), c.fixable, Wrench, 'ok'],
        ].map(([key, label, n, icon, tone]) => ({ label, value: n || 0, icon, tone: n ? tone : null, active: filter === key, title: t('Show only these'), onClick: () => setFilter(filter === key ? null : key) }))} />
      ) : (
      <div className="vw-stats">
        {stat('critical', t('Critical'), c.critical, OctagonAlert, 'vw-stat-critical')}
        {stat('high', t('High'), c.high, TriangleAlert, 'vw-stat-high')}
        {stat('medium', t('Medium'), c.medium, CircleAlert, 'vw-stat-medium')}
        {stat('low', t('Low'), (c.low || 0) + (c.unknown || 0), Info, 'vw-stat-low')}
        {stat('kev', t('Exploited'), c.kev, Flame, 'vw-stat-kev')}
        {stat('eol', t('End of life'), c.eol, Clock, 'vw-stat-eol')}
        {stat('fixable', t('Hostwerk can fix'), c.fixable, Wrench, 'vw-stat-fix')}
      </div>
      )}
    </div>
  );
}

function FindingRow({ f, onOpen, onIgnore }) {
  const menu = (e) => contextMenu(e, [
    f.cve && { label: t('Copy ID'), icon: Copy, onClick: () => copy(f.cve) },
    f.kind === 'vuln' && { label: t('Open at NVD'), icon: ExternalLink, onClick: () => openExternal(f.cve ? nvdUrl(f.cve) : osvUrl(f.id)) },
    { label: f.ignored ? t('Remove exception') : t('Ignore …'), icon: f.ignored ? Eye : EyeOff, onClick: () => onIgnore(f) },
  ]);
  return (
    <li>
      <button type="button" className={`vw-row ${f.ignored ? 'vw-row-ignored' : ''}`} onClick={() => onOpen(f)} onContextMenu={menu}>
        <LevelBadge f={f} />
        <span className="vw-row-main">
          <span className="vw-row-title ellipsis" title={titleOf(f)}>{titleOf(f)}</span>
          <span className="tiny muted vw-row-sub">
            {f.kind === 'vuln' && <span className="mono">{f.id}</span>}
            {f.pkg && <span className="mono">{f.pkg.name} {f.pkg.version}</span>}
            {f.fixed && <span>{t('fixed in {v}', { v: f.fixed })}</span>}
            {f.ignored && <span>{t('ignored')}{f.ignored.reason ? `: ${f.ignored.reason}` : ''}</span>}
          </span>
        </span>
        <span className="vw-row-tags">
          {f.kev && <span className="badge err vw-kev" title={t('Known to be exploited in real attacks (CISA KEV)')}><Flame size={12} aria-hidden="true" />{t('Exploited')}</span>}
          {f.epss && f.epss.epss >= 0.01 && <span className="badge vw-epss" title={t('Likelihood of exploitation in the next 30 days (EPSS)')}>EPSS {pct(f.epss.epss)}</span>}
          {f.fix && f.fix.kind === 'patch' && <span className="badge ok" title={fixText(f, t)}><Wrench size={12} aria-hidden="true" />{t('Fixable')}</span>}
          {(f.hints || []).length > 0 && <span className="badge info" title={(f.hints || []).map((h) => hintText(h, t)).join('\n')}><Info size={12} aria-hidden="true" />{t('Note')}</span>}
        </span>
        <ChevronRight size={16} className="muted" aria-hidden="true" />
      </button>
    </li>
  );
}

const worstOf = (g) => g.findings.reduce((m, f) => Math.max(m, f.kev ? 5 : RANK[levelOf(f)]), 0);
const countsOf = (g) => ORDER.map((lv) => [lv, g.findings.filter((f) => f.kind === 'vuln' && levelOf(f) === lv && !f.ignored).length]).filter(([, n]) => n);

/** Funde eines Dienstes (rechte Seite der Ansicht „nach Dienst“): Kopf mit Update-Knopf, Liste scrollt in ihrer Fläche. */
function ServiceGroup({ g, onOpen, onIgnore, onUpdate, busyKey }) {
  const A = AREA[g.area] || AREA.system;
  const patch = g.findings.map((f) => f.fix).find((x) => x && x.kind === 'patch');
  const href = g.findings[0] && g.findings[0].fix && g.findings[0].fix.href;
  return (
    <section className={`card vw-group vw-detail-pane vw-worst-${worstOf(g)}`} aria-label={g.name}>
      <div className="card-head">
        <A.icon size={16} aria-hidden="true" />
        <h3 className="ellipsis grow" title={g.name}>{g.name}{g.version ? <span className="muted vw-ver"> {g.version}</span> : null}</h3>
        <span className="badge">{g.findings.length}</span>
        {patch && <Btn className="primary sm" icon={ArrowUpCircle} busy={busyKey === patch.key} onClick={() => onUpdate(patch.key)} title={t('Hostwerk installs {to} – tested, with automatic rollback.', { to: patch.to })}>{t('Update to {to}', { to: patch.to })}</Btn>}
        {!patch && href && <a className="btn ghost sm" href={href} title={t('Open the service')}><ExternalLink size={14} aria-hidden="true" />{t('Open')}</a>}
      </div>
      <ul className="vw-list vw-scroll">{g.findings.map((f) => <FindingRow key={f.key} f={f} onOpen={onOpen} onIgnore={onIgnore} />)}</ul>
    </section>
  );
}

/** Linke Liste der Dienste mit Zählern – Pfeiltasten wechseln den Dienst (Muster wie eine Listbox). */
function ServiceNav({ groups, sel, onSel }) {
  const keys = (e) => {
    const i = groups.findIndex((g) => g.id === sel);
    const n = e.key === 'ArrowDown' ? i + 1 : e.key === 'ArrowUp' ? i - 1 : e.key === 'Home' ? 0 : e.key === 'End' ? groups.length - 1 : null;
    if (n == null || !groups[n]) return;
    e.preventDefault(); onSel(groups[n].id);
    const el = e.currentTarget.querySelector(`[data-key="${CSS.escape(String(groups[n].id))}"]`); if (el) el.focus();
  };
  return (
    <nav className="card vw-nav" aria-label={t('Services')}>
      <ul className="vw-scroll" onKeyDown={keys}>
        {groups.map((g) => {
          const A = AREA[g.area] || AREA.system;
          const on = g.id === sel;
          return (
            <li key={g.id}>
              <button type="button" data-key={g.id} className={`vw-nav-item vw-worst-${worstOf(g)} ${on ? 'on' : ''}`} aria-current={on ? 'true' : undefined} tabIndex={on ? 0 : -1} onClick={() => onSel(g.id)}>
                <A.icon size={15} aria-hidden="true" />
                <span className="grow vw-nav-main">
                  <span className="ellipsis" title={g.name}>{g.name}{g.version ? <span className="muted vw-ver"> {g.version}</span> : null}</span>
                  <span className="vw-group-counts">
                    {g.findings.some((f) => f.kev) && <span className="badge err" title={t('Exploited')}><Flame size={11} aria-hidden="true" />{g.findings.filter((f) => f.kev).length}</span>}
                    {countsOf(g).map(([lv, n]) => <span key={lv} className={`badge ${LEVEL_BADGE[lv]}`} title={t(LEVEL_LABEL[lv])}>{n} {t(LEVEL_LABEL[lv])}</span>)}
                    {g.findings.some((f) => f.kind === 'eol') && <span className="badge warn" title={t('End of life')}><Clock size={11} aria-hidden="true" />{t('End of life')}</span>}
                  </span>
                </span>
                <ChevronRight size={14} className="muted" aria-hidden="true" />
              </button>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

/** Eine Gruppe der Ansicht „nach Schwere“ – zuklappbar; offen sind nur die dringenden (ausgenutzt, kritisch). */
function SeverityGroup({ g, label, Icon, onOpen, onIgnore }) {
  const [open, setOpen] = useState(g.id === 'kev' || g.id === 'critical');
  return (
    <section className={`vw-sev vw-sev-${g.id}`} aria-label={t(label)}>
      <button type="button" className="vw-sev-head" aria-expanded={open} onClick={() => setOpen(!open)}>
        <ChevronRight size={14} className={open ? 'vw-rot' : ''} aria-hidden="true" />
        <Icon size={15} aria-hidden="true" /><b className="grow">{t(label)}</b><span className="badge">{g.findings.length}</span>
      </button>
      {open && <ul className="vw-list">{g.findings.map((f) => <FindingRow key={f.key} f={{ ...f, title: `${f.itemName}: ${titleOf(f)}` }} onOpen={onOpen} onIgnore={onIgnore} />)}</ul>}
    </section>
  );
}

function IgnoreDialog({ f, onClose, onSaved }) {
  const [reason, setReason] = useState('');
  const [until, setUntil] = useState('');
  const [busy, setBusy] = useState(false);
  const save = async () => {
    setBusy(true);
    try { onSaved(await put('/vuln-watch/ignore', { key: f.key, reason, until: until || null })); toast.success('Exception saved'); onClose(); } catch (e) { toast.error(e); }
    setBusy(false);
  };
  return (
    <Modal title={t('Ignore {id}', { id: f.kind === 'eol' ? t('End of life') : f.id })} subtitle={`${f.itemName}${f.pkg ? ` · ${f.pkg.name}` : ''}`} onClose={onClose}
      footer={<><Btn onClick={onClose}>Cancel</Btn><Btn className="primary" icon={EyeOff} busy={busy} onClick={save} disabled={!reason.trim()}>Ignore</Btn></>}>
      <div className="stack">
        <Field label={t('Why does it not matter here?')}>
          <input className="input" value={reason} maxLength={300} onChange={(e) => setReason(e.target.value)} placeholder={t('e.g. module not used, only reachable in the home network')} aria-label={t('Why does it not matter here?')} autoFocus />
        </Field>
        <Field label={t('Ignore until (optional)')}>
          <input className="input" type="date" value={until} onChange={(e) => setUntil(e.target.value)} aria-label={t('Ignore until (optional)')} />
        </Field>
        <p className="tiny muted">{t('Ignored findings no longer count and do not trigger notifications. After the date they come back on their own.')}</p>
      </div>
    </Modal>
  );
}

/** KI-Kurzfassung in der Oberflächensprache – nur, wenn der KI-Helfer bereit ist. */
function AiSummary({ f, lang, ready }) {
  const [st, setSt] = useState(null);
  const run = async () => { setSt('busy'); try { setSt({ text: (await post('/vuln-watch/ai', { key: f.key })).text }); } catch (e) { setSt({ error: e.message }); } };
  useEffect(() => { setSt(null); if (ready && lang !== 'en' && f.details) run(); }, [f.key, ready]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!ready || !f.details) return null;
  if (!st) return <Btn className="ghost sm ai" icon={Sparkles} onClick={run}>Summarize in plain words</Btn>;
  return (
    <div className="vw-ai" aria-live="polite">
      <div className="tiny muted row-tight"><Languages size={13} aria-hidden="true" />{lang === 'en' ? t('AI summary') : t('AI translation and summary')}<InfoTip pop title={t('AI summary')}>Written by Hostwerk’s AI assistant from the original text below. It can be wrong – the original counts.</InfoTip></div>
      {st === 'busy' ? <p className="small muted">{t('The AI is reading …')}</p> : st.error ? <p className="small c-warn">{st.error}</p> : <p className="small vw-pre">{st.text}</p>}
    </div>
  );
}

function Detail({ fKey, lang, aiReady, onClose, onChanged, onUpdate, busyKey }) {
  const d = useApi(`/vuln-watch/detail?key=${encodeURIComponent(fKey)}`, [fKey], { live: false });
  const [ignoring, setIgnoring] = useState(false);
  const f = d.data;
  const p = f && f.vector ? parse(f.vector) : null;
  const parts = p ? explain(p, t) : [];
  const unignore = async () => { try { onChanged(await del(`/vuln-watch/ignore?key=${encodeURIComponent(f.key)}`)); d.reload(); toast.success('Exception removed'); } catch (e) { toast.error(e); } };
  const cmd = f && f.pkg ? pkgCommand(f.pkg, f.fixed) : null;
  return (
    <Modal size="wide" title={f ? (f.kind === 'eol' ? `${t('End of life')}: ${f.itemName}` : f.id) : t('Vulnerability')} subtitle={f ? `${f.itemName}${f.version ? ` ${f.version}` : ''}${f.pkg ? ` · ${f.pkg.name} ${f.pkg.version}` : ''}` : null} onClose={onClose}>
      {d.loading && !f ? <Loading /> : d.error ? <Callout kind="err" dismissible={false}>{d.error}</Callout> : f && (
        <div className="stack vw-detail">
          <div className="row-tight vw-detail-head">
            <LevelBadge f={f} />
            {f.cvssVersion && <span className="tiny muted">CVSS {f.cvssVersion}</span>}
            {f.cwe && f.cwe.length > 0 && <span className="tiny muted mono">{f.cwe.join(', ')}</span>}
            {f.published && <span className="tiny muted">{t('published {when}', { when: fmtDate(f.published) })}</span>}
            {f.ids && f.ids.length > 1 && <span className="tiny muted mono">{f.ids.filter((x) => x !== f.id).join(' · ')}</span>}
          </div>
          {f.kev && (
            <Callout kind="err" dismissible={false} icon={Flame} title={t('Actively exploited')}>
              {t('Known to be used in real attacks since {when} (CISA KEV).', { when: f.kev.added || '?' })}{f.kev.ransomware ? ` ${t('Also used by ransomware.')}` : ''}
            </Callout>
          )}
          {f.ignored && (
            <Callout kind="info" dismissible={false} icon={EyeOff} title={t('Ignored')}>
              {f.ignored.reason || t('No reason given.')}{f.ignored.until ? ` ${t('Until {when}.', { when: fmtDate(f.ignored.until) })}` : ''} <Btn className="ghost sm" icon={Eye} onClick={unignore}>Remove exception</Btn>
            </Callout>
          )}

          {f.kind === 'eol' ? (
            <section className="vw-sec">
              <h4>What it means</h4>
              <p className="small">{f.eol && f.eol.state === 'eol' ? t('Series {cycle} has reached its end of life{date} – new vulnerabilities are no longer fixed.', { cycle: f.eol.cycle || '', date: f.eol.eolAt ? ` (${fmtDate(f.eol.eolAt)})` : '' }) : t('Support for series {cycle} ends on {date} – after that, vulnerabilities are no longer fixed.', { cycle: (f.eol && f.eol.cycle) || '', date: f.eol && f.eol.eolAt ? fmtDate(f.eol.eolAt) : '?' })}</p>
            </section>
          ) : (
            <section className="vw-sec">
              <h4>What it is</h4>
              <AiSummary f={f} lang={lang} ready={aiReady} />
              <div className="vw-orig">
                <div className="tiny muted row-tight"><Languages size={13} aria-hidden="true" />{t('Original description (English)')}</div>
                <p className="small vw-pre">{f.details || f.title || t('The source has no description yet.')}</p>
              </div>
            </section>
          )}

          {parts.length > 0 && (
            <section className="vw-sec">
              <h4 className="row-tight">How an attack works<InfoTip pop title="CVSS">CVSS describes a vulnerability with a few features. The base score (0–10) combines them – it says how bad the flaw is in general, not how exposed your computer is.</InfoTip></h4>
              <dl className="vw-cvss">
                {parts.map((x) => (
                  <div key={x.key} className={`vw-cvss-${x.risk}`}>
                    <dt className="muted small">{x.label}</dt>
                    <dd className="small row-tight">{x.risk === 'high' ? <CircleAlert size={14} className="c-err" aria-label={t('makes it worse')} /> : x.risk === 'mid' ? <CircleMinus size={14} className="c-warn" aria-label={t('medium')} /> : <CircleCheck size={14} className="c-ok" aria-label={t('makes it harder')} />}{x.value}</dd>
                  </div>
                ))}
              </dl>
              <p className="tiny muted mono vw-vector" title={t('CVSS vector')}>{f.vector}</p>
            </section>
          )}

          {f.epss && (
            <section className="vw-sec">
              <h4 className="row-tight">Likelihood of exploitation<InfoTip pop title="EPSS">FIRST’s Exploit Prediction Scoring System estimates how likely an attack on this vulnerability is within the next 30 days.</InfoTip></h4>
              <div className="vw-epss-bar" role="progressbar" aria-label="EPSS" aria-valuenow={Math.round(f.epss.epss * 100)} aria-valuemin={0} aria-valuemax={100}><div style={{ width: `${Math.max(1, Math.round(f.epss.epss * 100))}%` }} /></div>
              <p className="small">{t('{p} within the next 30 days – higher than {q} of all known vulnerabilities.', { p: pct(f.epss.epss), q: pct(f.epss.pct) })}</p>
            </section>
          )}

          <section className="vw-sec">
            <h4>Fix</h4>
            <dl className="kv">
              <dt>Installed</dt><dd className="mono">{f.pkg ? f.pkg.version : f.version || '–'}</dd>
              {f.introduced && f.introduced !== '0' && <><dt>Affected since</dt><dd className="mono">{f.introduced}</dd></>}
              <dt>Fixed in</dt><dd className="mono">{f.fixed || (f.kind === 'eol' && f.fix && f.fix.to) || '–'}</dd>
            </dl>
            <p className="small">{fixText(f, t)}</p>
            {f.kev && f.kev.action && <p className="small muted">{t('CISA recommends:')} {f.kev.action}</p>}
            <div className="row-tight vw-actions">
              {f.fix && f.fix.kind === 'patch' && <Btn className="primary" icon={ArrowUpCircle} busy={busyKey === f.fix.key} onClick={() => onUpdate(f.fix.key)}>{t('Update now to {to}', { to: f.fix.to })}</Btn>}
              {f.fix && f.fix.kind === 'app' && <a className="btn" href="#/settings/updates" onClick={onClose}><ArrowUpCircle size={14} aria-hidden="true" />{t('Hostwerk updates')}</a>}
              {f.fix && f.fix.href && f.fix.kind !== 'app' && <a className="btn ghost" href={f.fix.href} onClick={onClose}><ExternalLink size={14} aria-hidden="true" />{t('Open the service')}</a>}
              {cmd && <Btn className="ghost" icon={Copy} onClick={() => copy(cmd)} title={cmd}>Copy update command</Btn>}
            </div>
            {cmd && <p className="tiny muted mono vw-cmd">{cmd}</p>}
          </section>

          <section className="vw-sec">
            <h4 className="row-tight">Does this affect me?<InfoTip pop title={t('Does this affect me?')}>Hostwerk only says what it can really tell from its own setup. Without a note the version matches – that does not prove an attack works, but it is worth fixing.</InfoTip></h4>
            {(f.hints || []).length ? <ul className="vw-hints">{f.hints.map((h, i) => <li key={i} className="small"><Info size={14} aria-hidden="true" /><span>{hintText(h, t)}</span></li>)}</ul> : <p className="small muted">{t('The installed version is in the affected range. Hostwerk knows nothing that would rule it out.')}</p>}
          </section>

          {f.kind === 'vuln' && (
            <section className="vw-sec">
              <h4>Links</h4>
              <ul className="vw-links small">
                {f.cve && <li><a href={nvdUrl(f.cve)} onClick={(e) => openUrl(e, nvdUrl(f.cve))}><ExternalLink size={13} aria-hidden="true" />NVD: {f.cve}</a></li>}
                {f.ids.filter((x) => !/^CVE-/.test(x)).slice(0, 2).map((id) => <li key={id}><a href={osvUrl(id)} onClick={(e) => openUrl(e, osvUrl(id))}><ExternalLink size={13} aria-hidden="true" />OSV: {id}</a></li>)}
                {(f.refs || []).slice(0, 8).map((r) => <li key={r.url}><a href={r.url} onClick={(e) => openUrl(e, r.url)} className="ellipsis" title={r.url}><ExternalLink size={13} aria-hidden="true" />{(r.tags && r.tags.length ? `${r.tags.join(', ')}: ` : '') + r.url.replace(/^https?:\/\//, '').slice(0, 90)}</a></li>)}
              </ul>
            </section>
          )}

          {!f.ignored && <div className="row-tight"><Btn className="ghost sm" icon={EyeOff} onClick={() => setIgnoring(true)}>Ignore …</Btn></div>}
          {ignoring && <IgnoreDialog f={f} onClose={() => setIgnoring(false)} onSaved={(v) => { onChanged(v); d.reload(); }} />}
        </div>
      )}
    </Modal>
  );
}

/** Gefilterte und gruppierte Liste – gebraucht von der Seite und den Reitern in Webserver/Datenbanken. */
function FindingList({ d, setData, areas = null, initialFilter = null, compact = false, foot = null }) {
  const [q, setQ] = useState('');
  const [group, setGroup] = useState('service');
  const [stat, setStat] = useState(initialFilter);
  const [area, setArea] = useState('');
  const [kevOnly, setKevOnly] = useState(false);
  const [fixOnly, setFixOnly] = useState(false);
  const [showIgnored, setShowIgnored] = useState(false);
  const [open, setOpen] = useState(null);
  const [ignoreFor, setIgnoreFor] = useState(null);
  const [busyKey, setBusyKey] = useState(null);
  const ai = useApi('/vuln-watch/ai', [], { live: false });

  const all = useMemo(() => (d.findings || []).filter((f) => !areas || areas.includes(f.area)), [d.findings, areas]);
  const list = useMemo(() => {
    const s = q.trim().toLowerCase();
    return all.filter((f) => {
      if (f.ignored && !showIgnored) return false;
      if (kevOnly && !f.kev) return false;
      if (fixOnly && !(f.fix && f.fix.kind === 'patch')) return false;
      if (area && f.area !== area) return false;
      if (stat === 'kev' && !f.kev) return false;
      if (stat === 'eol' && f.kind !== 'eol') return false;
      if (stat === 'fixable' && !(f.fix && f.fix.kind === 'patch')) return false;
      if (['critical', 'high', 'medium'].includes(stat) && (f.kind !== 'vuln' || levelOf(f) !== stat)) return false;
      if (stat === 'low' && (f.kind !== 'vuln' || !['low', 'unknown', 'none'].includes(levelOf(f)))) return false;
      if (s && ![f.id, f.title, f.itemName, f.pkg && f.pkg.name, ...(f.ids || [])].some((x) => x && String(x).toLowerCase().includes(s))) return false;
      return true;
    });
  }, [all, q, showIgnored, kevOnly, fixOnly, area, stat]);

  const groups = useMemo(() => {
    const by = new Map();
    if (group === 'service') {
      for (const f of list) { if (!by.has(f.item)) by.set(f.item, { id: f.item, name: f.itemName, version: f.pkg ? null : f.version, area: f.area, findings: [] }); by.get(f.item).findings.push(f); }
      return [...by.values()].sort((a, b) => Math.max(...b.findings.map((f) => (f.kev ? 5 : RANK[levelOf(f)]))) - Math.max(...a.findings.map((f) => (f.kev ? 5 : RANK[levelOf(f)]))) || b.findings.length - a.findings.length);
    }
    for (const lv of ['kev', 'eol', ...ORDER]) by.set(lv, { id: lv, findings: [] });
    for (const f of list) by.get(f.kev ? 'kev' : f.kind === 'eol' ? 'eol' : ORDER.includes(levelOf(f)) ? levelOf(f) : 'unknown').findings.push(f);
    return [...by.values()].filter((g) => g.findings.length);
  }, [list, group]);

  // Gewählter Dienst der linken Liste; fällt er durch Filter weg, gilt der dringendste
  const [sel, setSel] = useState(null);
  const selGroup = group === 'service' ? (groups.find((g) => g.id === sel) || groups[0]) : null;
  const fill = useFill({ min: 220 });
  const usedAreas = [...new Set(all.map((f) => f.area))];
  const onUpdate = async (key) => {
    setBusyKey(key);
    try {
      const r = await post('/vuln-watch/update', { key });
      setData(r);
      if (r.result && r.result.ok) toast.success('Installed and checked'); else toast.warn(t('The test run failed – the old version stays active.'));
    } catch (e) { toast.error(e); }
    setBusyKey(null);
  };
  const onIgnore = async (f) => {
    if (!f.ignored) { setIgnoreFor(f); return; }
    try { setData(await del(`/vuln-watch/ignore?key=${encodeURIComponent(f.key)}`)); toast.success('Exception removed'); } catch (e) { toast.error(e); }
  };
  const GROUP_TITLE = { kev: ['Actively exploited', Flame], eol: ['End of life', Clock], critical: ['Critical', OctagonAlert], high: ['High', TriangleAlert], medium: ['Medium', CircleAlert], low: ['Low', Info], unknown: ['Unrated', CircleHelp] };

  return (
    <>
      {!compact && <Summary d={d} filter={stat} setFilter={setStat} />}
      {foot}
      <div className="vw-toolbar">
        <div className="input-icon grow vw-search"><Search aria-hidden="true" /><input className="input sm" type="search" placeholder={t('Search CVE, service or package …')} aria-label={t('Search')} value={q} onChange={(e) => setQ(e.target.value)} /></div>
        <Seg value={group} onChange={setGroup} options={[{ id: 'service', label: t('By service'), icon: Layers }, { id: 'severity', label: t('By severity'), icon: ListTree }]} />
        {!areas && usedAreas.length > 1 && (
          <select className="input sm select vw-area" value={area} onChange={(e) => setArea(e.target.value)} aria-label={t('Area')}>
            <option value="">{t('All areas')}</option>
            {usedAreas.map((a) => <option key={a} value={a}>{t((AREA[a] || { label: a }).label)}</option>)}
          </select>
        )}
        <div className="row-tight vw-chips" role="group" aria-label={t('Filter')}>
          {compact && <select className="input sm select" value={stat || ''} onChange={(e) => setStat(e.target.value || null)} aria-label={t('Severity')}>
            <option value="">{t('All severities')}</option>
            {['critical', 'high', 'medium', 'low'].map((lv) => <option key={lv} value={lv}>{t(LEVEL_LABEL[lv])}</option>)}
          </select>}
          <button type="button" className={`chip-toggle ${kevOnly ? 'on' : ''}`} aria-pressed={kevOnly} onClick={() => setKevOnly(!kevOnly)}><Flame size={12} aria-hidden="true" />{t('Only exploited')}</button>
          <button type="button" className={`chip-toggle ${fixOnly ? 'on' : ''}`} aria-pressed={fixOnly} onClick={() => setFixOnly(!fixOnly)}><Wrench size={12} aria-hidden="true" />{t('Only fixable')}</button>
          <button type="button" className={`chip-toggle ${showIgnored ? 'on' : ''}`} aria-pressed={showIgnored} onClick={() => setShowIgnored(!showIgnored)}><EyeOff size={12} aria-hidden="true" />{t('Show ignored')}{d.counts && d.counts.ignored ? ` (${d.counts.ignored})` : ''}</button>
        </div>
      </div>
      {!list.length ? (
        all.length ? <Empty icon={Search} title="Nothing matches" text="Change the search or the filters." /> : <Empty icon={ShieldCheck} title="No known vulnerabilities" text="Nothing known affects the installed versions here." />
      ) : group === 'service' ? (
        // Links die Dienste mit Zählern, rechts die Funde des gewählten – die Seite scrollt nicht, nur die beiden Listen
        <div className="vw-md" ref={fill}>
          <ServiceNav groups={groups} sel={selGroup && selGroup.id} onSel={setSel} />
          {selGroup && <ServiceGroup key={selGroup.id} g={selGroup} onOpen={(f) => setOpen(f.key)} onIgnore={onIgnore} onUpdate={onUpdate} busyKey={busyKey} />}
        </div>
      ) : (
        <div className="card vw-sev-list vw-scroll" ref={fill}>
          {groups.map((g) => { const [label, Icon] = GROUP_TITLE[g.id]; return <SeverityGroup key={g.id} g={g} label={label} Icon={Icon} onOpen={(x) => setOpen(x.key)} onIgnore={onIgnore} />; })}
        </div>
      )}
      {open && <Detail fKey={open} lang={d.lang} aiReady={!!(ai.data && ai.data.ready)} onClose={() => setOpen(null)} onChanged={setData} onUpdate={onUpdate} busyKey={busyKey} />}
      {ignoreFor && <IgnoreDialog f={ignoreFor} onClose={() => setIgnoreFor(null)} onSaved={setData} />}
    </>
  );
}

/** „Was wird geprüft“: Knopf mit Zählern, der Bestand steht im Dialog statt unter der Liste. */
function Unchecked({ d }) {
  const [openList, setOpenList] = useState(false);
  const list = d.unchecked || [];
  const checked = (d.inventory || []).filter((x) => !x.why);
  const pkgs = (d.inventory || []).reduce((n, x) => n + (x.packages || 0), 0);
  const label = `${t('What is checked: {n} services', { n: checked.length })}${pkgs ? ` · ${pl(pkgs, '{n} package', '{n} packages')}` : ''}${list.length ? ` · ${t('{n} without check', { n: list.length })}` : ''}`;
  return (
    <>
      <button type="button" className="link-btn tiny vw-inv-btn" onClick={() => setOpenList(true)}>{label} …</button>
      {openList && (
        <Sheet size="wide" title={t('What is checked')} subtitle={label} onClose={() => setOpenList(false)} footer={<Btn onClick={() => setOpenList(false)}>Close</Btn>}>
          <div className="table-wrap">
            <table className="table vw-inv-table small">
              <thead><tr><th scope="col">{t('Service')}</th><th scope="col">{t('Program')}</th><th scope="col">{t('Version')}</th><th scope="col">{t('Check')}</th></tr></thead>
              <tbody>
                {(d.inventory || []).map((x) => (
                  <tr key={x.id}>
                    <td className="ellipsis">{x.name}</td>
                    <td className="muted">{x.label || (x.image ? x.image : x.files ? x.files.join(', ') : '–')}</td>
                    <td className="mono">{x.packages != null ? pl(x.packages, '{n} package', '{n} packages') : x.version || '–'}{x.distro ? <span className="muted"> ({t('system package')})</span> : null}{x.local ? <span className="muted"> · {t('local only')}</span> : null}</td>
                    <td>{x.why ? <span className="muted">{t(WHY[x.why] || x.why)}</span> : <span className="c-ok row-tight"><CircleCheck size={13} aria-hidden="true" />{t('checked')}</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Sheet>
      )}
    </>
  );
}

function VulnPage() {
  const st = useApi('/vuln-watch', [], { live: false });
  const [busy, setBusy] = useState(false);
  const d = st.data;
  const refresh = async (force = false) => {
    setBusy(true);
    try { st.setData(await post('/vuln-watch/refresh', { force })); } catch (e) { toast.error(e); }
    setBusy(false);
  };
  const blocked = d ? Object.entries(d.blocked || {}) : [];
  return (
    <div className="page fade-in vw-page">
      <div className="page-head">
        <div>
          <h1><Shield /> Vulnerabilities</h1>
          <p>Known vulnerabilities of everything Hostwerk runs – matched to the installed version, ordered by severity.</p>
        </div>
        <div className="actions">
          <Btn className="primary" icon={RefreshCw} busy={busy || (d && d.running)} onClick={() => refresh(false)} onContextMenu={(e) => contextMenu(e, [{ label: t('Reload all sources'), icon: RefreshCw, onClick: () => refresh(true) }])}>Check now</Btn>
        </div>
      </div>
      {st.error && <Callout kind="err" dismissible={false}>{st.error}</Callout>}
      {d && d.offline && <Callout kind="info" dismissible={false} title="Offline mode is on">Hostwerk does not ask the vulnerability databases right now. You see the last known state.</Callout>}
      {blocked.length > 0 && <Callout kind="warn" title="A source asked for a break">{t('{host} limits requests without a key – the next attempt follows automatically.', { host: blocked.map(([h]) => h).join(', ') })}</Callout>}
      {st.loading && !d ? <Loading /> : !d || !d.at ? (
        <Empty icon={ShieldAlert} title="Not checked yet" text="The first check runs a few minutes after Hostwerk starts – or right now." action={<Btn className="primary" icon={RefreshCw} busy={busy} onClick={() => refresh(false)}>Check now</Btn>} />
      ) : (
        <>
          <FindingList d={d} setData={st.setData} foot={(
            <div className="row-tight tiny muted vw-foot">
              <Unchecked d={d} />
              <SourceChips d={d} />
              <InfoTip pop title="Sources">Free databases without a key: OSV.dev, the NVD (by CPE), CISA’s list of exploited vulnerabilities and FIRST’s EPSS. Hostwerk asks once a day, bundled and throttled, and keeps the answers – if a source is down, the last state stays. New critical or exploited findings go to Hostwerk’s notifications (Settings → Notifications).</InfoTip>
            </div>
          )} />
        </>
      )}
    </div>
  );
}

/** Kachel: Ampel, Zahlen und die drei wichtigsten Funde. */
function VulnTile() {
  const st = useApi('/vuln-watch', [], { live: false });
  const d = st.data;
  if (st.loading && !d) return <div className="card-body"><div className="skeleton vw-skel" /></div>;
  if (!d || !d.at) return <TileEmpty icon={ShieldAlert} text="Not checked yet" href="#/ext/vuln-watch" />;
  const c = d.counts || {};
  const top = (d.findings || []).filter((f) => !f.ignored).slice(0, 3);
  return (
    <div className="card-body stack vw-tile">
      <a className="row-tight vw-tile-head" href="#/ext/vuln-watch">
        <Lights overall={d.overall || 'ok'} size="sm" />
        <b className="grow">{t((OVERALL[d.overall] || OVERALL.ok).title)}</b>
      </a>
      <div className="row-tight vw-tile-counts small">
        {c.kev ? <span className="badge err"><Flame size={12} aria-hidden="true" />{c.kev} {t('exploited')}</span> : null}
        {['critical', 'high', 'medium'].map((lv) => (c[lv] ? <span key={lv} className={`badge ${LEVEL_BADGE[lv]}`}>{c[lv]} {t(LEVEL_LABEL[lv])}</span> : null))}
        {c.eol ? <span className="badge warn">{c.eol} {t('End of life')}</span> : null}
        {!c.total && <span className="muted">{t('Nothing known')}</span>}
      </div>
      {top.map((f) => (
        <a key={f.key} className="row-tight vw-tile-row" href="#/ext/vuln-watch" title={titleOf(f)}>
          <LevelBadge f={f} compact />
          <span className="grow ellipsis small">{f.itemName}: {f.kind === 'eol' ? t('End of life') : f.id}</span>
        </a>
      ))}
    </div>
  );
}

/** Reiter in Webserver und Datenbanken: dieselbe Liste, nur dieser Bereich. */
function areaTab(areas) {
  return function AreaTab() {
    const st = useApi('/vuln-watch', [], { live: false });
    const d = st.data;
    if (st.loading && !d) return <Loading />;
    if (!d || !d.at) return <Empty icon={ShieldAlert} title="Not checked yet" text="Open “Vulnerabilities” and check once." action={<a className="btn primary" href="#/ext/vuln-watch">Open</a>} />;
    return <div className="vw-area-tab"><FindingList d={d} setData={st.setData} areas={areas} compact /></div>;
  };
}

export default {
  pages: { main: VulnPage },
  slots: {
    'dashboard.tiles': [{ id: 'vulns', title: 'Vulnerabilities', icon: ShieldAlert, size: 'third', Component: VulnTile }],
    // Seit Hostwerk 3.0 (SDK 3.2) ohne eigenen Seitenleisten-Eintrag ("nav": false) – die ganze Seite als Reiter im passenden Bereich;
    // Hostwerk blendet dabei ihren Titel aus (Reiter + Herkunftszeile sagen schon, was es ist), die Knöpfe bleiben
    'system.tabs': [{ id: 'vulns', title: 'Vulnerabilities', icon: ShieldAlert, Component: VulnPage, order: 45 }],
    'web.tabs': [{ id: 'vulns', title: 'Vulnerabilities', icon: ShieldAlert, Component: areaTab(['web', 'php']), order: 80 }],
    'dbs.tabs': [{ id: 'vulns', title: 'Vulnerabilities', icon: ShieldAlert, Component: areaTab(['dbs']), order: 80 }],
  },
};
