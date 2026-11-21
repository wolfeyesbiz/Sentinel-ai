import React, { useEffect, useState } from 'react';
import { Activity, Copy, Plus, RefreshCw, ScanLine, Trash2, X, Zap } from 'lucide-react';
import { apiUrl } from '../api';

type Site = {
  id: string; name: string; url: string; status: string; checked_at?: string;
  http_status?: number; latency_ms?: number; event_count: number; threat_count: number;
  last_event_at?: string; last_scan_at?: string; last_scan_findings?: number | null;
};
type Probe = { probe: string; status_code?: number | null; latency_ms?: number; result: string; severity: string; details: string };
type Assessment = {
  summary?: string; finding_count?: number; checks?: Array<{ title: string; result: string; severity: string; details: string }>;
  probes: Probe[]; requests_sent?: number; scope: string;
};

export const IntegrationsModal: React.FC<{ isOpen: boolean; onClose: () => void }> = ({ isOpen, onClose }) => {
  const [sites, setSites] = useState<Site[]>([]);
  const [name, setName] = useState('');
  const [url, setUrl] = useState('https://');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [credential, setCredential] = useState<{ id: string; key: string } | null>(null);
  const [assessments, setAssessments] = useState<Record<string, Assessment>>({});
  const [activeAction, setActiveAction] = useState<string | null>(null);

  const refresh = async () => {
    const response = await fetch(apiUrl('/api/integrations'));
    if (!response.ok) throw new Error('Could not load integrations.');
    setSites(await response.json());
  };
  useEffect(() => { if (isOpen) refresh().catch(() => setError('Could not load integrations.')); }, [isOpen]);
  if (!isOpen) return null;

  const add = async (event: React.FormEvent) => {
    event.preventDefault(); setBusy(true); setError(''); setCredential(null);
    try {
      const response = await fetch(apiUrl('/api/integrations'), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, url }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || 'Could not add site.');
      setCredential({ id: result.id, key: result.integration_key }); setName(''); setUrl('https://'); await refresh();
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not add site.'); }
    finally { setBusy(false); }
  };
  const check = async (site: Site) => {
    const response = await fetch(apiUrl(`/api/integrations/${site.id}/check`), { method: 'POST' });
    if (!response.ok) throw new Error('Availability check failed.');
    await refresh();
  };
  const assess = async (site: Site, mode: 'scan' | 'simulate') => {
    setActiveAction(`${site.id}:${mode}`); setError('');
    try {
      const response = await fetch(apiUrl(`/api/integrations/${site.id}/${mode}`), { method: 'POST' });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || 'Assessment failed.');
      setAssessments(current => ({ ...current, [site.id]: result })); await refresh();
    } catch (e) { setError(e instanceof Error ? e.message : 'Assessment failed.'); }
    finally { setActiveAction(null); }
  };
  const remove = async (site: Site) => {
    const response = await fetch(apiUrl(`/api/integrations/${site.id}`), { method: 'DELETE' });
    if (!response.ok) throw new Error('Could not remove site.');
    setAssessments(current => { const next = { ...current }; delete next[site.id]; return next; });
    await refresh();
  };

  return <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/80 backdrop-blur-sm">
    <section className="bg-[#0A1929] border border-[#1E3A5F] w-full max-w-3xl rounded-xl shadow-2xl max-h-[92vh] overflow-y-auto">
      <header className="sticky top-0 bg-[#0F2137] border-b border-[#1E3A5F] p-5 flex justify-between items-center z-10">
        <div><h2 className="text-lg font-bold text-white">Website integrations</h2><p className="text-xs text-slate-400 mt-1">Availability, safe security checks, and telemetry from your Render demos</p></div>
        <button onClick={onClose} aria-label="Close" className="text-slate-400 hover:text-white"><X /></button>
      </header>
      <div className="p-5 space-y-5">
        <form onSubmit={add} className="rounded-lg border border-[#1E3A5F] bg-[#06101E] p-4 space-y-3">
          <h3 className="text-xs font-bold tracking-wider text-cyan-300 uppercase">Connect a website</h3>
          <p className="text-xs text-slate-400">Add a public Render demo URL. A limited root-page scan checks security headers and uses two harmless GET canaries. The simulation sends three low-impact GET requests; it does not change site data or generate load.</p>
          <div className="grid sm:grid-cols-2 gap-3"><input required maxLength={80} placeholder="Demo store name" value={name} onChange={e => setName(e.target.value)} className="rounded bg-[#0A1929] border border-[#1E3A5F] px-3 py-2 text-sm text-white"/><input required type="url" placeholder="https://my-demo.onrender.com" value={url} onChange={e => setUrl(e.target.value)} className="rounded bg-[#0A1929] border border-[#1E3A5F] px-3 py-2 text-sm text-white"/></div>
          {error && <p className="text-sm text-red-300">{error}</p>}
          <button disabled={busy} className="inline-flex items-center gap-2 rounded bg-cyan-700 hover:bg-cyan-600 px-3 py-2 text-xs font-semibold disabled:opacity-50"><Plus size={15}/>{busy ? 'Connecting…' : 'Add website'}</button>
        </form>
        {credential && <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-4 space-y-3 text-xs">
          <p className="font-bold text-amber-200">Save this integration key now. It is shown only once.</p>
          <div className="rounded bg-[#06101E] p-3 space-y-2"><p className="text-slate-400">Integration key</p><code className="block break-all text-slate-100">{credential.key}</code></div>
          <div className="rounded bg-[#06101E] p-3 space-y-1"><p className="text-slate-400">Telemetry endpoint</p><code className="block break-all text-slate-300">POST /api/integrations/{credential.id}/events</code><code className="block break-all text-slate-300">Authorization: Bearer &lt;key&gt;</code></div>
          <p className="text-slate-300">Forward only method, path, source IP, user agent, and sanitized query/body data. Never forward passwords, cookies, tokens, or payment data.</p>
          <pre className="overflow-x-auto rounded bg-[#06101E] p-2 text-[10px] text-slate-300">{`await fetch("${apiUrl(`/api/integrations/${credential.id}/events`)}", {
  method: "POST",
  headers: { "Content-Type": "application/json", "Authorization": "Bearer " + process.env.SENTINEL_KEY },
  body: JSON.stringify({ method: "GET", path: "/", client_ip: request.ip, user_agent: request.headers["user-agent"] })
});`}</pre>
          <button onClick={() => navigator.clipboard?.writeText(credential.key)} className="inline-flex items-center gap-1 text-cyan-300"><Copy size={13}/>Copy key</button>
        </div>}
        {error && <p className="text-sm text-red-300">{error}</p>}
        <div className="space-y-2">{sites.length === 0 ? <div className="text-center text-sm text-slate-500 py-8">No websites connected yet.</div> : sites.map(site => <article key={site.id} className="rounded-lg border border-[#1E3A5F] bg-[#0F2137]/60 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3"><div className="min-w-0"><h3 className="font-semibold text-white">{site.name}</h3><a href={site.url} target="_blank" rel="noreferrer" className="text-xs text-cyan-300 break-all">{site.url}</a></div><div className="flex flex-wrap gap-2">
            <button disabled={activeAction !== null} onClick={() => check(site).catch(e => setError(e instanceof Error ? e.message : 'Availability check failed.'))} className="inline-flex items-center gap-1 rounded border border-[#1E3A5F] px-2 py-1 text-xs text-slate-200 disabled:opacity-50"><RefreshCw size={13}/>Check</button>
            <button disabled={activeAction !== null} onClick={() => assess(site, 'scan')} className="inline-flex items-center gap-1 rounded border border-cyan-700 px-2 py-1 text-xs text-cyan-200 disabled:opacity-50"><ScanLine size={13}/>{activeAction === `${site.id}:scan` ? 'Scanning…' : 'Security scan'}</button>
            <button disabled={activeAction !== null} onClick={() => assess(site, 'simulate')} className="inline-flex items-center gap-1 rounded border border-amber-700 px-2 py-1 text-xs text-amber-200 disabled:opacity-50"><Zap size={13}/>{activeAction === `${site.id}:simulate` ? 'Probing…' : 'Simulate safe probes'}</button>
            <button onClick={() => remove(site).catch(e => setError(e instanceof Error ? e.message : 'Could not remove site.'))} aria-label={`Remove ${site.name}`} className="rounded border border-red-900 px-2 py-1 text-red-300"><Trash2 size={13}/></button>
          </div></div>
          <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-xs text-slate-400"><span>Status: <b className={site.status === 'online' ? 'text-emerald-300' : site.status === 'unreachable' ? 'text-red-300' : 'text-slate-200'}>{site.status.replace('_', ' ')}</b></span><span>HTTP: {site.http_status ?? '—'}</span><span>Latency: {site.latency_ms != null ? `${site.latency_ms} ms` : '—'}</span><span><Activity className="inline" size={13}/> Events {site.event_count} · Threats {site.threat_count}</span></div>
          <p className="mt-2 text-[11px] text-slate-500">{site.last_event_at ? `Last telemetry: ${new Date(site.last_event_at).toLocaleString()}` : 'No telemetry received yet'}{site.checked_at ? ` · Checked ${new Date(site.checked_at).toLocaleString()}` : ''}{site.last_scan_at ? ` · Last scan: ${new Date(site.last_scan_at).toLocaleString()} (${site.last_scan_findings ?? 0} potential findings)` : ''}</p>
          {assessments[site.id] && <div className="mt-3 rounded border border-[#1E3A5F] bg-[#06101E] p-3 space-y-2">
            <p className="text-xs font-semibold text-white">{assessments[site.id].summary ? `Scan: ${assessments[site.id].summary} (${assessments[site.id].finding_count} potential findings)` : `Simulation: ${assessments[site.id].requests_sent} safe GET probes sent`}</p>
            {assessments[site.id].checks?.map((check, index) => <div key={`check-${index}`} className="text-[11px] text-slate-300"><b className={check.severity === 'info' ? 'text-emerald-300' : 'text-amber-300'}>{check.title}: {check.result}</b><span className="block text-slate-400">{check.details}</span></div>)}
            {assessments[site.id].probes.map((probe, index) => <div key={`probe-${index}`} className="text-[11px] text-slate-300"><b className={probe.severity === 'info' ? 'text-emerald-300' : 'text-amber-300'}>{probe.probe}: {probe.result}</b><span className="block text-slate-400">HTTP {probe.status_code ?? '—'} · {probe.details}</span></div>)}
            <p className="text-[10px] text-slate-500">{assessments[site.id].scope}</p>
          </div>}
        </article>)}</div>
        <p className="text-[11px] text-slate-500">Scans are limited to the registered site’s root page on *.onrender.com. A few low-impact GET canaries are not a full penetration test and do not block traffic. Ongoing attack detection still needs the site to forward request telemetry. Integration data is held in memory and clears when the backend restarts.</p>
      </div>
    </section>
  </div>;
};
