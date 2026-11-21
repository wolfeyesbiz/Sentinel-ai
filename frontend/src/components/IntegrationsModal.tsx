import React, { useEffect, useState } from 'react';
import { Activity, Copy, Plus, RefreshCw, Trash2, X } from 'lucide-react';
import { apiUrl } from '../api';

type Site = { id: string; name: string; url: string; status: string; checked_at?: string; http_status?: number; latency_ms?: number; event_count: number; threat_count: number; last_event_at?: string };

export const IntegrationsModal: React.FC<{ isOpen: boolean; onClose: () => void }> = ({ isOpen, onClose }) => {
  const [sites, setSites] = useState<Site[]>([]);
  const [name, setName] = useState('');
  const [url, setUrl] = useState('https://');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [credential, setCredential] = useState<{ id: string; key: string } | null>(null);

  const refresh = async () => {
    const response = await fetch(apiUrl('/api/integrations'));
    if (response.ok) setSites(await response.json());
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
    await fetch(apiUrl(`/api/integrations/${site.id}/check`), { method: 'POST' }); await refresh();
  };
  const remove = async (site: Site) => {
    await fetch(apiUrl(`/api/integrations/${site.id}`), { method: 'DELETE' }); await refresh();
  };

  return <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/80 backdrop-blur-sm">
    <section className="bg-[#0A1929] border border-[#1E3A5F] w-full max-w-3xl rounded-xl shadow-2xl max-h-[92vh] overflow-y-auto">
      <header className="sticky top-0 bg-[#0F2137] border-b border-[#1E3A5F] p-5 flex justify-between items-center z-10">
        <div><h2 className="text-lg font-bold text-white">Website integrations</h2><p className="text-xs text-slate-400 mt-1">Availability checks and security telemetry from your demo sites</p></div>
        <button onClick={onClose} aria-label="Close" className="text-slate-400 hover:text-white"><X /></button>
      </header>
      <div className="p-5 space-y-5">
        <form onSubmit={add} className="rounded-lg border border-[#1E3A5F] bg-[#06101E] p-4 space-y-3">
          <h3 className="text-xs font-bold tracking-wider text-cyan-300 uppercase">Connect a website</h3>
          <p className="text-xs text-slate-400">Sentinel checks HTTPS availability on demand. To detect attacks, your app must forward request metadata to the authenticated event endpoint below.</p>
          <div className="grid sm:grid-cols-2 gap-3"><input required maxLength={80} placeholder="Demo store name" value={name} onChange={e => setName(e.target.value)} className="rounded bg-[#0A1929] border border-[#1E3A5F] px-3 py-2 text-sm text-white"/><input required type="url" placeholder="https://my-demo.onrender.com" value={url} onChange={e => setUrl(e.target.value)} className="rounded bg-[#0A1929] border border-[#1E3A5F] px-3 py-2 text-sm text-white"/></div>
          {error && <p className="text-sm text-red-300">{error}</p>}
          <button disabled={busy} className="inline-flex items-center gap-2 rounded bg-cyan-700 hover:bg-cyan-600 px-3 py-2 text-xs font-semibold disabled:opacity-50"><Plus size={15}/>{busy ? 'Connecting…' : 'Add website'}</button>
        </form>
        {credential && <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-4 space-y-2 text-xs">
          <p className="font-bold text-amber-200">Save this integration key now. It is shown only once.</p>
          <code className="block break-all text-slate-100">{credential.key}</code>
          <code className="block break-all text-slate-300">POST /api/integrations/{credential.id}/events — Authorization: Bearer &lt;key&gt;</code>
          <p className="text-slate-300">JSON body: method, path, client_ip, and optional headers, query_params, body, user_agent. Never forward passwords, cookies, tokens, or payment data.</p>
          <pre className="overflow-x-auto rounded bg-[#06101E] p-2 text-[10px] text-slate-300">{`await fetch("${apiUrl(`/api/integrations/${credential.id}/events`)}", {
  method: "POST",
  headers: { "Content-Type": "application/json", "Authorization": "Bearer " + process.env.SENTINEL_KEY },
  body: JSON.stringify({ method: "GET", path: "/", client_ip: request.ip, user_agent: request.headers["user-agent"] })
});`}</pre>
          <button onClick={() => navigator.clipboard?.writeText(credential.key)} className="inline-flex items-center gap-1 text-cyan-300"><Copy size={13}/>Copy key</button>
        </div>}
        <div className="space-y-2">{sites.length === 0 ? <div className="text-center text-sm text-slate-500 py-8">No websites connected yet.</div> : sites.map(site => <article key={site.id} className="rounded-lg border border-[#1E3A5F] bg-[#0F2137]/60 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3"><div className="min-w-0"><h3 className="font-semibold text-white">{site.name}</h3><a href={site.url} target="_blank" rel="noreferrer" className="text-xs text-cyan-300 break-all">{site.url}</a></div><div className="flex gap-2"><button onClick={() => check(site).catch(() => setError('Availability check failed.'))} className="inline-flex items-center gap-1 rounded border border-[#1E3A5F] px-2 py-1 text-xs text-slate-200"><RefreshCw size={13}/>Check</button><button onClick={() => remove(site).catch(() => setError('Could not remove site.'))} aria-label={`Remove ${site.name}`} className="rounded border border-red-900 px-2 py-1 text-red-300"><Trash2 size={13}/></button></div></div>
          <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-xs text-slate-400"><span>Status: <b className={site.status === 'online' ? 'text-emerald-300' : site.status === 'unreachable' ? 'text-red-300' : 'text-slate-200'}>{site.status.replace('_', ' ')}</b></span><span>HTTP: {site.http_status ?? '—'}</span><span>Latency: {site.latency_ms != null ? `${site.latency_ms} ms` : '—'}</span><span><Activity className="inline" size={13}/> Events {site.event_count} · Threats {site.threat_count}</span></div>
          <p className="mt-2 text-[11px] text-slate-500">{site.last_event_at ? `Last telemetry: ${new Date(site.last_event_at).toLocaleString()}` : 'No telemetry received yet'}{site.checked_at ? ` · Checked ${new Date(site.checked_at).toLocaleString()}` : ''}</p>
        </article>)}</div>
        <p className="text-[11px] text-slate-500">Integration records and keys are held in memory and reset when the backend restarts. Availability status does not indicate whether a site is under attack.</p>
      </div>
    </section>
  </div>;
};
