import React from 'react';
import { Cpu, HardDrive, Wifi, Activity } from 'lucide-react';
import { SystemMetrics } from '../types';

interface MetricCardsProps { metrics: SystemMetrics | null }

export const MetricCards: React.FC<MetricCardsProps> = ({ metrics }) => {
  const cards = [
    { label: 'CPU usage', value: metrics ? `${Math.round(metrics.cpu_usage)}%` : '—', detail: 'Current host load', icon: Cpu, tone: 'text-emerald-400', bar: metrics?.cpu_usage },
    { label: 'Memory', value: metrics ? `${Math.round(metrics.ram_usage)}%` : '—', detail: 'Current host usage', icon: HardDrive, tone: 'text-cyan-400', bar: metrics?.ram_usage },
    { label: 'Network I/O', value: metrics ? `${Number(metrics.network_io).toFixed(1)} MB/s` : '—', detail: 'Inbound and outbound', icon: Wifi, tone: 'text-sky-400' },
    { label: 'Active processes', value: metrics ? String(metrics.active_processes) : '—', detail: 'Reported by monitor', icon: Activity, tone: 'text-violet-400' }
  ];
  return <section className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-label="System metrics">
    {cards.map(({ label, value, detail, icon: Icon, tone, bar }) => <article key={label} className="rounded-xl border border-[#252525] bg-[#141414] p-4 transition-colors hover:border-[#353535]">
      <div className="flex items-center justify-between"><span className="text-xs text-zinc-400">{label}</span><span className={`rounded-lg bg-white/[0.04] p-2 ${tone}`}><Icon size={16}/></span></div>
      <div className="mt-3 text-[27px] font-semibold tracking-tight text-zinc-100">{value}</div>
      <div className="mt-1 text-[11px] text-zinc-500">{detail}</div>
      {typeof bar === 'number' && <div className="mt-4 h-1 overflow-hidden rounded-full bg-white/[0.06]"><div className="h-full rounded-full bg-emerald-500 transition-all" style={{ width: `${Math.min(100, Math.max(0, bar))}%` }}/></div>}
    </article>)}
  </section>;
};
