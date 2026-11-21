import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle } from 'lucide-react';

interface ThreatLevelBannerProps { threatLevel: string; activeThreats: number; blockedToday: number; riskScore: number }

export const ThreatLevelBanner: React.FC<ThreatLevelBannerProps> = ({ threatLevel, activeThreats, blockedToday, riskScore }) => {
  const level = threatLevel.toUpperCase();
  const severe = ['CRITICAL', 'EMERGENCY'].includes(level);
  const elevated = ['MEDIUM', 'ELEVATED', 'HIGH'].includes(level);
  const Icon = severe ? ShieldAlert : elevated ? AlertTriangle : ShieldCheck;
  const color = severe ? 'text-rose-400' : elevated ? 'text-amber-400' : 'text-emerald-400';
  return <section className="mb-4 flex flex-col gap-4 rounded-xl border border-[#252525] bg-[#141414] p-4 sm:flex-row sm:items-center sm:justify-between">
    <div className="flex items-center gap-3">
      <span className={`rounded-lg bg-white/[0.04] p-2.5 ${color}`}><Icon size={19}/></span>
      <div><div className="text-xs text-zinc-500">Defense status</div><div className="mt-0.5 text-sm font-semibold text-zinc-100">{level} <span className="ml-1 font-normal text-zinc-500">· Risk score {Number(riskScore).toFixed(2)}</span></div></div>
    </div>
    <div className="flex items-center gap-6 border-t border-[#252525] pt-3 sm:border-l sm:border-t-0 sm:pl-6 sm:pt-0">
      <div><div className="text-[11px] text-zinc-500">Active threats</div><div className={`mt-1 text-lg font-semibold ${activeThreats ? 'text-rose-400' : 'text-zinc-100'}`}>{activeThreats}</div></div>
      <div><div className="text-[11px] text-zinc-500">Blocked today</div><div className="mt-1 text-lg font-semibold text-zinc-100">{blockedToday}</div></div>
    </div>
  </section>;
};
