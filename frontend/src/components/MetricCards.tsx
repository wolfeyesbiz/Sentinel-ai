import React from 'react';
import { Cpu, HardDrive, Wifi, Activity } from 'lucide-react';
import { SystemMetrics } from '../types';

interface MetricCardsProps {
  metrics: SystemMetrics | null;
}

export const MetricCards: React.FC<MetricCardsProps> = ({ metrics }) => {
  const cpu = metrics?.cpu_usage ?? 34;
  const ram = metrics?.ram_usage ?? 52;
  const net = metrics?.network_io ?? 2.4;
  const procs = metrics?.active_processes ?? 124;

  const getStatusColor = (val: number, warn: number, crit: number) => {
    if (val >= crit) return 'text-[#FF1744]';
    if (val >= warn) return 'text-[#FFB300]';
    return 'text-[#00D9FF]';
  };

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      {/* CPU Usage Card */}
      <div className="bg-[#0A1929]/90 border border-[#1E3A5F] rounded-xl p-4 flex flex-col justify-between hover:border-[#00D9FF]/40 transition-all shadow-lg">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-mono font-medium text-slate-400 uppercase flex items-center gap-1.5">
            <Cpu className="w-4 h-4 text-[#00D9FF]" />
            CPU USAGE
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#0F2137] text-slate-300 border border-[#1E3A5F]">
            {cpu > 80 ? 'ELEVATED' : 'NOMINAL'}
          </span>
        </div>

        <div className="flex items-end justify-between my-2">
          <div className="text-3xl font-extrabold font-mono text-white">
            {cpu}%
          </div>
          {/* Mini Progress Bar Gauge */}
          <div className="w-24 h-2 bg-[#0F2137] rounded-full overflow-hidden border border-[#1E3A5F]">
            <div
              className={`h-full transition-all duration-500 rounded-full ${
                cpu > 80 ? 'bg-[#FF1744]' : (cpu > 60 ? 'bg-[#FFB300]' : 'bg-[#00D9FF]')
              }`}
              style={{ width: `${Math.min(100, Math.max(5, cpu))}%` }}
            />
          </div>
        </div>

        <div className="text-[11px] font-mono text-slate-400 flex justify-between">
          <span>Target: &lt;75%</span>
          <span className={getStatusColor(cpu, 65, 80)}>{cpu < 65 ? 'Optimal' : 'Investigate'}</span>
        </div>
      </div>

      {/* RAM Usage Card */}
      <div className="bg-[#0A1929]/90 border border-[#1E3A5F] rounded-xl p-4 flex flex-col justify-between hover:border-[#00D9FF]/40 transition-all shadow-lg">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-mono font-medium text-slate-400 uppercase flex items-center gap-1.5">
            <HardDrive className="w-4 h-4 text-emerald-400" />
            RAM USAGE
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#0F2137] text-slate-300 border border-[#1E3A5F]">
            {ram > 85 ? 'WARNING' : 'HEALTHY'}
          </span>
        </div>

        <div className="flex items-end justify-between my-2">
          <div className="text-3xl font-extrabold font-mono text-white">
            {ram}%
          </div>
          {/* Progress bar */}
          <div className="w-24 h-2 bg-[#0F2137] rounded-full overflow-hidden border border-[#1E3A5F]">
            <div
              className={`h-full transition-all duration-500 rounded-full ${
                ram > 85 ? 'bg-[#FF1744]' : (ram > 70 ? 'bg-[#FFB300]' : 'bg-[#00C853]')
              }`}
              style={{ width: `${Math.min(100, Math.max(5, ram))}%` }}
            />
          </div>
        </div>

        <div className="text-[11px] font-mono text-slate-400 flex justify-between">
          <span>Capacity: 16 GB</span>
          <span className="text-emerald-400">Stable Pool</span>
        </div>
      </div>

      {/* Network I/O Card with Dynamic Waveform */}
      <div className="bg-[#0A1929]/90 border border-[#1E3A5F] rounded-xl p-4 flex flex-col justify-between hover:border-[#00D9FF]/40 transition-all shadow-lg">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-mono font-medium text-slate-400 uppercase flex items-center gap-1.5">
            <Wifi className="w-4 h-4 text-amber-400" />
            NETWORK I/O
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#0F2137] text-slate-300 border border-[#1E3A5F]">
            EDGE WAF
          </span>
        </div>

        <div className="flex items-end justify-between my-2">
          <div className="text-3xl font-extrabold font-mono text-white">
            {net} <span className="text-sm font-normal text-slate-400">MB/s</span>
          </div>
          {/* SVG Animated Sparkline Wave */}
          <div className="w-24 h-8 flex items-end gap-1">
            {[40, 65, 30, 85, 45, 95, 60, 75].map((h, i) => (
              <div
                key={i}
                className="w-2 bg-[#00D9FF]/60 rounded-t transition-all duration-300"
                style={{ height: `${(h * (net / 3.0)).toFixed(0)}%` }}
              />
            ))}
          </div>
        </div>

        <div className="text-[11px] font-mono text-slate-400 flex justify-between">
          <span>Inbound / Outbound</span>
          <span className="text-amber-400">Real-time Stream</span>
        </div>
      </div>

      {/* Active Processes / Anomaly Score Card */}
      <div className="bg-[#0A1929]/90 border border-[#1E3A5F] rounded-xl p-4 flex flex-col justify-between hover:border-[#00D9FF]/40 transition-all shadow-lg">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-mono font-medium text-slate-400 uppercase flex items-center gap-1.5">
            <Activity className="w-4 h-4 text-purple-400" />
            ACTIVE PROCESSES
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#0F2137] text-purple-300 border border-[#1E3A5F]">
            SYSTEM THREADS
          </span>
        </div>

        <div className="flex items-end justify-between my-2">
          <div className="text-3xl font-extrabold font-mono text-white">
            {procs}
          </div>
          <span className="text-xs font-mono text-[#00C853] flex items-center gap-1">
            ● NOMINAL
          </span>
        </div>

        <div className="text-[11px] font-mono text-slate-400 flex justify-between">
          <span>Core Isolation Forest</span>
          <span className="text-[#00D9FF]">Active ML Baseline</span>
        </div>
      </div>
    </div>
  );
};
