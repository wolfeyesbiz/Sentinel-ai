import React from 'react';
import { X, Globe, Shield, MapPin, Compass } from 'lucide-react';
import { AlertItem } from '../types';

interface ThreatMapModalProps {
  isOpen: boolean;
  onClose: () => void;
  alerts: AlertItem[];
}

export const ThreatMapModal: React.FC<ThreatMapModalProps> = ({
  isOpen,
  onClose,
  alerts
}) => {
  if (!isOpen) return null;

  // Aggregate country statistics
  const countryCounts: Record<string, { count: number; threats: Set<string> }> = {};
  alerts.forEach(a => {
    const c = a.country || 'Unknown';
    if (!countryCounts[c]) {
      countryCounts[c] = { count: 0, threats: new Set() };
    }
    countryCounts[c].count += 1;
    countryCounts[c].threats.add(a.threat_type);
  });

  const sortedCountries = Object.entries(countryCounts).sort((a, b) => b[1].count - a[1].count);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/80 backdrop-blur-sm overflow-y-auto">
      <div className="bg-[#0A1929] border border-[#1E3A5F] w-full max-w-4xl rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        {/* Header */}
        <div className="bg-[#0F2137] border-b border-[#1E3A5F] px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded bg-[#00D9FF]/15 border border-[#00D9FF]/30 text-[#00D9FF]">
              <Globe className="w-6 h-6 animate-spin-slow" />
            </div>
            <div>
              <h2 className="text-xl font-bold font-mono text-white">
                SENTINEL AI · GLOBAL THREAT RADAR
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Geographic attack origin visualization & telemetry mapping
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-[#1E3A5F]/50 transition-all cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 overflow-y-auto space-y-6">
          {/* Radar Visualizer Card matching Slide 1 & Slide 10 */}
          <div className="relative h-72 rounded-xl bg-gradient-to-b from-[#06101E] to-[#0A1929] border border-[#1E3A5F] flex items-center justify-center overflow-hidden">
            {/* Concentric Radar Rings */}
            <div className="absolute w-64 h-64 rounded-full border border-[#00D9FF]/20" />
            <div className="absolute w-48 h-48 rounded-full border border-[#00D9FF]/30" />
            <div className="absolute w-32 h-32 rounded-full border border-[#00D9FF]/40" />
            <div className="absolute w-16 h-16 rounded-full border border-[#00D9FF]/50" />

            {/* Radar Crosshairs */}
            <div className="absolute w-full h-[1px] bg-[#00D9FF]/20" />
            <div className="absolute h-full w-[1px] bg-[#00D9FF]/20" />

            {/* Rotating Radar Sweep Needle */}
            <div
              className="absolute w-64 h-64 rounded-full origin-center animate-spin"
              style={{
                background: 'conic-gradient(from 0deg, rgba(0, 217, 255, 0.4) 0deg, transparent 60deg, transparent 360deg)',
                animationDuration: '6s'
              }}
            />

            {/* Simulated Live Geographic Hotspot Nodes */}
            <div className="absolute top-1/4 left-1/3 flex items-center gap-1">
              <span className="w-3 h-3 rounded-full bg-[#FF1744] animate-ping" />
              <span className="text-[10px] font-mono font-bold text-[#FF1744] bg-black/80 px-1 rounded border border-red-900">
                Russia (SQLi)
              </span>
            </div>

            <div className="absolute bottom-1/3 right-1/4 flex items-center gap-1">
              <span className="w-3 h-3 rounded-full bg-[#FFB300] animate-ping" />
              <span className="text-[10px] font-mono font-bold text-[#FFB300] bg-black/80 px-1 rounded border border-amber-900">
                China (Brute Force)
              </span>
            </div>

            <div className="absolute top-1/2 right-1/3 flex items-center gap-1">
              <span className="w-3 h-3 rounded-full bg-[#00D9FF] animate-pulse" />
              <span className="text-[10px] font-mono font-bold text-[#00D9FF] bg-black/80 px-1 rounded border border-cyan-900">
                Germany (Bot Scraping)
              </span>
            </div>

            <div className="absolute bottom-1/4 left-1/4 flex items-center gap-1">
              <span className="w-3 h-3 rounded-full bg-purple-500 animate-ping" />
              <span className="text-[10px] font-mono font-bold text-purple-400 bg-black/80 px-1 rounded border border-purple-900">
                Vietnam (Session Jump)
              </span>
            </div>

            {/* Center Shield Icon */}
            <div className="z-10 p-3 rounded-full bg-[#0F2744] border border-[#00D9FF] shadow-[0_0_20px_rgba(0,217,255,0.4)] text-[#00D9FF]">
              <Shield className="w-7 h-7" />
            </div>
          </div>

          {/* Country breakdown list */}
          <div>
            <h4 className="text-xs font-mono font-bold tracking-widest text-[#00D9FF] uppercase mb-3 flex items-center gap-1.5">
              <MapPin className="w-4 h-4" />
              ATTACK ORIGINS & GEOGRAPHIC DISTRIBUTION
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
              {sortedCountries.length === 0 ? (
                <div className="col-span-3 text-center py-6 text-slate-400 text-xs font-mono">
                  No attack telemetry recorded yet.
                </div>
              ) : (
                sortedCountries.map(([country, data]) => (
                  <div key={country} className="bg-[#06101E] border border-[#1E3A5F] rounded-lg p-3 text-xs font-mono">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-white font-bold">{country}</span>
                      <span className="px-1.5 py-0.5 rounded bg-red-950/60 text-red-300 border border-red-800 text-[10px]">
                        {data.count} attacks
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 truncate">
                      Vectors: {Array.from(data.threats).join(', ') || 'N/A'}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="bg-[#0F2137] border-t border-[#1E3A5F] px-6 py-3 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded bg-[#0A1929] hover:bg-[#132B47] text-slate-300 border border-[#1E3A5F] font-mono text-xs cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
