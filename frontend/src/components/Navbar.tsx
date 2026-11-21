import React from 'react';
import { Shield, Volume2, VolumeX, Radio, Zap, Globe, Lock, FileText, Activity, Link2 } from 'lucide-react';
import { soundAlert } from '../SoundAlert';

interface NavbarProps {
  systemStatus: string;
  lastScanSeconds: number;
  wsConnected: boolean;
  soundEnabled: boolean;
  onToggleSound: () => void;
  onOpenSimulator: () => void;
  onOpenMap: () => void;
  onOpenFirewall: () => void;
  onOpenReport: () => void;
  onOpenTraffic: () => void;
  onOpenIntegrations: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  systemStatus,
  lastScanSeconds,
  wsConnected,
  soundEnabled,
  onToggleSound,
  onOpenSimulator,
  onOpenMap,
  onOpenFirewall,
  onOpenReport,
  onOpenTraffic,
  onOpenIntegrations
}) => {
  return (
    <header className="bg-[#0A1929]/95 backdrop-blur-md border-b border-[#1E3A5F] sticky top-0 z-40 px-4 lg:px-8 py-3">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row md:items-center md:justify-between gap-3">
        {/* Brand & Status */}
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-lg bg-[#0F2744] border border-[#00D9FF]/40 text-[#00D9FF] shadow-[0_0_15px_rgba(0,217,255,0.25)]">
            <Shield className="w-5 h-5 animate-pulse" />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-[#00C853] animate-ping" />
          </div>

          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold tracking-wider text-white">
                SENTINEL <span className="text-[#00D9FF]">AI</span>
              </h1>
              <span className="text-xs px-2 py-0.5 rounded bg-[#0F2744] text-[#00D9FF] border border-[#00D9FF]/30 font-mono">
                v1.0 PROD
              </span>
            </div>
            <p className="text-xs text-slate-400 uppercase tracking-widest font-mono">
              E-Commerce Security Monitoring & WAF
            </p>
          </div>

          {/* System status & Last Scan Pill */}
          <div className="hidden sm:flex items-center gap-2 ml-4">
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-[#00C853]/15 text-[#00C853] border border-[#00C853]/30">
              <span className="w-2 h-2 rounded-full bg-[#00C853] animate-pulse" />
              STATUS: {systemStatus.toUpperCase()} ✓
            </span>
            <span className="text-xs text-slate-400 font-mono px-2 py-1 rounded bg-[#0F2137] border border-[#1E3A5F]">
              Last Scan: {lastScanSeconds}s ago
            </span>
          </div>
        </div>

        {/* Action Controls & Modal Launchers */}
        <div className="flex items-center flex-wrap gap-2">
          {/* WebSocket stream status */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#0F2137] border border-[#1E3A5F] text-xs font-mono text-slate-300">
            <Radio className={`w-3.5 h-3.5 ${wsConnected ? 'text-[#00C853] animate-pulse' : 'text-[#FFB300]'}`} />
            <span className="hidden xl:inline">{wsConnected ? 'STREAM: LIVE' : 'CONNECTING'}</span>
          </div>

          {/* Sound alert toggle */}
          <button
            onClick={onToggleSound}
            title={soundEnabled ? 'Mute Alert Chimes' : 'Enable Alert Chimes'}
            className={`p-1.5 rounded border transition-all ${
              soundEnabled
                ? 'bg-[#0F2744] border-[#00D9FF]/40 text-[#00D9FF] hover:bg-[#00D9FF]/15'
                : 'bg-[#0F2137] border-[#1E3A5F] text-slate-400 hover:text-white'
            }`}
          >
            {soundEnabled ? <Volume2 className="w-4 h-4" /> : <VolumeX className="w-4 h-4" />}
          </button>

          {/* Simulate Attack Button */}
          <button
            onClick={onOpenSimulator}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-gradient-to-r from-red-600/90 to-amber-600/90 hover:from-red-600 hover:to-amber-600 text-white font-medium text-xs shadow-[0_0_15px_rgba(255,23,68,0.3)] transition-all cursor-pointer"
          >
            <Zap className="w-3.5 h-3.5 fill-current" />
            <span>Simulate Attack</span>
          </button>

          {/* Threat Map */}
          <button
            onClick={onOpenMap}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-[#0F2744] hover:bg-[#133054] text-slate-200 border border-[#1E3A5F] text-xs transition-all cursor-pointer"
          >
            <Globe className="w-3.5 h-3.5 text-[#00D9FF]" />
            <span className="hidden sm:inline">Threat Map</span>
          </button>

          {/* Firewall / Blocklist */}
          <button
            onClick={onOpenFirewall}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-[#0F2744] hover:bg-[#133054] text-slate-200 border border-[#1E3A5F] text-xs transition-all cursor-pointer"
          >
            <Lock className="w-3.5 h-3.5 text-amber-400" />
            <span className="hidden sm:inline">Firewall</span>
          </button>

          {/* Security Report */}
          <button
            onClick={onOpenReport}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-[#0F2744] hover:bg-[#133054] text-slate-200 border border-[#1E3A5F] text-xs transition-all cursor-pointer"
          >
            <FileText className="w-3.5 h-3.5 text-emerald-400" />
            <span className="hidden sm:inline">Report</span>
          </button>

          {/* Live Traffic Feed */}
          <button onClick={onOpenIntegrations} className="flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-[#0F2744] hover:bg-[#133054] text-slate-200 border border-[#1E3A5F] text-xs transition-all cursor-pointer">
            <Link2 className="w-3.5 h-3.5 text-cyan-300" /><span>Integrations</span>
          </button>

          {/* Live Traffic Feed */}
          <button
            onClick={onOpenTraffic}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-[#0F2744] hover:bg-[#133054] text-slate-200 border border-[#1E3A5F] text-xs transition-all cursor-pointer"
          >
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden sm:inline">Live Stream</span>
          </button>
        </div>
      </div>
    </header>
  );
};
