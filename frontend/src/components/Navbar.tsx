import React from 'react';
import { Shield, Volume2, VolumeX, Radio, Zap, Link2, Menu } from 'lucide-react';

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
  onOpenMenu: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  systemStatus, lastScanSeconds, wsConnected, soundEnabled, onToggleSound,
  onOpenSimulator, onOpenIntegrations, onOpenMenu
}) => (
  <header className="sticky top-0 z-30 h-[68px] border-b border-[#242424] bg-[#090909]/95 backdrop-blur px-4 md:px-8">
    <div className="mx-auto flex h-full max-w-[1440px] items-center justify-between gap-4">
      <div className="flex min-w-0 items-center gap-3">
        <button onClick={onOpenMenu} className="rounded-lg p-2 text-zinc-400 hover:bg-white/5 md:hidden" aria-label="Open navigation"><Menu size={18}/></button>
        <div className="hidden items-center gap-2 text-sm text-zinc-500 sm:flex"><span>Security</span><span>/</span></div>
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-sm font-medium text-zinc-100"><Shield size={16} className="text-emerald-500"/> Sentinel AI</div>
          <div className="truncate text-[11px] text-zinc-500">{systemStatus} · Updated {lastScanSeconds}s ago</div>
        </div>
      </div>
      <div className="flex items-center gap-2 sm:gap-3">
        <div className="hidden items-center gap-2 rounded-md border border-[#242424] px-2.5 py-1.5 text-xs text-zinc-400 sm:flex"><Radio size={14} className={wsConnected ? 'text-emerald-500' : 'text-zinc-600'}/>{wsConnected ? 'Live stream' : 'Connecting'}</div>
        <button onClick={onToggleSound} title={soundEnabled ? 'Mute alerts' : 'Enable alerts'} className="rounded-md p-2 text-zinc-400 hover:bg-white/5 hover:text-white">{soundEnabled ? <Volume2 size={17}/> : <VolumeX size={17}/>}</button>
        <button onClick={onOpenSimulator} className="hidden items-center gap-2 rounded-md border border-[#303030] px-3 py-2 text-xs font-medium text-zinc-200 hover:bg-white/5 sm:flex"><Zap size={14}/> Simulate</button>
        <button onClick={onOpenIntegrations} className="flex items-center gap-2 rounded-md bg-emerald-600 px-3 py-2 text-xs font-semibold text-white transition hover:bg-emerald-500"><Link2 size={14}/> <span className="hidden sm:inline">Add website</span></button>
      </div>
    </div>
  </header>
);
