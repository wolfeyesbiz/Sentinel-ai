import React from 'react';
import { Menu, Radio, Shield, Volume2, VolumeX, Zap, Link2 } from 'lucide-react';

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
  onOpenSimulator, onOpenIntegrations, onOpenMenu,
}) => <header className="sentinel-topbar">
  <div className="topbar-context">
    <button onClick={onOpenMenu} className="quiet-button mobile-nav-trigger" aria-label="Open navigation"><Menu size={18} /></button>
    <div className="topbar-brand-mobile"><Shield size={16} /><span>Sentinel AI</span></div>
    <div className="topbar-context-copy"><div className="topbar-title">Security console</div><div className="topbar-meta"><span>{systemStatus}</span><span>Last event {lastScanSeconds >= 60 ? 'over 1 min' : `${lastScanSeconds}s`} ago</span></div></div>
  </div>
  <div className="topbar-actions">
    <div className="connection-state" aria-live="polite"><Radio size={14} aria-hidden="true" />{wsConnected ? 'Live stream' : 'Connecting'}</div>
    <button onClick={onToggleSound} title={soundEnabled ? 'Mute alerts' : 'Enable alerts'} className="quiet-button" aria-label={soundEnabled ? 'Mute alerts' : 'Enable alerts'}>{soundEnabled ? <Volume2 size={17} /> : <VolumeX size={17} />}</button>
    <button onClick={onOpenSimulator} className="action-button"><Zap size={14} /> Simulate</button>
    <button onClick={onOpenIntegrations} className="action-button action-button--primary"><Link2 size={14} /> Add website</button>
  </div>
</header>;
