import React from 'react';
import { Activity, ShieldCheck, ShieldAlert, AlertTriangle } from 'lucide-react';

interface ThreatLevelBannerProps {
  threatLevel: string;
  activeThreats: number | null;
  blockedToday: number | null;
  riskScore: number | null;
}

export const ThreatLevelBanner: React.FC<ThreatLevelBannerProps> = ({ threatLevel, activeThreats, blockedToday, riskScore }) => {
  const level = threatLevel.toUpperCase();
  const severe = ['CRITICAL', 'EMERGENCY'].includes(level);
  const elevated = ['MEDIUM', 'ELEVATED', 'HIGH'].includes(level);
  const unknown = level === 'UNKNOWN';
  const tone = severe ? 'bad' : elevated ? 'warn' : unknown ? 'neutral' : 'ok';
  const Icon = severe ? ShieldAlert : elevated ? AlertTriangle : unknown ? Activity : ShieldCheck;
  const score = riskScore == null ? '—' : `${Math.round(riskScore * 100)}%`;

  return <section className="panel defense-banner" data-tone={tone} aria-label="Defense status">
    <div className="defense-copy">
      <span className="defense-icon"><Icon size={20} aria-hidden="true" /></span>
      <div><div className="defense-label">Defense status</div><div className="defense-level">{level} <span className="defense-label">Risk score {score}</span></div></div>
    </div>
    <dl className="defense-stats">
      <div className="defense-stat"><dt>Active threats</dt><dd>{activeThreats ?? '—'}</dd></div>
      <div className="defense-stat"><dt>Blocked today</dt><dd>{blockedToday ?? '—'}</dd></div>
    </dl>
  </section>;
};
