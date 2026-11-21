import React from 'react';
import { AlertCircle, ShieldCheck, ShieldAlert, AlertTriangle } from 'lucide-react';

interface ThreatLevelBannerProps {
  threatLevel: string;
  activeThreats: number;
  blockedToday: number;
  riskScore: number;
}

export const ThreatLevelBanner: React.FC<ThreatLevelBannerProps> = ({
  threatLevel,
  activeThreats,
  blockedToday,
  riskScore
}) => {
  const level = threatLevel.toUpperCase();

  const getTheme = () => {
    switch (level) {
      case 'CRITICAL':
      case 'EMERGENCY':
        return {
          textColor: 'text-[#FF1744]',
          borderColor: 'border-[#FF1744]/40',
          bgColor: 'bg-[#FF1744]/10',
          dotColor: 'bg-[#FF1744]',
          shadow: 'shadow-[0_0_20px_rgba(255,23,68,0.25)]',
          icon: <ShieldAlert className="w-5 h-5 text-[#FF1744] animate-bounce" />,
          label: 'ELEVATED/CRITICAL THREAT ACTIVE - WAF LOCKDOWN ENGAGED'
        };
      case 'MEDIUM':
      case 'ELEVATED':
        return {
          textColor: 'text-[#FFB300]',
          borderColor: 'border-[#FFB300]/40',
          bgColor: 'bg-[#FFB300]/10',
          dotColor: 'bg-[#FFB300]',
          shadow: 'shadow-[0_0_20px_rgba(255,179,0,0.2)]',
          icon: <AlertTriangle className="w-5 h-5 text-[#FFB300]" />,
          label: 'SUSPICIOUS TRAFFIC SPIKE DETECTED - STEP-UP CHALLENGES ENGAGED'
        };
      default:
        return {
          textColor: 'text-[#00C853]',
          borderColor: 'border-[#00C853]/40',
          bgColor: 'bg-[#00C853]/10',
          dotColor: 'bg-[#00C853]',
          shadow: 'shadow-[0_0_20px_rgba(0,200,83,0.15)]',
          icon: <ShieldCheck className="w-5 h-5 text-[#00C853]" />,
          label: 'STOREFRONT IS CURRENTLY PROTECTED · ALL ML GUARDS NOMINAL'
        };
    }
  };

  const theme = getTheme();

  return (
    <div className={`p-4 md:p-6 rounded-xl border ${theme.borderColor} ${theme.bgColor} ${theme.shadow} backdrop-blur-md mb-6 transition-all duration-300`}>
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        {/* Threat Level */}
        <div>
          <div className="flex items-center gap-2 mb-1">
            {theme.icon}
            <span className="text-xs font-mono font-bold tracking-widest text-slate-400 uppercase">
              DEFENSE STATUS
            </span>
          </div>

          <div className="flex items-center gap-3">
            <h2 className="text-2xl md:text-3xl font-extrabold tracking-wide font-mono text-white">
              THREAT LEVEL: <span className={theme.textColor}>{level}</span>
            </h2>
            <span className={`w-3.5 h-3.5 rounded-full ${theme.dotColor} animate-ping`} />
          </div>

          <p className="text-xs text-slate-400 mt-1 font-mono">
            {theme.label}
          </p>
        </div>

        {/* Counter Stats matching wireframe */}
        <div className="flex items-center flex-wrap gap-4 sm:gap-6 font-mono bg-[#0A1929]/70 px-4 py-3 rounded-lg border border-[#1E3A5F]">
          <div>
            <span className="text-xs text-slate-400 block">Active Threats</span>
            <span className={`text-xl font-bold ${activeThreats > 0 ? 'text-[#FF1744]' : 'text-slate-200'}`}>
              {activeThreats}
            </span>
          </div>

          <div className="w-[1px] h-8 bg-[#1E3A5F]" />

          <div>
            <span className="text-xs text-slate-400 block">Blocked Today</span>
            <span className="text-xl font-bold text-[#00D9FF]">
              {blockedToday}
            </span>
          </div>

          <div className="w-[1px] h-8 bg-[#1E3A5F]" />

          <div>
            <span className="text-xs text-slate-400 block">Risk Score</span>
            <div className="flex items-baseline gap-1.5">
              <span className={`text-xl font-bold ${riskScore > 0.7 ? 'text-[#FF1744]' : (riskScore > 0.4 ? 'text-[#FFB300]' : 'text-[#00C853]')}`}>
                {riskScore.toFixed(2)}
              </span>
              <span className="text-[10px] text-slate-500">/ 1.0</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
