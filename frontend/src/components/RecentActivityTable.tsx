import React, { useState } from 'react';
import { AlertItem, SeverityLevel } from '../types';
import { Search, Filter, ShieldCheck, ShieldAlert, AlertTriangle, Info, ArrowUpRight } from 'lucide-react';

interface RecentActivityTableProps {
  alerts: AlertItem[];
  onSelectAlert: (alert: AlertItem) => void;
}

export const RecentActivityTable: React.FC<RecentActivityTableProps> = ({
  alerts,
  onSelectAlert
}) => {
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const filtered = alerts.filter(item => {
    if (filterSeverity !== 'all' && item.severity !== filterSeverity) {
      return false;
    }
    if (searchQuery.trim() !== '') {
      const q = searchQuery.toLowerCase();
      return (
        item.source_ip.toLowerCase().includes(q) ||
        item.target.toLowerCase().includes(q) ||
        item.threat_type.toLowerCase().includes(q) ||
        item.description.toLowerCase().includes(q) ||
        item.country.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const getSeverityBadge = (severity: SeverityLevel) => {
    switch (severity) {
      case 'emergency':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-bold font-mono bg-[#FF1744]/20 text-[#FF1744] border border-[#FF1744]/50 animate-pulse">
            EMERGENCY
          </span>
        );
      case 'critical':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-bold font-mono bg-[#FF1744]/15 text-[#FF1744] border border-[#FF1744]/30">
            CRITICAL
          </span>
        );
      case 'warning':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-bold font-mono bg-[#FFB300]/15 text-[#FFB300] border border-[#FFB300]/30">
            WARNING
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-bold font-mono bg-[#00C853]/15 text-[#00C853] border border-[#00C853]/30">
            INFO
          </span>
        );
    }
  };

  const getStatusBadge = (status: string) => {
    if (status === 'blocked') {
      return (
        <span className="px-2 py-0.5 rounded bg-red-950/60 text-red-300 border border-red-800 text-[11px] font-mono font-medium">
          BLOCKED ✓
        </span>
      );
    }
    if (status === 'flagged') {
      return (
        <span className="px-2 py-0.5 rounded bg-amber-950/60 text-amber-300 border border-amber-800 text-[11px] font-mono font-medium">
          FLAGGED
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800 text-[11px] font-mono font-medium">
        ALLOWED
      </span>
    );
  };

  const formatTime = (isoString: string) => {
    try {
      const d = new Date(isoString);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    } catch {
      return isoString;
    }
  };

  return (
    <div className="bg-[#0A1929]/90 border border-[#1E3A5F] rounded-xl p-4 md:p-6 shadow-xl mb-8">
      {/* Table Header and Filters */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-4 pb-4 border-b border-[#1E3A5F]">
        <div>
          <h3 className="text-lg font-bold font-mono text-white tracking-wide">
            RECENT ACTIVITY (Last 1 Hour)
          </h3>
          <p className="text-xs text-slate-400 font-mono">
            Real-time telemetry stream · Click any alert row to view immediate remediation & code fixes
          </p>
        </div>

        {/* Search and Filters */}
        <div className="flex items-center flex-wrap gap-2">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search IP, URL, Threat..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="bg-[#0F2137] border border-[#1E3A5F] rounded text-xs pl-8 pr-3 py-1.5 text-white placeholder-slate-500 focus:outline-none focus:border-[#00D9FF] w-48 sm:w-60 font-mono"
            />
          </div>

          {/* Severity Tabs */}
          <div className="flex items-center bg-[#0F2137] border border-[#1E3A5F] rounded p-0.5 text-xs font-mono">
            {['all', 'critical', 'warning', 'info'].map(sev => (
              <button
                key={sev}
                onClick={() => setFilterSeverity(sev)}
                className={`px-2.5 py-1 rounded capitalize transition-all cursor-pointer ${
                  filterSeverity === sev
                    ? 'bg-[#00D9FF] text-black font-semibold shadow'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Table Element */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-mono">
          <thead>
            <tr className="border-b border-[#1E3A5F] text-slate-400 font-medium">
              <th className="py-2.5 px-3">TIMESTAMP</th>
              <th className="py-2.5 px-3">SEVERITY</th>
              <th className="py-2.5 px-3">THREAT TYPE</th>
              <th className="py-2.5 px-3">SOURCE IP</th>
              <th className="py-2.5 px-3">TARGET ENDPOINT</th>
              <th className="py-2.5 px-3">STATUS</th>
              <th className="py-2.5 px-3">RISK SCORE</th>
              <th className="py-2.5 px-3 text-right">ACTION</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1E3A5F]/40">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-slate-400 font-mono">
                  No alerts match the selected criteria. System is quiet and protected.
                </td>
              </tr>
            ) : (
              filtered.map(item => (
                <tr
                  key={item.id}
                  onClick={() => onSelectAlert(item)}
                  className="hover:bg-[#0F2744]/70 transition-colors cursor-pointer group"
                >
                  <td className="py-3 px-3 text-slate-300 font-semibold whitespace-nowrap">
                    {formatTime(item.timestamp)}
                  </td>
                  <td className="py-3 px-3 whitespace-nowrap">
                    {getSeverityBadge(item.severity)}
                  </td>
                  <td className="py-3 px-3 font-medium text-white whitespace-nowrap">
                    {item.threat_type.replace('_', ' ').toUpperCase()}
                  </td>
                  <td className="py-3 px-3 text-slate-300 whitespace-nowrap">
                    <span className="text-[#00D9FF] font-semibold">{item.source_ip}</span>
                    <span className="ml-1.5 text-[10px] text-slate-400">({item.country})</span>
                  </td>
                  <td className="py-3 px-3 text-slate-300 max-w-xs truncate" title={item.target}>
                    {item.target}
                  </td>
                  <td className="py-3 px-3 whitespace-nowrap">
                    {getStatusBadge(item.status)}
                  </td>
                  <td className="py-3 px-3 whitespace-nowrap">
                    <span className={`font-bold ${
                      item.risk_score >= 0.8 ? 'text-[#FF1744]' : (item.risk_score >= 0.5 ? 'text-[#FFB300]' : 'text-[#00C853]')
                    }`}>
                      {item.risk_score.toFixed(2)}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-right whitespace-nowrap">
                    <button
                      onClick={e => {
                        e.stopPropagation();
                        onSelectAlert(item);
                      }}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[#0F2744] hover:bg-[#00D9FF] hover:text-black text-[#00D9FF] border border-[#00D9FF]/30 transition-all font-semibold"
                    >
                      <span>Remediate</span>
                      <ArrowUpRight className="w-3 h-3" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
