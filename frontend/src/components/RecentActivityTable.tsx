import React, { useState } from 'react';
import { AlertItem, SeverityLevel } from '../types';
import { Search } from 'lucide-react';

interface RecentActivityTableProps {
  alerts: AlertItem[];
  onSelectAlert: (alert: AlertItem) => void;
}

const severityClass = (severity: SeverityLevel) => `severity-badge severity-badge--${severity}`;
const formatTime = (value: string) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
};

export const RecentActivityTable: React.FC<RecentActivityTableProps> = ({ alerts, onSelectAlert }) => {
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const filtered = alerts.filter(item => {
    if (filterSeverity !== 'all' && item.severity !== filterSeverity) return false;
    const query = searchQuery.trim().toLowerCase();
    return !query || [item.source_ip, item.target, item.threat_type, item.description, item.country].some(value => value.toLowerCase().includes(query));
  });

  return <section className="panel activity-panel" aria-label="Recent security activity">
    <div className="activity-header">
      <div><h2>Recent activity</h2><p>Choose an event to inspect its details and response options.</p></div>
      <div className="activity-controls">
        <label className="activity-search-wrap"><Search size={14} aria-hidden="true" /><span className="sr-only">Search security events</span><input className="activity-search" type="search" placeholder="Search events" value={searchQuery} onChange={e => setSearchQuery(e.target.value)} /></label>
        <div className="segmented-control" role="group" aria-label="Filter by severity">
          {['all', 'critical', 'warning', 'info'].map(sev => <button key={sev} type="button" className="severity-filter" aria-pressed={filterSeverity === sev} onClick={() => setFilterSeverity(sev)}>{sev[0].toUpperCase() + sev.slice(1)}</button>)}
        </div>
      </div>
    </div>
    <div className="activity-table-scroll"><table className="activity-table">
      <thead><tr><th scope="col">Time</th><th scope="col">Severity</th><th scope="col">Event</th><th scope="col">Source</th><th scope="col">Target</th><th scope="col">Status</th><th scope="col">Risk</th><th scope="col"><span className="sr-only">Review</span></th></tr></thead>
      <tbody>{filtered.length === 0 ? <tr><td className="table-empty" colSpan={8}>{alerts.length ? 'No alerts match these filters.' : 'No alert records are available in the current feed.'}</td></tr> : filtered.map(item => <tr key={item.id} onClick={() => onSelectAlert(item)} tabIndex={0} onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') onSelectAlert(item); }}>
        <td className="measured-cell">{formatTime(item.timestamp)}</td>
        <td><span className={severityClass(item.severity)}>{item.severity}</span></td>
        <td>{item.threat_type.replaceAll('_', ' ')}</td>
        <td><span className="measured-cell">{item.source_ip}</span><span className="country-cell"> {item.country}</span></td>
        <td className="target-cell" title={item.target}>{item.target}</td>
        <td><span className={`status-badge status-badge--${item.status}`}>{item.status}</span></td>
        <td className="measured-cell">{item.risk_score.toFixed(2)}</td>
        <td><button className="activity-link" onClick={e => { e.stopPropagation(); onSelectAlert(item); }}>Review</button></td>
      </tr>)}</tbody>
    </table></div>
  </section>;
};
