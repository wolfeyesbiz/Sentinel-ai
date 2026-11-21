import React, { useMemo, useState } from 'react';
import { Activity, Clock3 } from 'lucide-react';
import { AlertItem, TrafficPacket } from '../types';

type RangeKey = '15m' | '1h' | '24h';
type ChartMode = 'requests' | 'risk';

const ranges: Array<{ key: RangeKey; label: string; milliseconds: number }> = [
  { key: '15m', label: '15 min', milliseconds: 15 * 60 * 1000 },
  { key: '1h', label: '1 hour', milliseconds: 60 * 60 * 1000 },
  { key: '24h', label: '24 hours', milliseconds: 24 * 60 * 60 * 1000 },
];
const severities = ['emergency', 'critical', 'warning', 'info'] as const;

interface DashboardWorkbenchProps {
  packets: TrafficPacket[];
  alerts: AlertItem[];
}

export const DashboardWorkbench: React.FC<DashboardWorkbenchProps> = ({ packets, alerts }) => {
  const [range, setRange] = useState<RangeKey>('1h');
  const [mode, setMode] = useState<ChartMode>('requests');
  const activeRange = ranges.find(item => item.key === range) ?? ranges[1];
  const now = Date.now();
  const points = useMemo(() => {
    const selected = packets
      .map(packet => ({ packet, time: new Date(packet.timestamp).getTime() }))
      .filter(item => Number.isFinite(item.time) && item.time >= now - activeRange.milliseconds && item.time <= now)
      .sort((left, right) => left.time - right.time);
    const bucketCount = 12;
    const interval = activeRange.milliseconds / bucketCount;
    return Array.from({ length: bucketCount }, (_, index) => {
      const start = now - activeRange.milliseconds + index * interval;
      const bucket = selected.filter(item => item.time >= start && item.time < start + interval);
      return {
        time: start,
        requests: bucket.length,
        risk: bucket.length ? bucket.reduce((sum, item) => sum + item.packet.risk_score, 0) / bucket.length : 0,
      };
    });
  }, [packets, now, activeRange.milliseconds]);
  const hasData = points.some(point => mode === 'requests' ? point.requests > 0 : point.requests > 0 && point.risk > 0);
  const maxValue = mode === 'requests' ? Math.max(1, ...points.map(point => point.requests)) : 1;
  const pathPoints = points.map((point, index) => {
    const x = 32 + index * (696 / (points.length - 1));
    const value = mode === 'requests' ? point.requests : point.risk;
    const y = 184 - (value / maxValue) * 150;
    return { x, y, value };
  });
  const linePath = pathPoints.map((point, index) => `${index === 0 ? 'M' : 'L'} ${point.x} ${point.y}`).join(' ');
  const counts = severities.map(severity => ({
    severity,
    count: alerts.filter(alert => alert.severity === severity).length,
  }));
  const totalAlerts = counts.reduce((sum, item) => sum + item.count, 0);
  const highestCount = Math.max(1, ...counts.map(item => item.count));
  const totalPackets = points.reduce((sum, item) => sum + item.requests, 0);
  const meanRisk = totalPackets ? points.reduce((sum, item) => sum + item.risk * item.requests, 0) / totalPackets : null;

  return <section className="workbench-grid" aria-label="Live security telemetry">
    <article className="panel timeline-panel">
      <div className="panel-heading">
        <div><h2>Request timeline</h2><p>Traffic received by the Sentinel host</p></div>
        <div className="timeline-controls">
          <div className="segmented-control" role="group" aria-label="Timeline metric">
            <button className="segment-button" type="button" aria-pressed={mode === 'requests'} onClick={() => setMode('requests')}>Requests</button>
            <button className="segment-button" type="button" aria-pressed={mode === 'risk'} onClick={() => setMode('risk')}>Mean risk</button>
          </div>
          <div className="segmented-control" role="group" aria-label="Timeline range">
            {ranges.map(item => <button key={item.key} className="segment-button" type="button" aria-pressed={range === item.key} onClick={() => setRange(item.key)}>{item.label}</button>)}
          </div>
        </div>
      </div>
      <div className="timeline-wrap">
        {hasData ? <svg className="timeline-svg" viewBox="0 0 760 220" role="img" aria-label={`${mode === 'requests' ? 'Request count' : 'Mean risk score'} over the last ${activeRange.label}`}>
          <line className="timeline-gridline" x1="28" y1="34" x2="732" y2="34" />
          <line className="timeline-gridline" x1="28" y1="109" x2="732" y2="109" />
          <line className="timeline-gridline" x1="28" y1="184" x2="732" y2="184" />
          <text className="timeline-axis-label" x="2" y="37">{mode === 'requests' ? maxValue : '1.0'}</text>
          <text className="timeline-axis-label" x="2" y="187">0</text>
          <path className="timeline-line" d={linePath} />
          {pathPoints.filter(point => point.value > 0).map(point => <circle key={`${point.x}-${point.y}`} className="timeline-point" cx={point.x} cy={point.y} r="4" />)}
          <text className="timeline-axis-label" x="28" y="210">{new Date(now - activeRange.milliseconds).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</text>
          <text className="timeline-axis-label" x="732" y="210" textAnchor="end">Now</text>
        </svg> : <div className="timeline-empty"><strong>No request telemetry in this period</strong><span>Connect a website and forward request events to see its traffic.</span></div>}
      </div>
      <div className="timeline-footer">
        <span><strong>{mode === 'requests' ? totalPackets : meanRisk == null ? '—' : meanRisk.toFixed(2)}</strong> {mode === 'requests' ? 'requests in range' : 'mean risk score'}</span>
        <span><Clock3 size={13} aria-hidden="true" /> Source: request event feed</span>
      </div>
    </article>

    <article className="panel severity-panel">
      <div className="panel-heading"><div><h2>Alert severity</h2><p>Events reported to Sentinel</p></div><Activity size={17} aria-hidden="true" /></div>
      {totalAlerts ? <div className="severity-list" aria-label={`Alert severity distribution, ${totalAlerts} total alerts`}>
        {counts.map(item => <div className="severity-row" key={item.severity}>
          <span>{item.severity[0].toUpperCase() + item.severity.slice(1)}</span>
          <div className="severity-track" aria-hidden="true"><div className={`severity-fill severity-fill--${item.severity}`} style={{ transform: `scaleX(${item.count / highestCount})` }} /></div>
          <span className="severity-count">{item.count}</span>
        </div>)}
      </div> : <p className="severity-empty">No security events have been reported yet. Your monitored event feed will appear here.</p>}
      <div className="severity-footnote">Counts reflect the alert feed currently loaded in this dashboard.</div>
    </article>
  </section>;
};
