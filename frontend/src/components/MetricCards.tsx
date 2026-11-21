import React from 'react';
import { SystemMetrics } from '../types';

interface MetricCardsProps { metrics: SystemMetrics | null }

export const MetricCards: React.FC<MetricCardsProps> = ({ metrics }) => {
  const cards = [
    { label: 'CPU usage', value: metrics ? `${Math.round(metrics.cpu_usage)}%` : '—', detail: 'Sentinel host' },
    { label: 'Memory', value: metrics ? `${Math.round(metrics.ram_usage)}%` : '—', detail: 'Sentinel host' },
    { label: 'Network I/O', value: metrics ? `${Number(metrics.network_io).toFixed(1)} MB/s` : '—', detail: 'Sentinel host' },
    { label: 'Active processes', value: metrics ? String(metrics.active_processes) : '—', detail: 'Sentinel host' },
  ];

  return <section className="panel metrics-panel" aria-label="Sentinel host resources">
    <h2 className="sr-only">Sentinel host resources</h2>
    {cards.map(card => <dl className="metric-reading" key={card.label}>
      <dt className="metric-label">{card.label}</dt>
      <dd className="metric-value">{card.value}</dd>
      <dd className="metric-detail">{card.detail}</dd>
    </dl>)}
  </section>;
};
