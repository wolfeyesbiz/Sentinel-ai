export type SeverityLevel = 'info' | 'warning' | 'critical' | 'emergency';
export type ThreatStatus = 'blocked' | 'flagged' | 'monitored' | 'resolved' | 'allowed';

export interface PreventionMeasure {
  title: string;
  description: string;
  code_example?: string;
  configuration?: string;
  priority: string;
}

export interface RemediationGuide {
  threat_type: string;
  severity: string;
  explanation: string;
  impact_assessment: {
    potential_damage: string;
    data_at_risk: string;
    business_impact: string;
  };
  immediate_actions_taken: string[];
  how_to_fix_now: string[];
  prevention_measures: PreventionMeasure[];
}

export interface AlertItem {
  id: string;
  timestamp: string;
  severity: SeverityLevel;
  threat_type: string;
  source_ip: string;
  country: string;
  target: string;
  status: ThreatStatus;
  mitigated_at?: string | null;
  risk_score: number;
  description: string;
  payload?: string;
  attack_vector?: string;
  details?: Record<string, any>;
  remediation?: RemediationGuide;
}

export interface SystemMetrics {
  cpu_usage: number;
  ram_usage: number;
  network_io: number;
  active_processes: number;
  threat_level: string;
  risk_score: number;
  system_status: string;
  active_threats: number;
  blocked_today: number;
  timestamp: string;
}

export interface TrafficPacket {
  id: string;
  timestamp: string;
  ip: string;
  country: string;
  method: string;
  path: string;
  status: number;
  action: string;
  threat_type: string;
  risk_score: number;
}

export interface BlockedIPItem {
  ip_address: string;
  reason: string;
  blocked_at: string;
  blocked_until?: string;
  permanent: boolean;
  attack_count: number;
}

export interface WafRule {
  id: string;
  name: string;
  threat_type: string;
  pattern: string;
  action: string;
  enabled: boolean;
  description: string;
}
