import React, { useState, useEffect, useRef } from 'react';
import { Navbar } from './components/Navbar';
import { ThreatLevelBanner } from './components/ThreatLevelBanner';
import { MetricCards } from './components/MetricCards';
import { RecentActivityTable } from './components/RecentActivityTable';
import { ThreatDetailModal } from './components/ThreatDetailModal';
import { AttackSimulatorModal } from './components/AttackSimulatorModal';
import { ThreatMapModal } from './components/ThreatMapModal';
import { FirewallModal } from './components/FirewallModal';
import { SecurityReportModal } from './components/SecurityReportModal';
import { LiveTrafficDrawer } from './components/LiveTrafficDrawer';
import { IntegrationsModal } from './components/IntegrationsModal';
import { soundAlert } from './SoundAlert';
import { AlertItem, SystemMetrics, TrafficPacket } from './types';
import { ShieldAlert, Zap, Globe, Lock, FileText, Activity } from 'lucide-react';
import { apiUrl, WS_BASE } from './api';

export const App: React.FC = () => {
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [trafficPackets, setTrafficPackets] = useState<TrafficPacket[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null);

  // Modals state
  const [isSimulatorOpen, setIsSimulatorOpen] = useState(false);
  const [isMapOpen, setIsMapOpen] = useState(false);
  const [isFirewallOpen, setIsFirewallOpen] = useState(false);
  const [isReportOpen, setIsReportOpen] = useState(false);
  const [isTrafficOpen, setIsTrafficOpen] = useState(false);
  const [isIntegrationsOpen, setIsIntegrationsOpen] = useState(false);

  // WebSocket & Timer state
  const [wsConnected, setWsConnected] = useState(false);
  const [lastScanSeconds, setLastScanSeconds] = useState(2);
  const [soundEnabled, setSoundEnabled] = useState(soundAlert.enabled);
  const wsRef = useRef<WebSocket | null>(null);

  // Ticking timer for "Last Scan: Xs ago"
  useEffect(() => {
    const timer = setInterval(() => {
      setLastScanSeconds(prev => (prev >= 60 ? 1 : prev + 1));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Initial REST fetch
  const fetchOverview = async () => {
    try {
      const ovRes = await fetch(apiUrl('/api/dashboard/overview'));
      const ovData = await ovRes.json();
      setMetrics({
        cpu_usage: ovData.system_metrics.cpu_usage,
        ram_usage: ovData.system_metrics.ram_usage,
        network_io: ovData.system_metrics.network_io,
        active_processes: ovData.system_metrics.active_processes,
        threat_level: ovData.threat_level,
        risk_score: ovData.risk_score,
        system_status: ovData.system_status,
        active_threats: ovData.active_threats,
        blocked_today: ovData.blocked_today,
        timestamp: new Date().toISOString()
      });

      const alRes = await fetch(apiUrl('/api/alerts/recent?limit=50&severity=all'));
      const alData = await alRes.json();
      if (alData.alerts) {
        setAlerts(alData.alerts);
      }

      const tfRes = await fetch(apiUrl('/api/traffic/recent'));
      const tfData = await tfRes.json();
      if (Array.isArray(tfData)) {
        setTrafficPackets(tfData);
      }
    } catch (e) {
      console.error('Failed to fetch initial dashboard data', e);
    }
  };

  // WebSocket Connection
  useEffect(() => {
    fetchOverview();

    const wsUrl = `${WS_BASE}/ws/stream`;

    let reconnectTimer: any;

    const connectWS = () => {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setWsConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'INITIAL_SNAPSHOT') {
            if (data.metrics) setMetrics(data.metrics);
            if (data.recent_alerts) setAlerts(data.recent_alerts);
            if (data.recent_traffic) setTrafficPackets(data.recent_traffic);
          } else if (data.type === 'METRICS_UPDATE') {
            setLastScanSeconds(1);
            if (data.metrics) setMetrics(data.metrics);
            if (data.traffic_packet) {
              setTrafficPackets(prev => [data.traffic_packet, ...prev.slice(0, 100)]);
            }
          } else if (data.type === 'NEW_ALERT') {
            setLastScanSeconds(0);
            if (data.alert) {
              setAlerts(prev => [data.alert, ...prev]);
              // Trigger audio chime
              if (data.play_sound) {
                if (data.alert.severity === 'critical' || data.alert.severity === 'emergency') {
                  soundAlert.playCriticalAlert();
                } else {
                  soundAlert.playWarningAlert();
                }
              }
            }
          }
        } catch (e) {
          console.error('Error parsing WS message', e);
        }
      };

      ws.onclose = () => {
        setWsConnected(false);
        reconnectTimer = setTimeout(connectWS, 3000);
      };

      ws.onerror = () => {
        ws.close();
      };
    };

    connectWS();

    return () => {
      clearTimeout(reconnectTimer);
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const handleToggleSound = () => {
    const newState = soundAlert.toggle();
    setSoundEnabled(newState);
  };

  const handleBlockIP = async (ip: string, reason: string) => {
    await fetch(apiUrl('/api/security/block-ip'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip_address: ip, duration_hours: 0, reason }) // permanent
    });
    await fetchOverview();
  };

  const handleUnblockIP = async (ip: string) => {
    await fetch(apiUrl('/api/security/unblock-ip'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip_address: ip })
    });
    await fetchOverview();
  };

  return (
    <div className="min-h-screen bg-[#06101E] text-slate-100 flex flex-col selection:bg-[#00D9FF] selection:text-black">
      {/* Top Navigation */}
      <Navbar
        systemStatus={metrics?.system_status || 'PROTECTED'}
        lastScanSeconds={lastScanSeconds}
        wsConnected={wsConnected}
        soundEnabled={soundEnabled}
        onToggleSound={handleToggleSound}
        onOpenSimulator={() => setIsSimulatorOpen(true)}
        onOpenMap={() => setIsMapOpen(true)}
        onOpenFirewall={() => setIsFirewallOpen(true)}
        onOpenReport={() => setIsReportOpen(true)}
        onOpenTraffic={() => setIsTrafficOpen(true)}
        onOpenIntegrations={() => setIsIntegrationsOpen(true)}
      />

      {/* Main Dashboard Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 lg:px-8 py-6">
        {/* Threat Level Banner */}
        <ThreatLevelBanner
          threatLevel={metrics?.threat_level || 'LOW'}
          activeThreats={metrics?.active_threats || 0}
          blockedToday={metrics?.blocked_today || 47}
          riskScore={metrics?.risk_score || 0.12}
        />

        {/* System Resource Gauges */}
        <MetricCards metrics={metrics} />

        {/* Live Recent Activity Table */}
        <RecentActivityTable
          alerts={alerts}
          onSelectAlert={(alert) => setSelectedAlert(alert)}
        />

        {/* Bottom Quick-Action Buttons matching wireframe */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 pb-8 border-t border-[#1E3A5F]">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setIsSimulatorOpen(true)}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded bg-gradient-to-r from-red-600 to-amber-600 hover:from-red-500 hover:to-amber-500 text-white font-mono text-xs font-bold shadow transition-all cursor-pointer"
            >
              <Zap className="w-4 h-4 fill-current" />
              <span>[Simulate Attack]</span>
            </button>

            <button
              onClick={() => setIsMapOpen(true)}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded bg-[#0A1929] hover:bg-[#0F2744] text-slate-200 border border-[#1E3A5F] font-mono text-xs font-medium transition-all cursor-pointer"
            >
              <Globe className="w-4 h-4 text-[#00D9FF]" />
              <span>[Threat Map]</span>
            </button>

            <button
              onClick={() => setIsReportOpen(true)}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded bg-[#0A1929] hover:bg-[#0F2744] text-slate-200 border border-[#1E3A5F] font-mono text-xs font-medium transition-all cursor-pointer"
            >
              <FileText className="w-4 h-4 text-emerald-400" />
              <span>[Security Report]</span>
            </button>

            <button
              onClick={() => setIsFirewallOpen(true)}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded bg-[#0A1929] hover:bg-[#0F2744] text-slate-200 border border-[#1E3A5F] font-mono text-xs font-medium transition-all cursor-pointer"
            >
              <Lock className="w-4 h-4 text-amber-400" />
              <span>[Firewall Rules]</span>
            </button>
          </div>

          <button
            onClick={() => setIsTrafficOpen(true)}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded bg-[#0A1929] hover:bg-[#0F2744] text-[#00D9FF] border border-[#00D9FF]/30 font-mono text-xs font-medium transition-all cursor-pointer"
          >
            <Activity className="w-4 h-4 text-[#00D9FF]" />
            <span>[Live Stream Inspector]</span>
          </button>
        </div>
      </main>

      {/* Threat Detail Modal */}
      <ThreatDetailModal
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onBlockIP={handleBlockIP}
        onUnblockIP={handleUnblockIP}
      />

      {/* Attack Simulator Modal */}
      <AttackSimulatorModal
        isOpen={isSimulatorOpen}
        onClose={() => setIsSimulatorOpen(false)}
        onAttackSimulated={fetchOverview}
      />

      {/* Threat Map Modal */}
      <ThreatMapModal
        isOpen={isMapOpen}
        onClose={() => setIsMapOpen(false)}
        alerts={alerts}
      />

      {/* Firewall & WAF Rules Modal */}
      <FirewallModal
        isOpen={isFirewallOpen}
        onClose={() => setIsFirewallOpen(false)}
        onRefresh={fetchOverview}
      />

      {/* Security Report Modal */}
      <SecurityReportModal
        isOpen={isReportOpen}
        onClose={() => setIsReportOpen(false)}
      />

      {/* Live Traffic Inspector Drawer */}
      <LiveTrafficDrawer
        isOpen={isTrafficOpen}
        onClose={() => setIsTrafficOpen(false)}
        packets={trafficPackets}
      />
      <IntegrationsModal isOpen={isIntegrationsOpen} onClose={() => setIsIntegrationsOpen(false)} />
    </div>
  );
};

export default App;
