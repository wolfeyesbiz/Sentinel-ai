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
import { AuthScreen } from './components/AuthScreen';
import { soundAlert } from './SoundAlert';
import { AlertItem, SystemMetrics, TrafficPacket } from './types';
import { Shield, LayoutDashboard, Link2, Radio, Globe, Lock, FileText, Menu, X, LogOut } from 'lucide-react';
import { apiFetch, apiUrl, WS_BASE } from './api';

export const App: React.FC = () => {
  const [user, setUser] = useState<{ id: string; name: string; email: string } | null>(null);
  const [authLoading, setAuthLoading] = useState(true);
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
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    apiFetch(apiUrl('/api/auth/me')).then(async response => {
      if (response.ok) setUser((await response.json()).user);
    }).catch(() => {}).finally(() => setAuthLoading(false));
  }, []);

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
      const ovRes = await apiFetch(apiUrl('/api/dashboard/overview'));
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

      const alRes = await apiFetch(apiUrl('/api/alerts/recent?limit=50&severity=all'));
      const alData = await alRes.json();
      if (alData.alerts) {
        setAlerts(alData.alerts);
      }

      const tfRes = await apiFetch(apiUrl('/api/traffic/recent'));
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
    if (!user) return;
    fetchOverview();

    const sessionToken = window.sessionStorage.getItem('sentinel_session');

    let reconnectTimer: any;

    const connectWS = () => {
      const ws = sessionToken
        ? new WebSocket(`${WS_BASE}/ws/stream`, [`sentinel-auth-${sessionToken}`])
        : new WebSocket(`${WS_BASE}/ws/stream`);
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
  }, [user]);

  const handleLogout = async () => {
    try { await apiFetch(apiUrl('/api/auth/logout'), { method: 'POST' }); } catch { /* Clear the dashboard locally even if Render is offline. */ }
    window.sessionStorage.removeItem('sentinel_session');
    setUser(null);
    setMetrics(null);
    setAlerts([]);
    setTrafficPackets([]);
  };

  const handleToggleSound = () => {
    const newState = soundAlert.toggle();
    setSoundEnabled(newState);
  };

  const handleBlockIP = async (ip: string, reason: string) => {
    await apiFetch(apiUrl('/api/security/block-ip'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip_address: ip, duration_hours: 0, reason }) // permanent
    });
    await fetchOverview();
  };

  const handleUnblockIP = async (ip: string) => {
    await apiFetch(apiUrl('/api/security/unblock-ip'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip_address: ip })
    });
    await fetchOverview();
  };

  if (authLoading) return <div className="flex min-h-screen items-center justify-center bg-[#090909] text-sm text-zinc-500">Loading Sentinel AI…</div>;
  if (!user) return <AuthScreen onAuthenticated={setUser} />;

  return (
    <div className="min-h-screen bg-[#090909] text-zinc-100 selection:bg-emerald-500 selection:text-black">
      <aside className={`fixed inset-y-0 left-0 z-40 flex w-[228px] flex-col border-r border-[#222] bg-[#070707] transition-transform md:translate-x-0 ${mobileNavOpen ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="flex h-[68px] items-center gap-3 border-b border-[#222] px-5"><span className="rounded-lg bg-emerald-500/10 p-2 text-emerald-500"><Shield size={18}/></span><div><div className="text-sm font-semibold">Sentinel AI</div><div className="text-[10px] tracking-wide text-zinc-500">SECURITY CONSOLE</div></div><button className="ml-auto text-zinc-500 md:hidden" onClick={() => setMobileNavOpen(false)} aria-label="Close navigation"><X size={18}/></button></div>
        <div className="px-3 pt-6"><div className="px-2 pb-2 text-[10px] font-medium uppercase tracking-[0.16em] text-zinc-600">Overview</div><button onClick={() => setMobileNavOpen(false)} className="flex w-full items-center gap-3 rounded-lg bg-emerald-500/10 px-3 py-2.5 text-left text-sm text-emerald-400"><LayoutDashboard size={16}/> Dashboard</button></div>
        <div className="px-3 pt-7"><div className="px-2 pb-2 text-[10px] font-medium uppercase tracking-[0.16em] text-zinc-600">Monitor</div>
          <button onClick={() => {setIsIntegrationsOpen(true);setMobileNavOpen(false)}} className="side-link"><Link2 size={16}/> Websites</button>
          <button onClick={() => {setIsTrafficOpen(true);setMobileNavOpen(false)}} className="side-link"><Radio size={16}/> Live traffic</button>
          <button onClick={() => {setIsMapOpen(true);setMobileNavOpen(false)}} className="side-link"><Globe size={16}/> Threat map</button>
        </div>
        <div className="px-3 pt-7"><div className="px-2 pb-2 text-[10px] font-medium uppercase tracking-[0.16em] text-zinc-600">Response</div>
          <button onClick={() => {setIsFirewallOpen(true);setMobileNavOpen(false)}} className="side-link"><Lock size={16}/> Firewall</button>
          <button onClick={() => {setIsReportOpen(true);setMobileNavOpen(false)}} className="side-link"><FileText size={16}/> Security reports</button>
        </div>
        <div className="mt-auto border-t border-[#222] p-4"><div className="mb-4 flex items-center gap-3"><span className="grid h-8 w-8 place-items-center rounded-full bg-emerald-500/15 text-xs font-semibold text-emerald-400">{user.name.slice(0, 1).toUpperCase()}</span><div className="min-w-0"><div className="truncate text-xs text-zinc-200">{user.name}</div><div className="truncate text-[10px] text-zinc-600">{user.email}</div></div><button onClick={handleLogout} className="ml-auto rounded p-1.5 text-zinc-500 hover:bg-white/5 hover:text-white" title="Sign out" aria-label="Sign out"><LogOut size={15}/></button></div><div className="flex items-center gap-3"><span className={`h-2 w-2 rounded-full ${wsConnected ? 'bg-emerald-500' : 'bg-zinc-600'}`}/><div><div className="text-xs text-zinc-300">Monitoring {wsConnected ? 'active' : 'connecting'}</div><div className="mt-0.5 text-[10px] text-zinc-600">Sentinel system status</div></div></div></div>
      </aside>
      {mobileNavOpen && <button className="fixed inset-0 z-30 bg-black/60 md:hidden" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)}/>}
      <div className="min-h-screen md:ml-[228px]">
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
        onOpenMenu={() => setMobileNavOpen(true)}
      />

      {/* Main Dashboard Container */}
      <main className="mx-auto w-full max-w-[1440px] px-4 py-6 md:px-8">
        <div className="mb-5"><p className="text-xs text-zinc-500">Security overview</p><h1 className="mt-1 text-2xl font-semibold tracking-tight text-zinc-100">Dashboard</h1><p className="mt-1 text-sm text-zinc-500">Monitor activity and review your connected websites.</p></div>
        {/* Threat Level Banner */}
        <ThreatLevelBanner
          threatLevel={metrics?.threat_level || 'LOW'}
          activeThreats={metrics?.active_threats || 0}
          blockedToday={metrics?.blocked_today || 0}
          riskScore={metrics?.risk_score || 0.12}
        />

        {/* System Resource Gauges */}
        <MetricCards metrics={metrics} />

        {/* Live Recent Activity Table */}
        <RecentActivityTable
          alerts={alerts}
          onSelectAlert={(alert) => setSelectedAlert(alert)}
        />

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
    </div>
  );
};

export default App;
