import React, { useState, useEffect, useRef } from 'react';
import { Navbar } from './components/Navbar';
import { ThreatLevelBanner } from './components/ThreatLevelBanner';
import { DashboardWorkbench } from './components/DashboardWorkbench';
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
import { Shield, LayoutDashboard, Link2, Radio, Globe, Lock, FileText, X, LogOut, Zap } from 'lucide-react';
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
      setLastScanSeconds(prev => Math.min(60, prev + 1));
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
            setLastScanSeconds(1);
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

  useEffect(() => {
    const dashboard = document.querySelector('.dashboard-main');
    if (!dashboard) return;

    const sections = Array.from(dashboard.querySelectorAll<HTMLElement>('[data-reveal]'));
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduceMotion || !('IntersectionObserver' in window)) {
      sections.forEach(section => section.classList.add('is-visible'));
      return;
    }

    dashboard.classList.add('motion-ready');
    sections.forEach((section, index) => {
      section.style.setProperty('--reveal-delay', `${Math.min(index * 75, 300)}ms`);
    });

    const observer = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add('is-visible');
        observer.unobserve(entry.target);
      });
    }, { threshold: 0.12, rootMargin: '0px 0px -8% 0px' });

    sections.forEach(section => observer.observe(section));
    return () => {
      observer.disconnect();
      dashboard.classList.remove('motion-ready');
      sections.forEach(section => section.style.removeProperty('--reveal-delay'));
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
    const response = await apiFetch(apiUrl('/api/security/block-ip'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip_address: ip, duration_hours: 0, reason }) // permanent
    });
    if (!response.ok) throw new Error('Could not block this IP.');
    const result: { mitigated_at?: string | null } = await response.json();
    if (result.mitigated_at) {
      setSelectedAlert(current => current?.source_ip === ip
        ? { ...current, mitigated_at: result.mitigated_at }
        : current);
    }
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

  if (authLoading) return <div className="auth-loading">Loading Sentinel AI…</div>;
  if (!user) return <div className="sentinel-app"><AuthScreen onAuthenticated={setUser} /></div>;

  return (
    <div className="sentinel-app">
      <aside className={`sentinel-sidebar${mobileNavOpen ? ' sidebar--open' : ''}`} aria-label="Main navigation">
        <div className="sidebar-brand">
          <span className="brand-mark"><Shield size={19} /></span>
          <div><div className="brand-title">Sentinel AI</div><div className="brand-subtitle">Security console</div></div>
          <button className="sidebar-close quiet-button" onClick={() => setMobileNavOpen(false)} aria-label="Close navigation"><X size={18} /></button>
        </div>
        <div className="sidebar-group">
          <div className="sidebar-group-title">Overview</div>
          <button onClick={() => setMobileNavOpen(false)} className="side-link side-link--current" aria-current="page"><LayoutDashboard size={16} /> Dashboard</button>
        </div>
        <div className="sidebar-group">
          <div className="sidebar-group-title">Monitor</div>
          <button onClick={() => {setIsIntegrationsOpen(true);setMobileNavOpen(false)}} className="side-link"><Link2 size={16} /> Websites</button>
          <button onClick={() => {setIsTrafficOpen(true);setMobileNavOpen(false)}} className="side-link"><Radio size={16} /> Live traffic</button>
          <button onClick={() => {setIsMapOpen(true);setMobileNavOpen(false)}} className="side-link"><Globe size={16} /> Threat map</button>
        </div>
        <div className="sidebar-group">
          <div className="sidebar-group-title">Response</div>
          <button onClick={() => {setIsFirewallOpen(true);setMobileNavOpen(false)}} className="side-link"><Lock size={16} /> Firewall</button>
          <button onClick={() => {setIsReportOpen(true);setMobileNavOpen(false)}} className="side-link"><FileText size={16} /> Security reports</button>
        </div>
        <div className="sidebar-account">
          <div className="account-row">
            <span className="account-monogram">{user.name.slice(0, 1).toUpperCase()}</span>
            <div className="account-copy"><div className="account-name">{user.name}</div><div className="account-email">{user.email}</div></div>
            <button onClick={handleLogout} className="quiet-button" title="Sign out" aria-label="Sign out"><LogOut size={15} /></button>
          </div>
          <div className="monitor-state"><strong>Monitoring</strong> {wsConnected ? 'active' : 'connecting'}</div>
        </div>
      </aside>
      {mobileNavOpen && <button className="sidebar-backdrop" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)} />}
      <div className="sentinel-content">
        <Navbar
          systemStatus={metrics?.system_status || 'CONNECTING'}
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
        <main className="dashboard-main">
          <div className="dashboard-heading" data-reveal>
            <div><h1>Dashboard</h1><p>Review security findings and live traffic from your connected e-commerce websites.</p></div>
            <div className="dashboard-actions">
              <button className="action-button" onClick={() => setIsSimulatorOpen(true)}><Zap size={15} /> Safe simulation</button>
              <button className="action-button action-button--primary" onClick={() => setIsIntegrationsOpen(true)}><Link2 size={15} /> Add website</button>
            </div>
          </div>
          <div data-reveal><ThreatLevelBanner
            threatLevel={metrics?.threat_level || 'UNKNOWN'}
            activeThreats={metrics?.active_threats ?? null}
            blockedToday={metrics?.blocked_today ?? null}
            riskScore={metrics?.risk_score ?? null}
          /></div>
          <div data-reveal><MetricCards metrics={metrics} /></div>
          <div data-reveal><DashboardWorkbench packets={trafficPackets} alerts={alerts} /></div>
          <div data-reveal><RecentActivityTable alerts={alerts} onSelectAlert={(alert) => setSelectedAlert(alert)} /></div>
        </main>
        <ThreatDetailModal alert={selectedAlert} onClose={() => setSelectedAlert(null)} onBlockIP={handleBlockIP} onUnblockIP={handleUnblockIP} />
        <AttackSimulatorModal isOpen={isSimulatorOpen} onClose={() => setIsSimulatorOpen(false)} onAttackSimulated={fetchOverview} />
        <ThreatMapModal isOpen={isMapOpen} onClose={() => setIsMapOpen(false)} alerts={alerts} />
        <FirewallModal isOpen={isFirewallOpen} onClose={() => setIsFirewallOpen(false)} onRefresh={fetchOverview} />
        <SecurityReportModal isOpen={isReportOpen} onClose={() => setIsReportOpen(false)} />
        <LiveTrafficDrawer isOpen={isTrafficOpen} onClose={() => setIsTrafficOpen(false)} packets={trafficPackets} />
        <IntegrationsModal isOpen={isIntegrationsOpen} onClose={() => setIsIntegrationsOpen(false)} />
      </div>
    </div>
  );
};

export default App;
