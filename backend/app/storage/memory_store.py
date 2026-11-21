import time
import asyncio
from typing import List, Dict, Any, Optional, Set
from collections import deque
from fastapi import WebSocket
from datetime import datetime, timezone
import psutil

class MemoryStore:
    def __init__(self):
        # Sliding buffer of recent traffic packets (last 200)
        self.recent_traffic = deque(maxlen=200)
        
        # Sliding buffer of recent alerts for instant in-memory retrieval (last 100)
        self.recent_alerts = deque(maxlen=100)
        
        # Brute force attempt tracker: key: ip:username -> list of timestamps
        self.login_attempts: Dict[str, deque] = {}
        
        # IP request rate tracker: ip -> deque of timestamps
        self.request_velocity: Dict[str, deque] = {}
        
        # Active customer session tracking: session_id -> {ip, user_agent, created_at, last_active, actions}
        self.sessions: Dict[str, Dict[str, Any]] = {}
        
        # Connected WebSockets for real-time streaming
        self.active_websockets: Set[WebSocket] = set()
        
        # System metrics history (last 60 seconds)
        self.metrics_history = deque(maxlen=60)
        
        # In-memory counters
        self.total_requests_processed = 0
        self.total_threats_blocked = 0
        self.last_network_bytes = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
        self.last_network_check = time.time()
        self.current_network_mbps = 2.4

    async def connect_ws(self, websocket: WebSocket, subprotocol: Optional[str] = None):
        await websocket.accept(subprotocol=subprotocol)
        self.active_websockets.add(websocket)

    def disconnect_ws(self, websocket: WebSocket):
        self.active_websockets.discard(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        dead_sockets = set()
        for ws in list(self.active_websockets):
            try:
                await ws.send_json(message)
            except Exception:
                dead_sockets.add(ws)
        self.active_websockets.difference_update(dead_sockets)

    def record_traffic(self, packet: Dict[str, Any]):
        self.total_requests_processed += 1
        self.recent_traffic.appendleft(packet)

    def record_alert(self, alert_dict: Dict[str, Any]):
        if alert_dict.get("status") == "blocked":
            self.total_threats_blocked += 1
        self.recent_alerts.appendleft(alert_dict)

    def track_request_rate(self, ip: str) -> int:
        """Returns requests in the last 1 second for DoS detection."""
        now = time.time()
        if ip not in self.request_velocity:
            self.request_velocity[ip] = deque(maxlen=200)
        queue = self.request_velocity[ip]
        queue.append(now)
        # Purge items older than 1 second
        while queue and (now - queue[0] > 1.0):
            queue.popleft()
        return len(queue)

    def track_failed_login(self, ip: str, username: str) -> int:
        """Tracks failed logins in the last 15 minutes."""
        now = time.time()
        key = f"{ip}:{username}"
        if key not in self.login_attempts:
            self.login_attempts[key] = deque(maxlen=50)
        queue = self.login_attempts[key]
        queue.append(now)
        # Purge items older than 15 minutes (900 seconds)
        while queue and (now - queue[0] > 900):
            queue.popleft()
        return len(queue)

    def get_live_metrics(self) -> Dict[str, Any]:
        """Calculates live CPU, RAM, Network I/O, process count and threat score."""
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent
        process_count = len(psutil.pids())
        
        # Calculate network I/O in MB/s
        now = time.time()
        elapsed = now - self.last_network_check
        if elapsed >= 0.8:
            net_counters = psutil.net_io_counters()
            current_bytes = net_counters.bytes_sent + net_counters.bytes_recv
            bytes_diff = max(0, current_bytes - self.last_network_bytes)
            self.current_network_mbps = round((bytes_diff / (1024 * 1024)) / max(0.1, elapsed), 2)
            self.last_network_bytes = current_bytes
            self.last_network_check = now

        # Compute dynamic threat level
        recent_crit_count = sum(
            1 for a in list(self.recent_alerts)[:15] 
            if a.get("severity") in ("critical", "emergency")
        )
        recent_warn_count = sum(
            1 for a in list(self.recent_alerts)[:15] 
            if a.get("severity") == "warning"
        )
        
        if recent_crit_count >= 2:
            threat_level = "CRITICAL"
            risk_score = min(0.98, 0.85 + recent_crit_count * 0.03)
        elif recent_crit_count == 1:
            threat_level = "ELEVATED"
            risk_score = 0.76
        elif recent_warn_count >= 2:
            threat_level = "MEDIUM"
            risk_score = 0.48
        else:
            threat_level = "LOW"
            risk_score = 0.12

        metrics = {
            "cpu_usage": round(cpu, 1),
            "ram_usage": round(ram, 1),
            "network_io": max(0.4, self.current_network_mbps),
            "active_processes": process_count,
            "threat_level": threat_level,
            "risk_score": round(risk_score, 2),
            "system_status": "PROTECTED",
            "active_threats": recent_crit_count,
            "blocked_today": self.total_threats_blocked,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        self.metrics_history.append(metrics)
        return metrics

memory_store = MemoryStore()
