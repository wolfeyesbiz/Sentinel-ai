import sqlite3
import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from app.models.schemas import AlertItem, BlockedIPItem, SeverityLevel, ThreatType, ThreatStatus

# On Render (and similar PaaS), /tmp is the only writable directory on ephemeral filesystems.
# Fall back to the local path for development.
_default_db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinel.db")
DB_PATH = os.environ.get("DB_PATH", _default_db_path)

class Database:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._blocked_ips_cache: set = set()
        self._init_tables()
        self._load_blocked_cache()

    def _load_blocked_cache(self):
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT ip_address FROM blocked_ips")
                rows = cursor.fetchall()
                self._blocked_ips_cache = {r["ip_address"] for r in rows}
        except Exception:
            self._blocked_ips_cache = set()

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_tables(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    country TEXT NOT NULL,
                    target TEXT NOT NULL,
                    status TEXT NOT NULL,
                    mitigated_at TEXT,
                    risk_score REAL NOT NULL,
                    description TEXT NOT NULL,
                    payload TEXT,
                    attack_vector TEXT,
                    details_json TEXT,
                    remediation_json TEXT
                )
            """)
            alert_columns = {row["name"] for row in cursor.execute("PRAGMA table_info(alerts)").fetchall()}
            if "mitigated_at" not in alert_columns:
                cursor.execute("ALTER TABLE alerts ADD COLUMN mitigated_at TEXT")
            
            # Blocked IPs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip_address TEXT PRIMARY KEY,
                    reason TEXT NOT NULL,
                    blocked_at TEXT NOT NULL,
                    blocked_until TEXT,
                    permanent INTEGER NOT NULL DEFAULT 0,
                    attack_count INTEGER NOT NULL DEFAULT 1
                )
            """)

            # Traffic audit log
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS traffic_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    is_threat INTEGER NOT NULL DEFAULT 0,
                    risk_score REAL NOT NULL DEFAULT 0.0
                )
            """)
            conn.commit()

    def insert_alert(self, alert: AlertItem):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO alerts (
                    id, timestamp, severity, threat_type, source_ip, country, target, status, mitigated_at,
                    risk_score, description, payload, attack_vector, details_json, remediation_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.id,
                alert.timestamp,
                alert.severity.value,
                alert.threat_type.value,
                alert.source_ip,
                alert.country,
                alert.target,
                alert.status.value,
                alert.mitigated_at,
                alert.risk_score,
                alert.description,
                alert.payload,
                alert.attack_vector,
                json.dumps(alert.details),
                alert.remediation.model_dump_json() if alert.remediation else None
            ))
            conn.commit()

    def mitigate_alerts_for_ip(self, ip_address: str, mitigated_at: str) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE alerts SET mitigated_at = ? WHERE source_ip = ? AND mitigated_at IS NULL",
                (mitigated_at, ip_address),
            )
            conn.commit()
            return cursor.rowcount

    def resolve_alert(self, alert_id: str, resolved_at: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE alerts SET status = 'resolved', mitigated_at = COALESCE(mitigated_at, ?) WHERE id = ?",
                (resolved_at, alert_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def get_recent_alerts(self, limit: int = 50, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if severity and severity.lower() != "all":
                cursor.execute("""
                    SELECT * FROM alerts 
                    WHERE severity = ? 
                    ORDER BY timestamp DESC LIMIT ?
                """, (severity.lower(), limit))
            else:
                cursor.execute("""
                    SELECT * FROM alerts 
                    ORDER BY timestamp DESC LIMIT ?
                """, (limit,))
            
            rows = cursor.fetchall()
            results = []
            for row in rows:
                item = dict(row)
                if item.get("details_json"):
                    try:
                        item["details"] = json.loads(item["details_json"])
                    except Exception:
                        item["details"] = {}
                else:
                    item["details"] = {}
                
                if item.get("remediation_json"):
                    try:
                        item["remediation"] = json.loads(item["remediation_json"])
                    except Exception:
                        item["remediation"] = None
                else:
                    item["remediation"] = None
                    
                results.append(item)
            return results

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
            row = cursor.fetchone()
            if not row:
                return None
            item = dict(row)
            item["details"] = json.loads(item["details_json"]) if item.get("details_json") else {}
            item["remediation"] = json.loads(item["remediation_json"]) if item.get("remediation_json") else None
            return item

    def block_ip(self, ip_address: str, reason: str, duration_hours: int = 24, permanent: bool = False) -> BlockedIPItem:
        self._blocked_ips_cache.add(ip_address)
        now = datetime.now(timezone.utc)
        blocked_at = now.isoformat()
        blocked_until = None
        if not permanent and duration_hours > 0:
            import datetime as dt
            blocked_until = (now + dt.timedelta(hours=duration_hours)).isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO blocked_ips (ip_address, reason, blocked_at, blocked_until, permanent, attack_count)
                VALUES (?, ?, ?, ?, ?, 1)
                ON CONFLICT(ip_address) DO UPDATE SET
                    reason = excluded.reason,
                    blocked_at = excluded.blocked_at,
                    blocked_until = excluded.blocked_until,
                    permanent = excluded.permanent,
                    attack_count = blocked_ips.attack_count + 1
            """, (ip_address, reason, blocked_at, blocked_until, 1 if permanent else 0))
            conn.commit()
            
        return BlockedIPItem(
            ip_address=ip_address,
            reason=reason,
            blocked_at=blocked_at,
            blocked_until=blocked_until,
            permanent=permanent,
            attack_count=1
        )

    def unblock_ip(self, ip_address: str) -> bool:
        self._blocked_ips_cache.discard(ip_address)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip_address,))
            conn.commit()
            return cursor.rowcount > 0

    def is_ip_blocked(self, ip_address: str) -> bool:
        return ip_address in self._blocked_ips_cache

    def get_all_blocked_ips(self) -> List[BlockedIPItem]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC")
            rows = cursor.fetchall()
            return [
                BlockedIPItem(
                    ip_address=r["ip_address"],
                    reason=r["reason"],
                    blocked_at=r["blocked_at"],
                    blocked_until=r["blocked_until"],
                    permanent=bool(r["permanent"]),
                    attack_count=r["attack_count"]
                )
                for r in rows
            ]

    def log_traffic(self, client_ip: str, method: str, path: str, status_code: int, is_threat: bool, risk_score: float):
        if is_threat:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO traffic_logs (timestamp, client_ip, method, path, status_code, is_threat, risk_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (datetime.now(timezone.utc).isoformat(), client_ip, method, path, status_code, 1, risk_score))
                conn.commit()

    def get_threat_stats(self) -> Dict[str, int]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'blocked'")
            blocked_count = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('flagged', 'blocked')")
            total_threats = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM blocked_ips")
            blocked_ips_count = cursor.fetchone()[0]
            return {
                "blocked_today": blocked_count,
                "total_threats": total_threats,
                "blocked_ips_count": blocked_ips_count
            }

db = Database()
