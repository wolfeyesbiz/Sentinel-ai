import hashlib
from typing import Dict, Any, Optional
from app.storage.memory_store import memory_store

class SessionHijackingDetector:
    def __init__(self):
        pass

    def _generate_fingerprint(self, user_agent: str, ip: str) -> str:
        # Hashed fingerprint of user-agent and IP Class-C prefix
        ip_prefix = ".".join(ip.split(".")[:3]) if "." in ip else ip
        raw = f"{user_agent}|{ip_prefix}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def inspect(self, session_id: Optional[str], client_ip: str, user_agent: Optional[str]) -> Dict[str, Any]:
        if not session_id:
            return {"detected": False, "risk_score": 0.0}

        ua = user_agent or "Unknown"
        fingerprint = self._generate_fingerprint(ua, client_ip)

        session_record = memory_store.sessions.get(session_id)
        if not session_record:
            # First time seeing this session: register baseline
            memory_store.sessions[session_id] = {
                "initial_ip": client_ip,
                "initial_ua": ua,
                "initial_fingerprint": fingerprint,
                "request_count": 1
            }
            return {"detected": False, "risk_score": 0.05}

        # Check for discrepancies
        session_record["request_count"] += 1
        initial_ip = session_record["initial_ip"]
        initial_ua = session_record["initial_ua"]

        anomalies = []
        risk_score = 0.0

        if client_ip != initial_ip:
            # Check if subnet matches
            ip_sub1 = ".".join(client_ip.split(".")[:2])
            ip_sub2 = ".".join(initial_ip.split(".")[:2])
            if ip_sub1 != ip_sub2:
                anomalies.append(f"Significant IP jump from {initial_ip} to {client_ip}")
                risk_score += 0.55
            else:
                anomalies.append(f"Minor IP shift within subnet ({initial_ip} -> {client_ip})")
                risk_score += 0.20

        if ua != initial_ua:
            anomalies.append(f"Browser User-Agent switch mid-session: {initial_ua[:25]}... -> {ua[:25]}...")
            risk_score += 0.50

        detected = risk_score >= 0.70
        return {
            "detected": detected,
            "risk_score": min(1.0, risk_score),
            "anomalies": anomalies,
            "session_id": session_id,
            "initial_ip": initial_ip,
            "current_ip": client_ip
        }

session_hijack_detector = SessionHijackingDetector()
