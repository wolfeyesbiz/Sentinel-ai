from typing import Dict, Any
from app.storage.memory_store import memory_store

class BruteForceDetector:
    def __init__(self, threshold_warning: int = 4, threshold_block: int = 8):
        self.threshold_warning = threshold_warning
        self.threshold_block = threshold_block

    def inspect(self, client_ip: str, path: str, username: str = "admin") -> Dict[str, Any]:
        # Only evaluate authentication and administrative login paths
        auth_paths = ["/api/auth/login", "/admin/login", "/auth/signin", "/api/checkout/login", "/login"]
        is_auth_route = any(p in path.lower() for p in auth_paths)
        
        if not is_auth_route:
            return {"detected": False, "risk_score": 0.0, "failed_attempts": 0}

        # Track failed attempts in memory store
        failed_count = memory_store.track_failed_login(client_ip, username)

        if failed_count >= self.threshold_block:
            risk_score = min(1.0, 0.70 + (failed_count - self.threshold_block) * 0.06)
            return {
                "detected": True,
                "risk_score": risk_score,
                "failed_attempts": failed_count,
                "action": "block_ip",
                "severity": "critical" if failed_count >= 10 else "warning",
                "message": f"Brute force credential stuffing detected: {failed_count} failed logins from {client_ip}"
            }
        elif failed_count >= self.threshold_warning:
            risk_score = min(0.68, 0.35 + (failed_count * 0.08))
            return {
                "detected": False,
                "risk_score": risk_score,
                "failed_attempts": failed_count,
                "action": "require_captcha",
                "severity": "warning",
                "message": f"Suspicious login velocity: {failed_count} failed attempts from {client_ip}"
            }
        
        return {
            "detected": False,
            "risk_score": 0.10,
            "failed_attempts": failed_count,
            "action": "allow"
        }

brute_force_detector = BruteForceDetector()
