import math
from typing import Dict, Any, List
from datetime import datetime

class BaselineProfiler:
    """Tracks baseline behavior profiles for e-commerce endpoints and sessions."""
    
    def __init__(self):
        # Learned baselines for standard endpoints
        self.endpoint_baselines: Dict[str, Dict[str, float]] = {
            "/api/products": {"avg_len": 45, "std_len": 30, "expected_methods": ["GET"]},
            "/api/cart": {"avg_len": 120, "std_len": 60, "expected_methods": ["GET", "POST", "PUT"]},
            "/api/checkout": {"avg_len": 280, "std_len": 90, "expected_methods": ["POST"]},
            "/api/auth/login": {"avg_len": 95, "std_len": 40, "expected_methods": ["POST"]},
            "/api/reviews": {"avg_len": 220, "std_len": 150, "expected_methods": ["GET", "POST"]},
        }
        
        # Typical operating hours for merchant shoppers (weighted towards day/evening)
        self.peak_hours = set(range(7, 23))
        
        # Typical safe user-agents
        self.known_browsers = ["Chrome", "Firefox", "Safari", "Edge", "Mozilla"]

    def calculate_payload_zscore(self, endpoint: str, payload_len: int) -> float:
        baseline = self.endpoint_baselines.get(endpoint, {"avg_len": 150, "std_len": 100})
        mean = baseline["avg_len"]
        std = baseline["std_len"]
        z = (payload_len - mean) / max(1.0, std)
        return round(abs(z), 2)

    def calculate_entropy(self, text: str) -> float:
        """Calculates Shannon entropy to detect packed, obfuscated or shell payloads."""
        if not text:
            return 0.0
        entropy = 0.0
        text_len = len(text)
        counts: Dict[str, int] = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1
        for count in counts.values():
            p_x = count / text_len
            entropy += - p_x * math.log2(p_x)
        return round(entropy, 3)

    def analyze_session_behavior(self, session_id: str, client_ip: str, user_agent: str) -> Dict[str, Any]:
        hour = datetime.now().hour
        anomalies = []
        risk = 0.0

        # Check off-peak abnormal burst
        if hour not in self.peak_hours:
            risk += 0.15
            anomalies.append("off_peak_access")

        # Check user-agent
        if not user_agent or not any(b in user_agent for b in self.known_browsers):
            risk += 0.40
            anomalies.append("unusual_user_agent")

        return {
            "deviations": anomalies,
            "risk_contribution": min(1.0, risk)
        }

baseline_profiler = BaselineProfiler()
