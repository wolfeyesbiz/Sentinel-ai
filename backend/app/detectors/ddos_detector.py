from typing import Dict, Any
from app.storage.memory_store import memory_store

class DDoSDetector:
    def __init__(self, spike_threshold: int = 30, slowloris_threshold_sec: float = 8.0):
        self.spike_threshold = spike_threshold
        self.slowloris_threshold_sec = slowloris_threshold_sec

    def inspect(self, client_ip: str, headers: Dict[str, str], duration_seconds: float = 0.05) -> Dict[str, Any]:
        # Track velocity per second
        req_rate = memory_store.track_request_rate(client_ip)

        # 1. Volumetric Flood / Traffic Spike Detection
        if req_rate > self.spike_threshold:
            risk_score = min(1.0, 0.75 + (req_rate - self.spike_threshold) * 0.015)
            return {
                "detected": True,
                "risk_score": risk_score,
                "attack_subclass": "volumetric_flood",
                "request_rate": req_rate,
                "message": f"DDoS volumetric flood spike detected ({req_rate} req/s from {client_ip})"
            }

        # 2. Slowloris detection (slow headers, missing final CRLF, holding connection open)
        if duration_seconds > self.slowloris_threshold_sec:
            return {
                "detected": True,
                "risk_score": 0.88,
                "attack_subclass": "slowloris",
                "duration": duration_seconds,
                "message": f"Slowloris connection starvation attempt from {client_ip} ({duration_seconds}s latency)"
            }

        return {
            "detected": False,
            "risk_score": min(0.3, req_rate * 0.01),
            "request_rate": req_rate
        }

ddos_detector = DDoSDetector()
