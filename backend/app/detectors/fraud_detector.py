import re
import time
from typing import Dict, Any, Optional
from collections import deque

class PaymentFraudDetector:
    def __init__(self):
        # Track card authorization attempts per IP: ip -> deque of timestamps
        self.payment_velocity: Dict[str, deque] = {}
        # Track card testing numbers per IP: ip -> set of card hashes
        self.cards_per_ip: Dict[str, deque] = {}

    def inspect(self, client_ip: str, path: str, body: Optional[str] = None) -> Dict[str, Any]:
        is_checkout = any(t in path.lower() for t in ["checkout", "payment", "charge", "pay", "stripe", "authorize"])
        if not is_checkout:
            return {"detected": False, "risk_score": 0.0}

        now = time.time()
        if client_ip not in self.payment_velocity:
            self.payment_velocity[client_ip] = deque(maxlen=50)
            self.cards_per_ip[client_ip] = deque(maxlen=50)

        velocity_queue = self.payment_velocity[client_ip]
        velocity_queue.append(now)
        # Purge items older than 3 minutes (180s)
        while velocity_queue and (now - velocity_queue[0] > 180):
            velocity_queue.popleft()

        attempts_in_3min = len(velocity_queue)
        anomalies = []
        risk_score = 0.0

        # High velocity card testing
        if attempts_in_3min >= 5:
            anomalies.append(f"High-velocity card checkout testing: {attempts_in_3min} attempts in 3 minutes")
            risk_score = min(1.0, 0.72 + (attempts_in_3min - 5) * 0.06)

        # Inspect body for suspicious carding payloads
        if body:
            # Check for micro-transaction amount in payment payload
            if re.search(r'"amount"\s*:\s*(?:0\.5|1\.0|0\.99|1)', body):
                anomalies.append("Card validation micro-transaction pattern ($1 or less testing charge)")
                risk_score = max(risk_score, 0.85)

            # Check for card test numbers
            if re.search(r'"card_number"\s*:\s*"4[0-9]{15}"', body):
                self.cards_per_ip[client_ip].append(now)
                if len(self.cards_per_ip[client_ip]) >= 3:
                    anomalies.append("Multiple distinct credit cards tested from single IP within short window")
                    risk_score = max(risk_score, 0.94)

        detected = risk_score >= 0.70
        return {
            "detected": detected,
            "risk_score": min(1.0, risk_score),
            "anomalies": anomalies,
            "attempts_in_window": attempts_in_3min
        }

payment_fraud_detector = PaymentFraudDetector()
