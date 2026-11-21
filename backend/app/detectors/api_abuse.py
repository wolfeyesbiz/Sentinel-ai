import re
import json
from typing import Dict, Any, Optional

class APIAbuseDetector:
    def __init__(self):
        # Sensitive or prohibited endpoints for standard customers
        self.forbidden_probes = [
            r'/\.env', r'/\.git', r'/actuator', r'/wp-admin', r'/phpmyadmin',
            r'/api/v1/internal', r'/api/admin/users/export', r'/config\.json',
            r'/server-status', r'/debug/default/view', r'/telescope'
        ]
        self.forbidden_regexes = [re.compile(p, re.IGNORECASE) for p in self.forbidden_probes]

        # Parameter tampering patterns in JSON body
        self.role_tamper_patterns = [
            r'"role"\s*:\s*"(?:admin|root|superuser|manager)"',
            r'"is_admin"\s*:\s*true',
            r'"is_staff"\s*:\s*true',
            r'"privilege"\s*:\s*"all"'
        ]
        self.role_regexes = [re.compile(p, re.IGNORECASE) for p in self.role_tamper_patterns]

    def inspect(self, path: str, method: str, body: Optional[str] = None) -> Dict[str, Any]:
        matched = []
        risk_score = 0.0

        # 1. Probing restricted or unauthorized endpoints
        for rgx in self.forbidden_regexes:
            if rgx.search(path):
                matched.append(f"Probing unauthorized/sensitive path: {path}")
                risk_score = max(risk_score, 0.88)
                break

        # 2. Body inspection for parameter tampering
        if body:
            # Check privilege escalation tampering
            for r_rgx in self.role_regexes:
                if r_rgx.search(body):
                    matched.append("Privilege escalation parameter tampering detected (role=admin)")
                    risk_score = max(risk_score, 0.94)

            # Check price and quantity manipulation in checkout/cart endpoints
            if any(term in path.lower() for term in ["cart", "checkout", "order", "payment"]):
                # Look for negative quantity or suspicious price overrides
                if re.search(r'"quantity"\s*:\s*-\d+', body):
                    matched.append("Negative item quantity tampering detected")
                    risk_score = max(risk_score, 0.92)
                
                if re.search(r'"price"\s*:\s*(?:0|0\.00|-[\d.]+)', body):
                    matched.append("Zero/Negative price tampering detected in order payload")
                    risk_score = max(risk_score, 0.95)

        detected = risk_score >= 0.70
        return {
            "detected": detected,
            "risk_score": min(1.0, risk_score),
            "matched": matched,
            "path": path
        }

api_abuse_detector = APIAbuseDetector()
