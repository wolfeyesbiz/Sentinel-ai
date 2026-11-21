import re
from typing import Dict, Any, List
from urllib.parse import unquote
from app.ml.isolation_forest import ml_anomaly_scorer

class XSSDetector:
    def __init__(self):
        self.xss_patterns = [
            r'<\s*script[^>]*>.*?<\s*/\s*script\s*>',
            r'<\s*script[^>]*>',
            r'javascript\s*:',
            r'vbscript\s*:',
            r'data\s*:\s*text\/html',
            r'on(?:error|load|click|mouseover|focus|blur|submit)\s*=',
            r'<\s*img[^>]+src[^>]+onerror\s*=',
            r'<\s*svg[^>]+onload\s*=',
            r'<\s*iframe[^>]*>',
            r'document\.(?:cookie|location|domain|write)',
            r'window\.(?:location|navigate)',
            r'eval\s*\(',
            r'setTimeout\s*\(\s*["\']',
            r'String\.fromCharCode\s*\(',
            r'alert\s*\(',
            r'prompt\s*\(',
            r'confirm\s*\('
        ]
        self.compiled_patterns = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.xss_patterns]

    def inspect(self, text: str) -> Dict[str, Any]:
        if not text:
            return {"detected": False, "risk_score": 0.0, "matched": []}

        decoded = unquote(unquote(text))
        matched = []

        for pat in self.compiled_patterns:
            if pat.search(decoded):
                matched.append(pat.pattern)

        has_xss = len(matched) > 0

        risk_score = ml_anomaly_scorer.calculate_risk_score(
            raw_text=decoded,
            param_count=len(matched),
            request_rate=1.0,
            has_xss=has_xss
        )

        if has_xss:
            risk_score = max(risk_score, 0.92)
            detected = True
        elif "<" in decoded and ">" in decoded:
            risk_score = max(risk_score, 0.55)
            detected = risk_score >= 0.70
        else:
            detected = False

        return {
            "detected": detected,
            "risk_score": min(1.0, risk_score),
            "matched": matched,
            "features": {
                "matched_patterns_count": len(matched),
                "payload_length": len(decoded)
            }
        }

xss_detector = XSSDetector()
