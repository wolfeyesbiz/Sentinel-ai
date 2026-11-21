import re
from typing import Dict, Any, Optional

class DataExfiltrationDetector:
    def __init__(self):
        # Exfiltration query parameters and paths
        self.bulk_export_patterns = [
            r'limit=(?:[5-9]\d{4}|\d{6,})',  # limit >= 50,000
            r'export=(?:all|database|users|orders|customers|full)',
            r'action=(?:dump|backup|download_all)',
            r'format=(?:sql|csv_dump)'
        ]
        self.bulk_regexes = [re.compile(p, re.IGNORECASE) for p in self.bulk_export_patterns]

        self.sensitive_dump_endpoints = [
            "/api/users/dump", "/api/customers/export-all", "/api/admin/db/export",
            "/api/orders/bulk-download", "/api/backup/download"
        ]

    def inspect(self, path: str, query_params: Dict[str, str], body: Optional[str] = None) -> Dict[str, Any]:
        matched = []
        risk_score = 0.0

        # Check endpoints
        lower_path = path.lower()
        for ep in self.sensitive_dump_endpoints:
            if ep in lower_path:
                matched.append(f"Direct request to sensitive bulk dump endpoint: {path}")
                risk_score = 0.96
                break

        # Check query parameters for massive limit or dump directives
        for k, v in query_params.items():
            combined = f"{k}={v}"
            for rgx in self.bulk_regexes:
                if rgx.search(combined):
                    matched.append(f"Unbounded data exfiltration parameter: {combined}")
                    risk_score = max(risk_score, 0.92)

        # Check body for massive extraction commands
        if body and len(body) > 20000:
            matched.append(f"Anomalously large outbound/inbound payload ({len(body)} bytes)")
            risk_score = max(risk_score, 0.78)

        detected = risk_score >= 0.70
        return {
            "detected": detected,
            "risk_score": min(1.0, risk_score),
            "matched": matched,
            "path": path
        }

data_exfiltration_detector = DataExfiltrationDetector()
