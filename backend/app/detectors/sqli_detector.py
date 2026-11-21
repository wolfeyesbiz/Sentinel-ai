import re
from typing import Dict, Any, List, Optional
from urllib.parse import unquote
from app.ml.isolation_forest import ml_anomaly_scorer

class SQLInjectionDetector:
    def __init__(self):
        # SQL Keywords
        self.sql_keywords = [
            r'\bSELECT\b', r'\bUNION\b', r'\bINSERT\b', r'\bUPDATE\b',
            r'\bDELETE\b', r'\bDROP\b', r'\bTRUNCATE\b', r'\bALTER\b',
            r'\bEXEC\b', r'\bEXECUTE\b', r'\bXP_CMDSHELL\b', r'\bWAITFOR\b',
            r'\bBENCHMARK\b', r'\bSLEEP\b', r'\bINFORMATION_SCHEMA\b',
            r'\bCONCAT\b', r'\bCAST\b', r'\bCONVERT\b', r'\bDATABASE\b',
            r'\bUSER\b', r'\bSCHEMA\b', r'\bLOAD_FILE\b', r'\bINTO\s+OUTFILE\b'
        ]
        
        # SQL Operators and comment markers
        self.sql_operators = [
            r'--', r'/\*.*?\*/', r';', r'\bOR\b\s+[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+',
            r'\bAND\b\s+[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+',
            r'\'\s*OR\s*\'', r'\"\s*OR\s*\"', r'\'\s*=\s*\'', r'\"\s*=\s*\"',
            r'\bUNION\s+(?:ALL\s+)?SELECT\b', r'\b1\s*=\s*1\b', r'\b1\s*=\s*2\b'
        ]
        
        # Compiled regexes (case-insensitive)
        self.kw_patterns = [re.compile(kw, re.IGNORECASE) for kw in self.sql_keywords]
        self.op_patterns = [re.compile(op, re.IGNORECASE) for op in self.sql_operators]
        self.suspicious_chars_regex = re.compile(r"['\"\\;`#]")

    def inspect(self, text: str) -> Dict[str, Any]:
        if not text:
            return {"detected": False, "risk_score": 0.0, "matched": []}
            
        decoded = unquote(unquote(text))
        matched = []

        # Check keywords
        kw_count = 0
        for kw_pat in self.kw_patterns:
            if kw_pat.search(decoded):
                kw_count += 1
                matched.append(kw_pat.pattern)

        # Check operators
        op_count = 0
        for op_pat in self.op_patterns:
            if op_pat.search(decoded):
                op_count += 1
                matched.append(op_pat.pattern)

        # Check suspicious chars
        suspicious_chars = self.suspicious_chars_regex.findall(decoded)
        char_count = len(suspicious_chars)

        has_sql = (kw_count >= 1 and op_count >= 1) or (op_count >= 2) or (kw_count >= 2)

        # ML Risk Score integration
        risk_score = ml_anomaly_scorer.calculate_risk_score(
            raw_text=decoded,
            param_count=max(1, kw_count + op_count),
            request_rate=1.0,
            has_sql=has_sql
        )

        # If explicit SQL injection signatures match, calibrate risk score
        if has_sql or (op_count >= 1 and any(q in decoded for q in ["'", "--", "/*", ";"])):
            risk_score = max(risk_score, 0.94)
            detected = True
        elif kw_count >= 1 and op_count >= 1:
            risk_score = max(risk_score, 0.85)
            detected = True
        else:
            detected = False
            risk_score = min(0.35, risk_score)

        return {
            "detected": detected,
            "risk_score": min(1.0, risk_score),
            "matched": matched,
            "features": {
                "keywords_count": kw_count,
                "operators_count": op_count,
                "suspicious_chars_count": char_count,
                "payload_length": len(decoded)
            }
        }

sqli_detector = SQLInjectionDetector()
