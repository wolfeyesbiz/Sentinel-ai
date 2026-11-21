import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from app.config import settings
from app.models.schemas import (
    RequestInspectionPayload,
    ThreatDetectionResult,
    ThreatType,
    SeverityLevel,
    ThreatStatus,
    AlertItem
)
from app.storage.db import db
from app.storage.memory_store import memory_store
from app.alerts.alert_manager import alert_manager
from app.remediation.advisor import remediation_advisor

# Import all detectors
from app.detectors.sqli_detector import sqli_detector
from app.detectors.xss_detector import xss_detector
from app.detectors.brute_force import brute_force_detector
from app.detectors.ddos_detector import ddos_detector
from app.detectors.malware_detector import malware_detector
from app.detectors.session_hijack import session_hijack_detector
from app.detectors.api_abuse import api_abuse_detector
from app.detectors.bot_detector import bot_detector
from app.detectors.fraud_detector import payment_fraud_detector
from app.detectors.data_exfiltration import data_exfiltration_detector
from app.ml.isolation_forest import ml_anomaly_scorer

class ThreatDetectionEngine:
    def __init__(self):
        # Known Geo IP mapping table for demo & testing IPs
        self.geo_lookup_cache: Dict[str, str] = {
            "198.51.100.23": "Russia",
            "203.0.113.45": "China",
            "192.0.2.88": "Netherlands",
            "185.220.101.5": "Germany",
            "45.33.32.156": "United States",
            "103.251.167.22": "Vietnam",
            "127.0.0.1": "Localhost",
            "::1": "Localhost"
        }

    def resolve_country(self, ip: str) -> str:
        if ip in self.geo_lookup_cache:
            return self.geo_lookup_cache[ip]
        # Hash-based deterministic country mapping for other arbitrary IPs
        countries = ["United States", "Germany", "United Kingdom", "Russia", "China", "Brazil", "India", "France", "Netherlands"]
        idx = sum(ord(c) for c in ip) % len(countries)
        return countries[idx]

    async def inspect_request(self, payload: RequestInspectionPayload) -> ThreatDetectionResult:
        ip = payload.client_ip
        path = payload.path
        body = payload.body or ""
        params_str = "&".join(f"{k}={v}" for k, v in payload.query_params.items())
        combined_payload = f"{path}?{params_str} {body}"
        country = self.resolve_country(ip)

        # 1. Quick Check: Is IP already blocked in firewall/database?
        if db.is_ip_blocked(ip):
            result = ThreatDetectionResult(
                detected=True,
                threat_type=ThreatType.ANOMALY,
                severity=SeverityLevel.CRITICAL,
                risk_score=1.0,
                confidence=1.0,
                action_taken=ThreatStatus.BLOCKED,
                matched_patterns=["IP is on active Sentinel AI blacklist"],
                malicious_payload=payload.body[:100] if payload.body else None,
                attack_vector="Blacklisted Source IP",
                target_endpoint=path,
                source_ip=ip,
                country=country
            )
            # Log traffic
            db.log_traffic(ip, payload.method, path, 403, True, 1.0)
            return result

        # 2. Run All 10 Threat Detectors
        findings: List[Dict[str, Any]] = []

        # (1) SQL Injection
        sqli_res = sqli_detector.inspect(combined_payload)
        if sqli_res["detected"]:
            findings.append({
                "type": ThreatType.SQL_INJECTION,
                "risk": sqli_res["risk_score"],
                "patterns": sqli_res["matched"],
                "vector": "URL / Form / Header SQL manipulation",
                "desc": "SQL Injection attempt targeting database schema"
            })

        # (2) Cross-Site Scripting (XSS)
        xss_res = xss_detector.inspect(combined_payload)
        if xss_res["detected"]:
            findings.append({
                "type": ThreatType.XSS,
                "risk": xss_res["risk_score"],
                "patterns": xss_res["matched"],
                "vector": "Script injection via input parameter",
                "desc": "Cross-Site Scripting (XSS) script payload intercepted"
            })

        # (3) Brute Force
        bf_res = brute_force_detector.inspect(ip, path, payload.user_id or "admin")
        if bf_res["detected"]:
            findings.append({
                "type": ThreatType.BRUTE_FORCE,
                "risk": bf_res["risk_score"],
                "patterns": [f"failed_attempts: {bf_res['failed_attempts']}"],
                "vector": "High-velocity credential stuffing against auth route",
                "desc": bf_res["message"]
            })

        # (4) DDoS / Traffic Spike
        ddos_res = ddos_detector.inspect(ip, payload.headers)
        if ddos_res["detected"]:
            findings.append({
                "type": ThreatType.DDOS,
                "risk": ddos_res["risk_score"],
                "patterns": [ddos_res.get("attack_subclass", "volumetric_spike")],
                "vector": "Abnormal request rate / connection holding",
                "desc": ddos_res["message"]
            })

        # (5) Malware Upload
        if payload.file_name or payload.file_content_base64:
            mal_res = malware_detector.inspect(
                filename=payload.file_name,
                base64_str=payload.file_content_base64
            )
            if mal_res["detected"]:
                findings.append({
                    "type": ThreatType.MALWARE_UPLOAD,
                    "risk": mal_res["risk_score"],
                    "patterns": mal_res["reasons"],
                    "vector": "Executable web shell disguised in file upload",
                    "desc": f"Malware upload blocked: {payload.file_name}"
                })

        # (6) Session Hijacking
        if payload.session_id:
            sh_res = session_hijack_detector.inspect(payload.session_id, ip, payload.user_agent)
            if sh_res["detected"]:
                findings.append({
                    "type": ThreatType.SESSION_HIJACKING,
                    "risk": sh_res["risk_score"],
                    "patterns": sh_res["anomalies"],
                    "vector": "Session token reuse with fingerprint drift",
                    "desc": "Session Hijacking attempt intercepted"
                })

        # (7) API Abuse & Parameter Tampering
        api_res = api_abuse_detector.inspect(path, payload.method, body)
        if api_res["detected"]:
            findings.append({
                "type": ThreatType.API_ABUSE,
                "risk": api_res["risk_score"],
                "patterns": api_res["matched"],
                "vector": "Unauthorized endpoint probing or parameter tampering",
                "desc": "API Abuse / Forbidden route inspection"
            })

        # (8) Bot Attacks
        bot_res = bot_detector.inspect(payload.user_agent, payload.headers, path)
        if bot_res["detected"]:
            findings.append({
                "type": ThreatType.BOT_ATTACK,
                "risk": bot_res["risk_score"],
                "patterns": bot_res["matched"],
                "vector": "Automated scraping or inventory hoarding",
                "desc": "Automated bot activity intercepted"
            })

        # (9) Payment Fraud
        pf_res = payment_fraud_detector.inspect(ip, path, body)
        if pf_res["detected"]:
            findings.append({
                "type": ThreatType.PAYMENT_FRAUD,
                "risk": pf_res["risk_score"],
                "patterns": pf_res["anomalies"],
                "vector": "Rapid card testing velocity or micro-transaction authorization",
                "desc": "Carding / Payment fraud attempt prevented"
            })

        # (10) Data Exfiltration
        de_res = data_exfiltration_detector.inspect(path, payload.query_params, body)
        if de_res["detected"]:
            findings.append({
                "type": ThreatType.DATA_EXFILTRATION,
                "risk": de_res["risk_score"],
                "patterns": de_res["matched"],
                "vector": "Massive bulk database dump / sensitive export request",
                "desc": "Data exfiltration attempt intercepted"
            })

        # (11) Machine Learning Isolation Forest Baseline Check
        ml_score = ml_anomaly_scorer.calculate_risk_score(
            raw_text=combined_payload,
            param_count=len(payload.query_params) + (1 if body else 0),
            request_rate=1.0,
            has_sql=sqli_res["detected"],
            has_xss=xss_res["detected"]
        )
        if ml_score >= settings.ANOMALY_THRESHOLD and not findings:
            findings.append({
                "type": ThreatType.ANOMALY,
                "risk": ml_score,
                "patterns": ["ML Isolation Forest statistical outlier detection"],
                "vector": "Behavioral baseline deviation",
                "desc": "Behavioral anomaly detected by Machine Learning model"
            })

        # 3. Decision Logic & Severity Assignment
        if findings:
            # Sort findings by risk score descending
            findings.sort(key=lambda x: x["risk"], reverse=True)
            top = findings[0]
            max_risk = top["risk"]
            threat_type = top["type"]
            attack_vector = top["vector"]
            matched_patterns = top["patterns"]
            description = top["desc"]

            # Severity calculation
            if max_risk >= 0.95 or threat_type in (ThreatType.MALWARE_UPLOAD, ThreatType.DATA_EXFILTRATION):
                severity = SeverityLevel.EMERGENCY
            elif max_risk >= 0.80 or threat_type in (ThreatType.SQL_INJECTION, ThreatType.PAYMENT_FRAUD):
                severity = SeverityLevel.CRITICAL
            elif max_risk >= 0.65:
                severity = SeverityLevel.WARNING
            else:
                severity = SeverityLevel.INFO

            # Action determination
            if max_risk >= settings.ANOMALY_THRESHOLD:
                action = ThreatStatus.BLOCKED
                # Auto-block IP in firewall
                db.block_ip(ip, reason=f"{threat_type.value.upper()}: {description}", duration_hours=settings.AUTO_BLOCK_DURATION_HOURS)
            else:
                action = ThreatStatus.FLAGGED

            # Generate Contextual Remediation Guidance
            snippet = body[:120] if body else (params_str[:120] if params_str else path)
            remediation = remediation_advisor.generate_contextual_remediation(
                threat_type=threat_type.value,
                source_ip=ip,
                target_endpoint=path,
                payload=snippet
            )

            # Create Alert Item
            alert = AlertItem(
                id=f"alert_{uuid.uuid4().hex[:8]}",
                timestamp=datetime.now(timezone.utc).isoformat(),
                severity=severity,
                threat_type=threat_type,
                source_ip=ip,
                country=country,
                target=path,
                status=action,
                risk_score=max_risk,
                description=description,
                payload=snippet,
                attack_vector=attack_vector,
                details={"matched_patterns": matched_patterns, "headers": payload.headers},
                remediation=remediation
            )

            # Persist and dispatch alert
            db.insert_alert(alert)
            memory_store.record_alert(alert.model_dump())
            await alert_manager.dispatch_alert(alert)

            # Log traffic with threat flag
            db.log_traffic(ip, payload.method, path, 403 if action == ThreatStatus.BLOCKED else 200, True, max_risk)

            # Record packet for live stream
            memory_store.record_traffic({
                "id": str(uuid.uuid4())[:8],
                "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "ip": ip,
                "country": country,
                "method": payload.method,
                "path": path,
                "status": 403 if action == ThreatStatus.BLOCKED else 200,
                "action": action.value,
                "threat_type": threat_type.value,
                "risk_score": max_risk
            })

            return ThreatDetectionResult(
                detected=True,
                threat_type=threat_type,
                severity=severity,
                risk_score=max_risk,
                confidence=0.98,
                action_taken=action,
                matched_patterns=matched_patterns,
                malicious_payload=snippet,
                attack_vector=attack_vector,
                target_endpoint=path,
                source_ip=ip,
                country=country,
                remediation=remediation
            )

        # 4. Clean Normal Traffic
        db.log_traffic(ip, payload.method, path, 200, False, ml_score)
        
        # Record packet in memory
        memory_store.record_traffic({
            "id": str(uuid.uuid4())[:8],
            "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "ip": ip,
            "country": country,
            "method": payload.method,
            "path": path,
            "status": 200,
            "action": "allowed",
            "threat_type": "normal",
            "risk_score": ml_score
        })

        return ThreatDetectionResult(
            detected=False,
            threat_type=ThreatType.NORMAL,
            severity=SeverityLevel.INFO,
            risk_score=ml_score,
            confidence=0.99,
            action_taken=ThreatStatus.ALLOWED,
            matched_patterns=[],
            malicious_payload=None,
            attack_vector=None,
            target_endpoint=path,
            source_ip=ip,
            country=country,
            remediation=None
        )

threat_engine = ThreatDetectionEngine()
