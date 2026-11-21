import asyncio
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_dashboard_overview():
    response = client.get("/api/dashboard/overview")
    assert response.status_code == 200
    data = response.json()
    assert "system_status" in data
    assert "threat_level" in data
    assert "risk_score" in data
    assert "system_metrics" in data
    assert "cpu_usage" in data["system_metrics"]
    assert "ram_usage" in data["system_metrics"]
    print("✅ /api/dashboard/overview PASSED")

def test_alerts_endpoints():
    response = client.get("/api/alerts/recent?limit=10&severity=all")
    assert response.status_code == 200
    data = response.json()
    assert "alerts" in data
    assert isinstance(data["alerts"], list)
    
    if len(data["alerts"]) > 0:
        alert_id = data["alerts"][0]["id"]
        detail_resp = client.get(f"/api/alerts/{alert_id}")
        assert detail_resp.status_code == 200
        detail_data = detail_resp.json()
        assert "alert" in detail_data
        assert detail_data["alert"]["id"] == alert_id
        assert "remediation" in detail_data["alert"]
    print("✅ /api/alerts endpoints PASSED")

def test_security_block_unblock():
    test_ip = "192.0.2.111"
    # Block IP
    block_resp = client.post("/api/security/block-ip", json={
        "ip_address": test_ip,
        "duration_hours": 12,
        "reason": "Integration Test Block"
    })
    assert block_resp.status_code == 200
    assert block_resp.json()["success"] is True

    # Check blocked list
    list_resp = client.get("/api/security/blocked-ips")
    assert list_resp.status_code == 200
    blocked_ips = [item["ip_address"] for item in list_resp.json()]
    assert test_ip in blocked_ips

    # Unblock IP
    unblock_resp = client.post("/api/security/unblock-ip", json={"ip_address": test_ip})
    assert unblock_resp.status_code == 200
    assert unblock_resp.json()["success"] is True
    print("✅ /api/security IP block/unblock PASSED")

def test_traffic_inspect_endpoint():
    from app.storage.db import db
    db.unblock_ip("198.51.100.77")
    db.unblock_ip("10.0.0.99")
    
    # Send clean request
    clean_resp = client.post("/api/traffic/inspect", json={
        "method": "GET",
        "path": "/api/products",
        "client_ip": "10.0.0.99",
        "query_params": {"category": "laptops"}
    })
    assert clean_resp.status_code == 200
    assert clean_resp.json()["action_taken"] == "allowed"

    # Send malicious SQLi request
    malicious_resp = client.post("/api/traffic/inspect", json={
        "method": "POST",
        "path": "/api/products",
        "client_ip": "198.51.100.77",
        "body": "' OR 1=1; DROP TABLE users; --"
    })
    assert malicious_resp.status_code == 200
    data = malicious_resp.json()
    assert data["detected"] is True
    assert data["action_taken"] == "blocked"
    assert data["threat_type"] == "sql_injection"
    assert data["remediation"] is not None
    print("✅ /api/traffic/inspect WAF enforcement PASSED")

def test_attack_simulator():
    resp = client.post("/api/simulate-attack", json={
        "threat_type": "xss",
        "source_ip": "192.0.2.88",
        "target": "/api/reviews"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["threat_type"] == "xss"
    print("✅ /api/simulate-attack PASSED")

if __name__ == "__main__":
    print("\n--- RUNNING SENTINEL AI API INTEGRATION TESTS ---")
    test_dashboard_overview()
    test_alerts_endpoints()
    test_security_block_unblock()
    test_traffic_inspect_endpoint()
    test_attack_simulator()
    print("✅ ALL API INTEGRATION TESTS PASSED!\n")
