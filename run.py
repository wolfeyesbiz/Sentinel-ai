import uvicorn
import os
import sys

def main():
    print("""
    ========================================================================
     🛡️  SENTINEL AI - E-COMMERCE SECURITY MONITORING SYSTEM
    ========================================================================
     [✓] Real-Time Threat Detection Engine (10 Attack Classes)
     [✓] Machine Learning Isolation Forest Anomaly Detection
     [✓] Automated Remediation Guidance & Code Generation
     [✓] Dynamic Edge WAF & IP Firewall
     [✓] Sub-second WebSocket Telemetry & Audio Chimes
    ========================================================================
     🚀 Dashboard URL:     http://localhost:8000
     📖 API Documentation: http://localhost:8000/docs
     📡 WebSocket Stream:  ws://localhost:8000/ws/stream
    ========================================================================
    """)
    backend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend")
    sys.path.insert(0, backend_dir)
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=False)

if __name__ == "__main__":
    main()
