from fastapi import APIRouter
from app.storage.memory_store import memory_store
from app.storage.db import db
from datetime import datetime, timezone

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/overview")
async def get_dashboard_overview():
    metrics = memory_store.get_live_metrics()
    stats = db.get_threat_stats()
    
    # Calculate combined blocked count (DB + memory)
    blocked_count = max(stats.get("blocked_today", 0), metrics.get("blocked_today", 0))

    return {
        "system_status": metrics["system_status"].lower(),
        "threat_level": metrics["threat_level"].lower(),
        "active_threats": metrics["active_threats"],
        "blocked_today": blocked_count,
        "risk_score": metrics["risk_score"],
        "system_metrics": {
            "cpu_usage": metrics["cpu_usage"],
            "ram_usage": metrics["ram_usage"],
            "network_io": metrics["network_io"],
            "active_processes": metrics["active_processes"]
        },
        "total_requests_processed": memory_store.total_requests_processed
    }

@router.get("/metrics/history")
async def get_metrics_history():
    return list(memory_store.metrics_history)
