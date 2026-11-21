from fastapi import APIRouter, HTTPException, Query
from typing import Optional, List
from app.storage.db import db
from app.storage.memory_store import memory_store

router = APIRouter(prefix="/alerts", tags=["Alerts"])

@router.get("/recent")
async def get_recent_alerts(
    limit: int = Query(50, ge=1, le=200),
    severity: str = Query("all")
):
    alerts = db.get_recent_alerts(limit=limit, severity=severity)
    return {"alerts": alerts, "total": len(alerts)}

@router.get("/{alert_id}")
async def get_threat_detail(alert_id: str):
    alert = db.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert with ID '{alert_id}' not found.")
    return {"alert": alert}

@router.post("/{alert_id}/resolve")
async def resolve_alert(alert_id: str):
    alert = db.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    # Update status to resolved
    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE alerts SET status = 'resolved' WHERE id = ?", (alert_id,))
        conn.commit()
    return {"success": True, "alert_id": alert_id, "status": "resolved"}

@router.post("/clear")
async def clear_alerts():
    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM alerts")
        conn.commit()
    memory_store.recent_alerts.clear()
    return {"success": True, "message": "All security alert records cleared."}
