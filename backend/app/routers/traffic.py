from fastapi import APIRouter
from typing import List, Dict, Any
from app.models.schemas import RequestInspectionPayload, ThreatDetectionResult
from app.core.engine import threat_engine
from app.storage.memory_store import memory_store

router = APIRouter(prefix="/traffic", tags=["Store Traffic WAF"])

@router.post("/inspect", response_model=ThreatDetectionResult)
async def inspect_traffic(payload: RequestInspectionPayload):
    """
    Main WAF inspection endpoint. Online store reverse proxies, Nginx plugins, 
    or store middlewares send incoming HTTP requests here for immediate threat analysis.
    """
    return await threat_engine.inspect_request(payload)

@router.get("/recent")
async def get_recent_traffic():
    """Returns sliding window of recent traffic packets for the live dashboard stream."""
    return list(memory_store.recent_traffic)
