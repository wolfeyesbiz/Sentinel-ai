"""Website integrations: passive HTTPS checks and authenticated telemetry intake."""
import ipaddress
import secrets
import socket
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from app.core.engine import threat_engine
from app.models.schemas import RequestInspectionPayload

router = APIRouter(prefix="/integrations", tags=["Website Integrations"])
integrations: dict[str, dict] = {}


class IntegrationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    url: str = Field(min_length=8, max_length=2048)


def _validated_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(400, "Enter a public HTTPS URL (credentials in URLs are not allowed).")
    if parsed.port not in (None, 443):
        raise HTTPException(400, "Only standard HTTPS port 443 is supported.")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)}
        if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
            raise HTTPException(400, "The URL must resolve only to public IP addresses.")
    except (socket.gaierror, ValueError):
        raise HTTPException(400, "The hostname could not be resolved to a public address.")
    return value.strip().rstrip("/")


@router.get("")
async def list_integrations():
    return [{k: v for k, v in item.items() if k != "key"} for item in integrations.values()]


@router.post("")
async def add_integration(body: IntegrationCreate):
    url = _validated_url(body.url)
    item = {"id": uuid.uuid4().hex[:12], "name": body.name.strip(), "url": url,
            "key": secrets.token_urlsafe(32), "status": "not_checked", "checked_at": None,
            "http_status": None, "latency_ms": None, "last_event_at": None,
            "event_count": 0, "threat_count": 0}
    integrations[item["id"]] = item
    return {k: v for k, v in item.items() if k != "key"} | {"integration_key": item["key"]}


@router.delete("/{integration_id}")
async def remove_integration(integration_id: str):
    if integrations.pop(integration_id, None) is None:
        raise HTTPException(404, "Integration not found.")
    return {"success": True}


@router.post("/{integration_id}/check")
async def check_site(integration_id: str):
    item = integrations.get(integration_id)
    if not item:
        raise HTTPException(404, "Integration not found.")
    _validated_url(item["url"])
    started = datetime.now(timezone.utc)
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
            response = await client.get(item["url"], headers={"User-Agent": "SentinelAI-AvailabilityCheck/1.0"})
        item["http_status"] = response.status_code
        item["status"] = "online" if response.status_code < 500 else "degraded"
        item["latency_ms"] = round((datetime.now(timezone.utc) - started).total_seconds() * 1000)
    except httpx.HTTPError:
        item["status"], item["http_status"], item["latency_ms"] = "unreachable", None, None
    item["checked_at"] = datetime.now(timezone.utc).isoformat()
    return {k: v for k, v in item.items() if k != "key"}


@router.post("/{integration_id}/events")
async def ingest_site_event(integration_id: str, payload: RequestInspectionPayload, authorization: str | None = Header(default=None)):
    item = integrations.get(integration_id)
    if not item:
        raise HTTPException(404, "Integration not found.")
    if not authorization or not secrets.compare_digest(authorization.removeprefix("Bearer "), item["key"]):
        raise HTTPException(401, "Invalid integration key.")
    result = await threat_engine.inspect_request(payload)
    item["event_count"] += 1
    item["last_event_at"] = datetime.now(timezone.utc).isoformat()
    if result.detected:
        item["threat_count"] += 1
    return {"accepted": True, "integration_id": integration_id, "detection": result.model_dump()}
