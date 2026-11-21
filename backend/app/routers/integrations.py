"""Website integrations: passive HTTPS checks and authenticated telemetry intake."""
import ipaddress
import secrets
import socket
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlencode, urlparse

import httpx
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from app.core.engine import threat_engine
from app.models.schemas import RequestInspectionPayload

router = APIRouter(prefix="/integrations", tags=["Website Integrations"])
integrations: dict[str, dict] = {}
last_assessment_at: dict[str, float] = {}
last_host_assessment_at: dict[str, float] = {}
MAX_RESPONSE_BYTES = 256_000
ASSESSMENT_INTERVAL_SECONDS = 30


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


def _assessment_host(item: dict) -> str:
    host = urlparse(item["url"]).hostname or ""
    if not host.endswith(".onrender.com"):
        raise HTTPException(400, "Security assessments are limited to registered *.onrender.com demo sites.")
    _validated_url(item["url"])
    return host


def _begin_assessment(integration_id: str) -> str:
    item = integrations.get(integration_id)
    if not item:
        raise HTTPException(404, "Integration not found.")
    host = _assessment_host(item)
    now = time.monotonic()
    if now - last_assessment_at.get(integration_id, 0) < ASSESSMENT_INTERVAL_SECONDS or now - last_host_assessment_at.get(host, 0) < ASSESSMENT_INTERVAL_SECONDS:
        raise HTTPException(429, "This demo was assessed recently. Wait 30 seconds before running another assessment.")
    last_assessment_at[integration_id] = now
    last_host_assessment_at[host] = now
    return host


async def _get_root(client: httpx.AsyncClient, host: str, probe_value: str | None = None) -> dict:
    url = f"https://{host}/"
    if probe_value is not None:
        url += "?" + urlencode({"sentinel_probe": probe_value})
    started = time.monotonic()
    try:
        async with client.stream("GET", url) as response:
            body = bytearray()
            async for chunk in response.aiter_bytes():
                remaining = MAX_RESPONSE_BYTES - len(body)
                if remaining <= 0:
                    break
                body.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    break
            return {
                "status_code": response.status_code,
                "headers": response.headers,
                "body": body.decode("utf-8", errors="replace"),
                "latency_ms": round((time.monotonic() - started) * 1000),
                "error": None,
            }
    except httpx.HTTPError as exc:
        return {"status_code": None, "headers": {}, "body": "", "latency_ms": round((time.monotonic() - started) * 1000), "error": type(exc).__name__}


def _run_safe_probes(baseline_body: str, xss_marker: str, xss_response: dict, sql_response: dict) -> list[dict]:
    xss_value = f"<sentinel-probe>{xss_marker}</sentinel-probe>"
    reflected = xss_value in xss_response["body"]
    sql_errors = ("sql syntax", "sqlite error", "mysql", "postgresql", "sqlstate", "odbc", "unterminated string", "database error")
    sql_body = sql_response["body"].lower()
    db_error = next((signature for signature in sql_errors if signature in sql_body and signature not in baseline_body.lower()), None)

    return [
        {
            "probe": "HTML reflection canary",
            "status_code": xss_response["status_code"],
            "latency_ms": xss_response["latency_ms"],
            "result": "potential_html_reflection" if reflected else "no_raw_reflection_observed",
            "severity": "low" if reflected else "info",
            "details": "A harmless custom HTML element was returned unescaped; review output encoding." if reflected else "The harmless HTML canary was not returned unescaped in the response.",
        },
        {
            "probe": "SQL error disclosure canary",
            "status_code": sql_response["status_code"],
            "latency_ms": sql_response["latency_ms"],
            "result": "database_error_signature" if db_error else ("server_error" if (sql_response["status_code"] or 0) >= 500 else "no_error_signature_observed"),
            "severity": "medium" if db_error or (sql_response["status_code"] or 0) >= 500 else "info",
            "details": f"Response contained a database error signature ({db_error})." if db_error else ("The probe received a server error; review application logs." if (sql_response["status_code"] or 0) >= 500 else "No common database error signature appeared in the bounded response sample."),
        },
    ]


@router.get("")
async def list_integrations():
    return [{k: v for k, v in item.items() if k != "key"} for item in integrations.values()]


@router.post("")
async def add_integration(body: IntegrationCreate):
    url = _validated_url(body.url)
    item = {"id": uuid.uuid4().hex[:12], "name": body.name.strip(), "url": url,
            "key": secrets.token_urlsafe(32), "status": "not_checked", "checked_at": None,
            "http_status": None, "latency_ms": None, "last_event_at": None,
            "event_count": 0, "threat_count": 0, "last_scan_at": None,
            "last_scan_findings": None, "last_simulation_at": None}
    integrations[item["id"]] = item
    return {k: v for k, v in item.items() if k != "key"} | {"integration_key": item["key"]}


@router.delete("/{integration_id}")
async def remove_integration(integration_id: str):
    if integrations.pop(integration_id, None) is None:
        raise HTTPException(404, "Integration not found.")
    last_assessment_at.pop(integration_id, None)
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


@router.post("/{integration_id}/scan")
async def scan_site(integration_id: str):
    host = _begin_assessment(integration_id)
    item = integrations[integration_id]
    async with httpx.AsyncClient(timeout=8, follow_redirects=False, max_redirects=0, headers={"User-Agent": "SentinelAI-SafeAssessment/1.0"}) as client:
        baseline = await _get_root(client, host)
        if baseline["error"]:
            raise HTTPException(502, f"The demo site could not be reached ({baseline['error']}).")

        headers = baseline["headers"]
        checks = []
        csp = headers.get("content-security-policy", "")
        header_checks = [
            ("Content-Security-Policy", bool(csp), "Helps limit script and resource injection."),
            ("Strict-Transport-Security", bool(headers.get("strict-transport-security")), "Keeps browsers on HTTPS after the first secure visit."),
            ("X-Content-Type-Options", headers.get("x-content-type-options", "").lower() == "nosniff", "Prevents MIME type sniffing."),
            ("Frame protection", "frame-ancestors" in csp.lower() or headers.get("x-frame-options", "").lower() in ("deny", "sameorigin"), "Helps protect against clickjacking."),
            ("Referrer-Policy", bool(headers.get("referrer-policy")), "Controls referrer information sent to other sites."),
            ("Permissions-Policy", bool(headers.get("permissions-policy")), "Restricts browser features the page can use."),
        ]
        for title, present, explanation in header_checks:
            checks.append({"title": title, "result": "present" if present else "missing", "severity": "info" if present else "low", "details": explanation if present else f"{title} was not present on the root response. Consider configuring it if appropriate for this site."})

        cookies = headers.get_list("set-cookie") if hasattr(headers, "get_list") else []
        for cookie in cookies:
            lower_cookie = cookie.lower()
            missing = [flag for flag in ("secure", "httponly", "samesite") if flag not in lower_cookie]
            if missing:
                checks.append({"title": "Cookie attributes", "result": "review", "severity": "low", "details": f"A cookie response is missing: {', '.join(missing)}. Review whether those attributes are appropriate."})

        xss_marker = "snt" + secrets.token_hex(5)
        sql_marker = "snt" + secrets.token_hex(5)
        xss_value = f"<sentinel-probe>{xss_marker}</sentinel-probe>"
        xss_response = await _get_root(client, host, xss_value)
        sql_response = await _get_root(client, host, sql_marker + "'")
        probes = _run_safe_probes(baseline["body"], xss_marker, xss_response, sql_response)

    for probe in probes:
        if probe["severity"] in ("low", "medium") and probe["result"] not in ("no_raw_reflection_observed", "no_error_signature_observed"):
            checks.append({"title": probe["probe"], "result": probe["result"], "severity": probe["severity"], "details": probe["details"]})

    findings = sum(1 for check in checks if check["severity"] in ("low", "medium", "high"))
    report = {
        "integration_id": integration_id,
        "site": item["url"],
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "http_status": baseline["status_code"],
        "latency_ms": baseline["latency_ms"],
        "summary": "potential findings" if findings else "no issues observed by these checks",
        "finding_count": findings,
        "checks": checks,
        "probes": probes,
        "scope": "Limited root-page HTTPS header checks and two harmless GET canaries. This is not a full vulnerability assessment.",
    }
    item["last_scan_at"] = report["checked_at"]
    item["last_scan_findings"] = findings
    return report


@router.post("/{integration_id}/simulate")
async def simulate_safe_probes(integration_id: str):
    host = _begin_assessment(integration_id)
    item = integrations[integration_id]
    xss_marker = "snt" + secrets.token_hex(5)
    sql_marker = "snt" + secrets.token_hex(5)
    xss_value = f"<sentinel-probe>{xss_marker}</sentinel-probe>"
    async with httpx.AsyncClient(timeout=8, follow_redirects=False, max_redirects=0, headers={"User-Agent": "SentinelAI-SafeProbe/1.0"}) as client:
        baseline = await _get_root(client, host)
        xss_response = await _get_root(client, host, xss_value)
        sql_response = await _get_root(client, host, sql_marker + "'")
    if baseline["error"]:
        raise HTTPException(502, f"The demo site could not be reached ({baseline['error']}).")
    probes = _run_safe_probes(baseline["body"], xss_marker, xss_response, sql_response)
    item["last_simulation_at"] = datetime.now(timezone.utc).isoformat()
    return {
        "integration_id": integration_id,
        "site": item["url"],
        "simulated_at": item["last_simulation_at"],
        "requests_sent": 3,
        "probes": probes,
        "scope": "Three GET requests to the site's root only: baseline, inert HTML canary, and quote-only SQL error canary. No login attempts, writes, uploads, or load generation.",
    }


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
