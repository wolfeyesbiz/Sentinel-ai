"""Website integrations: passive HTTPS checks and authenticated telemetry intake."""
import asyncio
import ipaddress
import re
import secrets
import socket
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlencode, urlparse, urlunparse

import httpx
from fastapi import APIRouter, File, Header, HTTPException, UploadFile
from pydantic import BaseModel, Field

from app.core.engine import threat_engine
from app.models.schemas import RequestInspectionPayload
from app.security.source_scanner import MAX_ARCHIVE_BYTES, scan_source_archive

router = APIRouter(prefix="/integrations", tags=["Website Integrations"])
integrations: dict[str, dict] = {}
last_assessment_at: dict[str, float] = {}
last_host_assessment_at: dict[str, float] = {}
last_code_scan_at: dict[str, float] = {}
MAX_RESPONSE_BYTES = 256_000
ASSESSMENT_INTERVAL_SECONDS = 30


class IntegrationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    url: str = Field(min_length=8, max_length=2048)


class RepositoryScanRequest(BaseModel):
    repository_url: str = Field(min_length=16, max_length=500)


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


def _assessment_target(item: dict, render_only: bool = False) -> tuple[str, str]:
    target = _validated_url(item["url"])
    parsed = urlparse(target)
    host = parsed.hostname or ""
    if render_only and not host.endswith(".onrender.com"):
        raise HTTPException(400, "Safe probe simulations are limited to registered *.onrender.com demo sites.")
    return target, host


def _begin_assessment(integration_id: str, render_only: bool = False) -> tuple[str, str]:
    item = integrations.get(integration_id)
    if not item:
        raise HTTPException(404, "Integration not found.")
    target, host = _assessment_target(item, render_only)
    now = time.monotonic()
    if now - last_assessment_at.get(integration_id, 0) < ASSESSMENT_INTERVAL_SECONDS or now - last_host_assessment_at.get(host, 0) < ASSESSMENT_INTERVAL_SECONDS:
        raise HTTPException(429, "This demo was assessed recently. Wait 30 seconds before running another assessment.")
    last_assessment_at[integration_id] = now
    last_host_assessment_at[host] = now
    return target, host


async def _get_root(client: httpx.AsyncClient, target: str, probe_value: str | None = None) -> dict:
    parsed = urlparse(target)
    url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))
    if probe_value is not None:
        url += ("&" if parsed.query else "?") + urlencode({"sentinel_probe": probe_value})
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
            "result": "probe_timed_out" if xss_response["error"] else ("potential_html_reflection" if reflected else "no_raw_reflection_observed"),
            "severity": "info" if xss_response["error"] else ("low" if reflected else "info"),
            "details": f"The website did not finish this request ({xss_response['error']})." if xss_response["error"] else ("A harmless custom HTML element was returned unescaped; review output encoding." if reflected else "The harmless HTML canary was not returned unescaped in the response."),
        },
        {
            "probe": "SQL error disclosure canary",
            "status_code": sql_response["status_code"],
            "latency_ms": sql_response["latency_ms"],
            "result": "probe_timed_out" if sql_response["error"] else ("database_error_signature" if db_error else ("server_error" if (sql_response["status_code"] or 0) >= 500 else "no_error_signature_observed")),
            "severity": "info" if sql_response["error"] else ("medium" if db_error or (sql_response["status_code"] or 0) >= 500 else "info"),
            "details": f"The website did not finish this request ({sql_response['error']})." if sql_response["error"] else (f"Response contained a database error signature ({db_error})." if db_error else ("The probe received a server error; review application logs." if (sql_response["status_code"] or 0) >= 500 else "No common database error signature appeared in the bounded response sample.")),
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
    last_code_scan_at.pop(integration_id, None)
    return {"success": True}


@router.post("/{integration_id}/check")
async def check_site(integration_id: str):
    item = integrations.get(integration_id)
    if not item:
        raise HTTPException(404, "Integration not found.")
    _validated_url(item["url"])
    started = datetime.now(timezone.utc)
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(12.0, connect=6.0), follow_redirects=False) as client:
            response = await client.get(item["url"], headers={"User-Agent": "SentinelAI-AvailabilityCheck/1.0"})
        item["http_status"] = response.status_code
        item["status"] = "online" if response.status_code < 500 else "degraded"
        item["latency_ms"] = round((datetime.now(timezone.utc) - started).total_seconds() * 1000)
    except httpx.TimeoutException:
        item["status"], item["http_status"] = "timed_out", None
        item["latency_ms"] = round((datetime.now(timezone.utc) - started).total_seconds() * 1000)
    except httpx.HTTPError:
        item["status"], item["http_status"], item["latency_ms"] = "unreachable", None, None
    item["checked_at"] = datetime.now(timezone.utc).isoformat()
    return {k: v for k, v in item.items() if k != "key"}


def _begin_code_scan(integration_id: str) -> dict:
    item = integrations.get(integration_id)
    if not item:
        raise HTTPException(404, "Integration not found.")
    now = time.monotonic()
    if now - last_code_scan_at.get(integration_id, 0) < 45:
        raise HTTPException(429, "This source was scanned recently. Wait 45 seconds before scanning it again.")
    last_code_scan_at[integration_id] = now
    return item


def _finish_code_scan(item: dict, result: dict) -> dict:
    if result["scanned_files"] == 0:
        raise HTTPException(400, "No supported source files were found in this archive.")
    result["integration_id"] = item["id"]
    result["checked_at"] = datetime.now(timezone.utc).isoformat()
    result["summary"] = "potential issues found" if result["finding_count"] else "no configured patterns matched"
    item["last_code_scan_at"] = result["checked_at"]
    item["last_code_scan_findings"] = result["finding_count"]
    return result


async def _download_github_zip(owner: str, repository: str) -> bytes:
    api_url = f"https://api.github.com/repos/{owner}/{repository}/zipball"
    headers = {"User-Agent": "SentinelAI-AuthorizedSourceReview/1.0", "Accept": "application/vnd.github+json"}
    async with httpx.AsyncClient(timeout=httpx.Timeout(25.0, connect=8.0), follow_redirects=False, headers=headers) as client:
        async with client.stream("GET", api_url) as response:
            if response.status_code in (301, 302, 303, 307, 308):
                redirect = response.headers.get("location", "")
                parsed_redirect = urlparse(redirect)
                if parsed_redirect.scheme != "https" or parsed_redirect.hostname != "codeload.github.com" or parsed_redirect.username or parsed_redirect.password or parsed_redirect.port not in (None, 443):
                    raise HTTPException(502, "GitHub returned an unexpected archive location.")
                archive_url = redirect
            elif response.status_code == 200:
                archive_url = ""
                chunks = bytearray()
                async for chunk in response.aiter_bytes():
                    chunks.extend(chunk)
                    if len(chunks) > MAX_ARCHIVE_BYTES:
                        raise HTTPException(413, "The repository archive is larger than the 12 MB source-review limit.")
                return bytes(chunks)
            elif response.status_code == 404:
                raise HTTPException(404, "Repository not found or not publicly accessible.")
            elif response.status_code == 403:
                raise HTTPException(429, "GitHub declined the download. Check its public access or try again later.")
            else:
                raise HTTPException(502, f"GitHub could not provide the source archive (HTTP {response.status_code}).")
        async with client.stream("GET", archive_url) as response:
            if response.status_code != 200:
                raise HTTPException(502, f"GitHub archive download failed (HTTP {response.status_code}).")
            chunks = bytearray()
            async for chunk in response.aiter_bytes():
                chunks.extend(chunk)
                if len(chunks) > MAX_ARCHIVE_BYTES:
                    raise HTTPException(413, "The repository archive is larger than the 12 MB source-review limit.")
            return bytes(chunks)


@router.post("/{integration_id}/source/github")
async def scan_github_source(integration_id: str, body: RepositoryScanRequest):
    item = _begin_code_scan(integration_id)
    parsed = urlparse(body.repository_url.strip())
    parts = [part for part in parsed.path.split("/") if part]
    if parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise HTTPException(400, "Enter a public HTTPS GitHub repository URL.")
    if len(parts) != 2 or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts):
        raise HTTPException(400, "Use a repository URL in the form https://github.com/owner/repository.")
    owner, repository = parts
    if repository.endswith(".git"):
        repository = repository[:-4]
    archive = await _download_github_zip(owner, repository)
    try:
        result = scan_source_archive(archive, f"github.com/{owner}/{repository}")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return _finish_code_scan(item, result)


@router.post("/{integration_id}/source/upload")
async def scan_uploaded_source(integration_id: str, file: UploadFile = File(...)):
    item = _begin_code_scan(integration_id)
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(400, "Upload a .zip source archive.")
    archive = await file.read(MAX_ARCHIVE_BYTES + 1)
    await file.close()
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise HTTPException(413, "The source archive is larger than the 12 MB source-review limit.")
    try:
        result = scan_source_archive(archive, file.filename[:120])
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return _finish_code_scan(item, result)


@router.post("/{integration_id}/scan")
async def scan_site(integration_id: str):
    target, host = _begin_assessment(integration_id)
    item = integrations[integration_id]
    async with httpx.AsyncClient(timeout=httpx.Timeout(12.0, connect=6.0), follow_redirects=False, max_redirects=0, headers={"User-Agent": "SentinelAI-SecurityReview/1.0 (passive checks)"}) as client:
        baseline = await _get_root(client, target)
        if baseline["error"]:
            raise HTTPException(502, f"The website could not be reached ({baseline['error']}). Check its URL and try again.")

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

        page = baseline["body"]
        content_type = headers.get("content-type", "").lower()
        server_banner = headers.get("server", "") + " " + headers.get("x-powered-by", "")
        if re.search(r"(?:apache|nginx|iis|php|express)[/ ]\d", server_banner, re.IGNORECASE):
            checks.append({"title": "Server version disclosure", "result": "version_banner_observed", "severity": "low", "details": "A response header appears to disclose a server or framework version. Review whether the version detail is needed publicly."})
        if "html" in content_type or "<html" in page[:1000].lower():
            if re.search(r"(?:src|poster)\s*=\s*['\"]http://|url\(\s*['\"]?http://", page, re.IGNORECASE):
                checks.append({"title": "Mixed HTTP content reference", "result": "potential_mixed_content", "severity": "low", "details": "The homepage contains an HTTP resource or link reference. Review whether any active page resources can be upgraded to HTTPS."})
            for form in re.findall(r"<form\b[^>]*>", page, re.IGNORECASE)[:40]:
                action = re.search(r"action\s*=\s*['\"]([^'\"]+)['\"]", form, re.IGNORECASE)
                if action and action.group(1).lower().startswith("http://"):
                    checks.append({"title": "Form submits over HTTP", "result": "insecure_form_action", "severity": "medium", "details": "A form on the homepage appears to submit to an unencrypted HTTP URL."})
                    break
            for script in re.findall(r"<script\b[^>]*\bsrc\s*=\s*['\"][^'\"]+['\"][^>]*>", page, re.IGNORECASE)[:30]:
                src = re.search(r"\bsrc\s*=\s*['\"]([^'\"]+)['\"]", script, re.IGNORECASE)
                if src and src.group(1).startswith("https://") and "integrity=" not in script.lower():
                    checks.append({"title": "External script without integrity attribute", "result": "review_external_script", "severity": "info", "details": "An external HTTPS script has no Subresource Integrity attribute. Review whether SRI is practical for this script."})
                    break

    probes = []

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
        "scope": "One bounded, read-only HTTPS GET to the registered page. Checks response headers, cookies and visible homepage markup; does not inspect server files, authenticate, submit forms, or prove the site secure.",
    }
    item["last_scan_at"] = report["checked_at"]
    item["last_scan_findings"] = findings
    return report


@router.post("/{integration_id}/simulate")
async def simulate_safe_probes(integration_id: str):
    target, _host = _begin_assessment(integration_id, render_only=True)
    item = integrations[integration_id]
    xss_marker = "snt" + secrets.token_hex(5)
    sql_marker = "snt" + secrets.token_hex(5)
    xss_value = f"<sentinel-probe>{xss_marker}</sentinel-probe>"
    async with httpx.AsyncClient(timeout=httpx.Timeout(12.0, connect=6.0), follow_redirects=False, max_redirects=0, headers={"User-Agent": "SentinelAI-SafeProbe/1.0"}) as client:
        baseline = await _get_root(client, target)
        xss_response, sql_response = await asyncio.gather(
            _get_root(client, target, xss_value),
            _get_root(client, target, sql_marker + "'"),
        )
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
