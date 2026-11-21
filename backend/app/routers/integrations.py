"""Website integrations: passive HTTPS checks and authenticated telemetry intake."""
import asyncio
import ipaddress
import re
import secrets
import socket
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlencode, urljoin, urlparse, urlunparse

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
REDIRECT_CODES = (301, 302, 303, 307, 308)
HEADER_FIXES = {
    "Content-Security-Policy": ("medium", "Limits where scripts and resources can load from, which helps reduce XSS impact.", "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'"),
    "Strict-Transport-Security": ("medium", "Tells browsers to keep using HTTPS after a secure visit.", "Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    "X-Content-Type-Options": ("low", "Stops browsers from guessing file types, which can make uploaded content safer.", "X-Content-Type-Options: nosniff"),
    "Frame protection": ("medium", "Prevents other sites from embedding the page in a frame (clickjacking).", "Content-Security-Policy: frame-ancestors 'self'  (or)  X-Frame-Options: DENY"),
    "Referrer-Policy": ("low", "Limits referrer details sent to other sites.", "Referrer-Policy: strict-origin-when-cross-origin"),
    "Permissions-Policy": ("low", "Restricts browser features that the site does not need.", "Permissions-Policy: camera=(), microphone=(), geolocation=()"),
}


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


async def _assessment_target(item: dict, render_only: bool = False) -> tuple[str, str]:
    target = await asyncio.to_thread(_validated_url, item["url"])
    parsed = urlparse(target)
    host = parsed.hostname or ""
    if render_only and not host.endswith(".onrender.com"):
        raise HTTPException(400, "Safe probe simulations are limited to registered *.onrender.com demo sites.")
    return target, host


async def _begin_assessment(integration_id: str, render_only: bool = False) -> tuple[str, str]:
    item = integrations.get(integration_id)
    if not item:
        raise HTTPException(404, "Integration not found.")
    target, host = await _assessment_target(item, render_only)
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


async def _get_root_following(client: httpx.AsyncClient, target: str, max_hops: int = 3) -> dict:
    """Follow a few same-host HTTPS redirects, revalidating each destination."""
    current, hops = target, []
    original_host = (urlparse(target).hostname or "").lower()
    for _ in range(max_hops + 1):
        result = await _get_root(client, current)
        location = result["headers"].get("location") if result["headers"] else None
        if result["status_code"] in REDIRECT_CODES and location:
            nxt = urljoin(current, location)
            if len(hops) >= max_hops:
                result["redirect_chain"], result["downgraded"], result["final_url"] = hops, False, current
                result["redirect_blocked"] = True
                result["redirect_error"] = "Redirect limit reached."
                return result
            parsed_next = urlparse(nxt)
            hops.append(f"{result['status_code']} -> {nxt}")
            if parsed_next.scheme != "https":
                result["redirect_chain"], result["downgraded"], result["final_url"] = hops, True, current
                return result
            if (parsed_next.hostname or "").lower() != original_host:
                result["redirect_chain"], result["downgraded"], result["final_url"] = hops, False, current
                result["redirect_blocked"] = True
                return result
            try:
                current = await asyncio.to_thread(_validated_url, nxt)
            except HTTPException as exc:
                result["redirect_chain"], result["downgraded"], result["final_url"] = hops, False, current
                result["redirect_blocked"] = True
                result["redirect_error"] = exc.detail
                return result
            continue
        result["redirect_chain"], result["downgraded"], result["final_url"] = hops, False, current
        return result
    result["redirect_chain"], result["downgraded"], result["final_url"] = hops, False, current
    return result


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
    url = await asyncio.to_thread(_validated_url, body.url)
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
    await asyncio.to_thread(_validated_url, item["url"])
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
    target, _host = await _begin_assessment(integration_id)
    item = integrations[integration_id]
    async with httpx.AsyncClient(timeout=httpx.Timeout(12.0, connect=6.0), follow_redirects=False, max_redirects=0, headers={"User-Agent": "SentinelAI-SecurityReview/1.0 (passive checks)"}) as client:
        baseline = await _get_root_following(client, target)
        if baseline["error"]:
            raise HTTPException(502, f"The website could not be reached ({baseline['error']}). Check its URL and try again.")

        headers = baseline["headers"]
        checks = []
        def add(title, result, severity, details, recommendation="", fix=""):
            checks.append({"title": title, "result": result, "severity": severity, "details": details,
                           "recommendation": recommendation, "fix": fix})

        if baseline.get("downgraded"):
            add("Redirect leaves HTTPS", "https_downgrade", "high",
                f"The site redirected away from HTTPS: {' -> '.join(baseline['redirect_chain'])}",
                "Redirect only to HTTPS URLs.", "return 301 https://$host$request_uri;   # nginx")
        elif baseline.get("redirect_blocked"):
            add("Cross-host redirect not followed", "redirect_not_followed", "info",
                "The page redirects to a different hostname. Sentinel stopped before requesting that host; add the destination as a separate integration if it is in scope.")
        status_code = baseline["status_code"]
        if status_code in (401, 403, 429):
            add("Site blocked the scanner", f"http_{status_code}", "info",
                f"The site answered HTTP {status_code}. A firewall or bot protection may be hiding the page, so these results may be incomplete.")

        csp = headers.get("content-security-policy", "")
        present = {
            "Content-Security-Policy": bool(csp),
            "Strict-Transport-Security": bool(headers.get("strict-transport-security")),
            "X-Content-Type-Options": headers.get("x-content-type-options", "").lower() == "nosniff",
            "Frame protection": "frame-ancestors" in csp.lower() or headers.get("x-frame-options", "").lower() in ("deny", "sameorigin"),
            "Referrer-Policy": bool(headers.get("referrer-policy")),
            "Permissions-Policy": bool(headers.get("permissions-policy")),
        }
        for title, configured in present.items():
            severity, explanation, fix = HEADER_FIXES[title]
            if configured:
                add(title, "present", "info", "Configured.")
            else:
                add(f"Missing {title}", "missing", severity, explanation,
                    f"Add the {title} response header at your web server, CDN, or app middleware.", fix)

        cookies = headers.get_list("set-cookie") if hasattr(headers, "get_list") else []
        for cookie in cookies:
            lower_cookie = cookie.lower()
            missing = [flag for flag in ("secure", "httponly", "samesite") if flag not in lower_cookie]
            if missing:
                cookie_name = cookie.split("=", 1)[0].strip()[:40]
                severity = "medium" if "httponly" in missing or "secure" in missing else "low"
                add(f"Cookie '{cookie_name}' missing flags", "review", severity,
                    f"Missing: {', '.join(missing)}.",
                    "Set Secure (HTTPS only), HttpOnly (hidden from JavaScript), and SameSite (CSRF protection) on session cookies.",
                    "Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax")

        page = baseline["body"]
        content_type = headers.get("content-type", "").lower()
        server_banner = headers.get("server", "") + " " + headers.get("x-powered-by", "")
        if re.search(r"(?:apache|nginx|iis|php|express)[/ ]\d", server_banner, re.IGNORECASE):
            add("Server version disclosed", "version_banner_observed", "low",
                f"Headers reveal: {server_banner.strip()[:80]}",
                "Hide version numbers so attackers cannot target known issues for an exact version.",
                "server_tokens off;   # nginx\nServerTokens Prod   # Apache\napp.disable('x-powered-by')   // Express")
        if "html" in content_type or "<html" in page[:1000].lower():
            if re.search(r"(?:src|poster)\s*=\s*['\"]http://|url\(\s*['\"]?http://", page, re.IGNORECASE):
                add("Mixed HTTP content reference", "potential_mixed_content", "low",
                    "The homepage contains an HTTP resource reference. Upgrade active page resources to HTTPS.",
                    "Load scripts, styles, images, and media over HTTPS.", '<script src="https://static.example.com/app.js"></script>')
            for form in re.findall(r"<form\b[^>]*>", page, re.IGNORECASE)[:40]:
                action = re.search(r"action\s*=\s*['\"]([^'\"]+)['\"]", form, re.IGNORECASE)
                if action and action.group(1).lower().startswith("http://"):
                    add("Form submits over HTTP", "insecure_form_action", "medium",
                        "A form on the homepage appears to submit to an unencrypted HTTP URL.",
                        "Change the form action to HTTPS.", '<form action="https://shop.example.com/submit" method="post">')
                    break
            for script in re.findall(r"<script\b[^>]*\bsrc\s*=\s*['\"][^'\"]+['\"][^>]*>", page, re.IGNORECASE)[:30]:
                src = re.search(r"\bsrc\s*=\s*['\"]([^'\"]+)['\"]", script, re.IGNORECASE)
                if src and src.group(1).startswith("https://") and "integrity=" not in script.lower():
                    add("External script without integrity attribute", "review_external_script", "info",
                        "An external HTTPS script has no Subresource Integrity attribute. Review whether SRI is practical for this script.",
                        "Pin the script contents with a current SRI hash where the provider supports stable assets.",
                        '<script src="https://cdn.example.com/library.js" integrity="sha384-<computed-hash>" crossorigin="anonymous"></script>')
                    break

    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    checks.sort(key=lambda check: order.get(check["severity"], 4))
    findings = sum(1 for check in checks if check["severity"] in ("low", "medium", "high"))
    checked_at = datetime.now(timezone.utc).isoformat()
    report = {
        "integration_id": integration_id,
        "site": baseline.get("final_url", item["url"]),
        "checked_at": checked_at,
        "http_status": baseline["status_code"],
        "latency_ms": baseline["latency_ms"],
        "summary": "potential findings" if findings else "no issues observed by these checks",
        "finding_count": findings,
        "checks": checks,
        "probes": [],
        "redirects": baseline.get("redirect_chain", []),
        "scope": "One bounded, read-only HTTPS GET (following up to 3 validated same-host redirects). Checks response headers, cookies and homepage markup; does not inspect server files, authenticate, submit forms, or prove the site secure.",
    }
    item["status"] = "online" if (baseline["status_code"] or 0) < 500 else "degraded"
    item["http_status"] = baseline["status_code"]
    item["latency_ms"] = baseline["latency_ms"]
    item["checked_at"] = checked_at
    item["last_scan_at"] = checked_at
    item["last_scan_findings"] = findings
    return report


@router.post("/{integration_id}/simulate")
async def simulate_safe_probes(integration_id: str):
    target, _host = await _begin_assessment(integration_id, render_only=True)
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
