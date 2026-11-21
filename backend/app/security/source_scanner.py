"""Bounded heuristic source review; does not execute uploaded or repository code."""
import re
import zipfile
from io import BytesIO
from pathlib import PurePosixPath

MAX_ARCHIVE_BYTES = 12 * 1024 * 1024
MAX_SOURCE_BYTES = 5 * 1024 * 1024
MAX_SOURCE_FILES = 250
MAX_FILE_BYTES = 512 * 1024
SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".html", ".htm", ".php", ".rb", ".go", ".java", ".cs", ".env", ".yml", ".yaml", ".toml", ".json", ".xml", ".sql", ".conf", ".ini", ".txt"}
SKIP_PARTS = {".git", "node_modules", "vendor", "dist", "build", ".next", ".venv", "venv", "coverage", "__pycache__"}
RULES = [
    ("high", "Possible hard-coded secret", re.compile(r"(?i)\b(?:api[_-]?key|secret(?:_key)?|password|passwd|access[_-]?token)\b\s*[:=]\s*['\"]([^'\"]{12,})['\"]"), "Move credentials to a secret manager or environment configuration, and rotate any real exposed secret."),
    ("high", "Possible SQL injection sink", re.compile(r"(?i)(?:\.execute|\.query|rawQuery)\s*\(\s*(?:f['\"]|`[^`]*\$\{|['\"][^'\"]{0,180}['\"]\s*\+\s*(?:str\s*\(|\w))"), "Use parameterized queries and bind values separately from SQL text."),
    ("high", "TLS certificate verification disabled", re.compile(r"(?i)(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false)"), "Enable certificate verification for all outbound HTTPS requests."),
    ("high", "Shell command execution", re.compile(r"(?i)(?:os\.system\s*\(|subprocess\.[\w]+\s*\([^\n]{0,180}shell\s*=\s*True|execSync\s*\()"), "Avoid shell execution with user-controlled input; use safe APIs and argument arrays."),
    ("medium", "Potential cross-site scripting sink", re.compile(r"(?i)(?:\.innerHTML\s*=|insertAdjacentHTML\s*\(|dangerouslySetInnerHTML)"), "Prefer text rendering or sanitize untrusted HTML with a well-maintained sanitizer."),
    ("medium", "Dynamic code evaluation", re.compile(r"(?i)(?:\beval\s*\(|new\s+Function\s*\()"), "Remove dynamic evaluation or strictly redesign it so untrusted input cannot reach it."),
    ("medium", "Permissive CORS configuration", re.compile(r"(?i)(?:allow_origins\s*=\s*\[\s*['\"]\*['\"]|Access-Control-Allow-Origin['\"]?\s*[:,=]\s*['\"]\*['\"]|origin\s*:\s*['\"]\*['\"])"), "Allow only the frontend origins that need access, especially on authenticated APIs."),
    ("medium", "Debug mode enabled", re.compile(r"(?i)\b(?:debug|DEBUG)\s*[:=]\s*True\b"), "Disable debug mode in production to avoid exposing stack traces and internal details."),
]
SECRET_PATTERN = RULES[0][2]


def scan_source_archive(archive_bytes: bytes, source_label: str) -> dict:
    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise ValueError("The source archive is larger than the 12 MB limit.")
    findings: list[dict] = []
    scanned = 0
    total_bytes = 0
    try:
        with zipfile.ZipFile(BytesIO(archive_bytes)) as archive:
            members = archive.infolist()
            if len(members) > 4000:
                raise ValueError("The archive contains too many entries to review safely.")
            for member in members:
                path = PurePosixPath(member.filename)
                is_env_file = path.name.lower().startswith(".env")
                is_dockerfile = path.name.lower() == "dockerfile"
                if member.is_dir() or any(part in SKIP_PARTS for part in path.parts) or (path.suffix.lower() not in SOURCE_SUFFIXES and not is_env_file and not is_dockerfile):
                    continue
                if path.is_absolute() or ".." in path.parts or member.file_size > MAX_FILE_BYTES:
                    continue
                if scanned >= MAX_SOURCE_FILES or total_bytes + member.file_size > MAX_SOURCE_BYTES:
                    break
                try:
                    content = archive.read(member)
                    text = content.decode("utf-8", errors="ignore")
                except (OSError, RuntimeError, zipfile.BadZipFile):
                    continue
                scanned += 1
                total_bytes += len(content)
                for line_number, line in enumerate(text.splitlines(), start=1):
                    for severity, title, pattern, recommendation in RULES:
                        match = pattern.search(line)
                        if not match:
                            continue
                        if title == "Possible hard-coded secret":
                            candidate = match.group(1).lower()
                            if any(marker in candidate for marker in ("example", "changeme", "your_", "dummy", "placeholder", "replace", "<", ">")):
                                continue
                        findings.append({
                            "severity": severity,
                            "title": title,
                            "file": member.filename[:240],
                            "line": line_number,
                            "evidence": SECRET_PATTERN.sub(lambda secret: secret.group(0).replace(secret.group(1), "[REDACTED]"), line.strip())[:220],
                            "recommendation": recommendation,
                        })
                        if len(findings) >= 250:
                            break
                    if len(findings) >= 250:
                        break
                if len(findings) >= 250:
                    break
    except zipfile.BadZipFile as exc:
        raise ValueError("The upload is not a valid ZIP archive.") from exc
    except OSError as exc:
        raise ValueError("The ZIP archive could not be read.") from exc
    return {
        "source": source_label,
        "scanned_files": scanned,
        "finding_count": len(findings),
        "findings": findings,
        "scope": "Heuristic review of a bounded set of source files. Sentinel did not execute code, resolve the full dependency tree, or prove the application secure.",
    }
