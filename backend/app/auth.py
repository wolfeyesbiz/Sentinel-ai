"""Small cookie-session authentication for the Sentinel demo dashboard."""
import hashlib
import hmac
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone

from app.storage.db import db

SESSION_SECONDS = 7 * 24 * 60 * 60
PASSWORD_ITERATIONS = 310_000
DEMO_EMAIL = "demo@sentinel.local"
DEMO_PASSWORD = "SentinelDemo2026!"
SECOND_DEMO_EMAIL = "demo2@sentinel.local"
SECOND_DEMO_PASSWORD = "SentinelGuest2026!"


def initialize_auth() -> None:
    with db._get_connection() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS auth_users (
            id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
            salt TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS auth_sessions (
            token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at TEXT NOT NULL
        )""")
        conn.commit()
    if not find_user(DEMO_EMAIL):
        create_user("Sentinel Demo", DEMO_EMAIL, DEMO_PASSWORD)
    if not find_user(SECOND_DEMO_EMAIL):
        create_user("Sentinel Demo Two", SECOND_DEMO_EMAIL, SECOND_DEMO_PASSWORD)


def _password_hash(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS).hex()


def create_user(name: str, email: str, password: str) -> dict:
    normalized = email.strip().lower()
    salt = secrets.token_bytes(16)
    user = {"id": uuid.uuid4().hex, "name": name.strip(), "email": normalized}
    with db._get_connection() as conn:
        conn.execute(
            "INSERT INTO auth_users(id,email,name,salt,password_hash,created_at) VALUES(?,?,?,?,?,?)",
            (user["id"], normalized, user["name"], salt.hex(), _password_hash(password, salt), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    return user


def find_user(email: str) -> dict | None:
    with db._get_connection() as conn:
        row = conn.execute("SELECT id,email,name,salt,password_hash FROM auth_users WHERE email=?", (email.strip().lower(),)).fetchone()
    return dict(row) if row else None


def verify_password(email: str, password: str) -> dict | None:
    user = find_user(email)
    if not user:
        # Burn comparable CPU for unknown email to reduce timing-based enumeration.
        _password_hash(password, b"sentinel-demo-salt")
        return None
    candidate = _password_hash(password, bytes.fromhex(user["salt"]))
    if not hmac.compare_digest(candidate, user["password_hash"]):
        return None
    return {"id": user["id"], "name": user["name"], "email": user["email"]}


def create_session(user_id: str) -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(seconds=SESSION_SECONDS)
    with db._get_connection() as conn:
        conn.execute("DELETE FROM auth_sessions WHERE expires_at < ?", (datetime.now(timezone.utc).isoformat(),))
        conn.execute("INSERT INTO auth_sessions(token_hash,user_id,expires_at) VALUES(?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), user_id, expires.isoformat()))
        conn.commit()
    return token, expires.isoformat()


def get_session_user(token: str | None) -> dict | None:
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with db._get_connection() as conn:
        row = conn.execute("""SELECT u.id,u.name,u.email FROM auth_sessions s
            JOIN auth_users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?""",
            (token_hash, datetime.now(timezone.utc).isoformat())).fetchone()
    return dict(row) if row else None


def delete_session(token: str | None) -> None:
    if not token:
        return
    with db._get_connection() as conn:
        conn.execute("DELETE FROM auth_sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
        conn.commit()


_attempts: dict[str, list[float]] = {}


def allow_auth_attempt(ip: str) -> bool:
    now = time.monotonic()
    recent = [stamp for stamp in _attempts.get(ip, []) if now - stamp < 60]
    if len(recent) >= 10:
        _attempts[ip] = recent
        return False
    recent.append(now)
    _attempts[ip] = recent
    return True
