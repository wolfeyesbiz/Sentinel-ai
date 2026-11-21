import re
import sqlite3

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from app.auth import (
    DEMO_EMAIL,
    DEMO_PASSWORD,
    SECOND_DEMO_EMAIL,
    SECOND_DEMO_PASSWORD,
    SESSION_SECONDS,
    allow_auth_attempt,
    create_session,
    create_user,
    delete_session,
    find_user,
    get_session_user,
    verify_password,
)
from app.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])
COOKIE_NAME = "sentinel_session"


class Credentials(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class Registration(Credentials):
    name: str = Field(min_length=2, max_length=60)
    password: str = Field(min_length=10, max_length=128)


def _request_token(request: Request) -> str | None:
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return request.cookies.get(COOKIE_NAME)


def _set_session(response: Response, user: dict) -> dict:
    token, _ = create_session(user["id"])
    response.set_cookie(
        COOKIE_NAME, token, max_age=SESSION_SECONDS, httponly=True,
        secure=settings.ENVIRONMENT.lower() == "production", samesite="none", path="/",
    )
    return {"user": {"id": user["id"], "name": user["name"], "email": user["email"]}, "access_token": token}


@router.get("/demo")
async def demo_credentials():
    return {"accounts": [
        {"label": "Demo account 1", "email": DEMO_EMAIL, "password": DEMO_PASSWORD},
        {"label": "Demo account 2", "email": SECOND_DEMO_EMAIL, "password": SECOND_DEMO_PASSWORD},
    ]}


@router.get("/me")
async def current_user(request: Request):
    user = get_session_user(_request_token(request))
    if not user:
        raise HTTPException(401, "Please sign in to continue.")
    return {"user": user}


@router.post("/login")
async def login(body: Credentials, request: Request, response: Response):
    ip = request.client.host if request.client else "unknown"
    if not allow_auth_attempt(ip):
        raise HTTPException(429, "Too many sign-in attempts. Wait one minute and try again.")
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", body.email.strip()):
        raise HTTPException(400, "Enter a valid email address.")
    user = verify_password(body.email, body.password)
    if not user:
        raise HTTPException(401, "Email or password is incorrect.")
    return _set_session(response, user)


@router.post("/register", status_code=201)
async def register(body: Registration, request: Request, response: Response):
    ip = request.client.host if request.client else "unknown"
    if not allow_auth_attempt(ip):
        raise HTTPException(429, "Too many account attempts. Wait one minute and try again.")
    email = body.email.strip().lower()
    name = body.name.strip()
    if len(name) < 2:
        raise HTTPException(400, "Enter a name with at least two characters.")
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(400, "Enter a valid email address.")
    if len(body.password) < 10:
        raise HTTPException(400, "Use a password with at least 10 characters.")
    if find_user(email):
        raise HTTPException(409, "An account with that email already exists.")
    try:
        user = create_user(name, email, body.password)
    except sqlite3.IntegrityError:
        raise HTTPException(409, "An account with that email already exists.")
    return _set_session(response, user)


@router.post("/logout")
async def logout(request: Request, response: Response):
    delete_session(_request_token(request))
    response.delete_cookie(COOKIE_NAME, httponly=True, secure=settings.ENVIRONMENT.lower() == "production", samesite="none", path="/")
    return {"success": True}
