"""
Gmail MCP Server — FastMCP + Google OAuth proxy

Flow:
  Claude.ai ──[OAuth]──► This server ──[OAuth]──► Google
  Claude.ai ──[MCP]────► This server ──[Gmail API]──► Gmail/Calendar
"""
import base64
import hashlib
import os
import secrets
import time
from contextvars import ContextVar
from email.mime.text import MIMEText
from urllib.parse import urlencode

import httpx
import jwt
from fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route

# ── Config ─────────────────────────────────────────────────────────────────────

GOOGLE_CLIENT_ID = os.environ["GOOGLE_CLIENT_ID"]
GOOGLE_CLIENT_SECRET = os.environ["GOOGLE_CLIENT_SECRET"]
BASE_URL = os.environ["BASE_URL"].rstrip("/")  # e.g. https://mcp.gar.im/gmail
JWT_SECRET = os.environ["JWT_SECRET"]

# Redirect URIs /authorize is allowed to send the auth code to. Without this allowlist,
# an attacker can craft an /authorize?redirect_uri=<attacker-controlled> link and, once
# the victim completes Google's consent screen, receive the resulting single-use code
# themselves — full account takeover if PKCE isn't also enforced (see _authorize below).
ALLOWED_REDIRECT_URIS = frozenset(
    u.strip() for u in os.environ.get(
        "ALLOWED_REDIRECT_URIS", "https://claude.ai/api/mcp/auth_callback"
    ).split(",") if u.strip()
)

GOOGLE_SCOPES = " ".join([
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/calendar.readonly",
])

GMAIL = "https://gmail.googleapis.com/gmail/v1/users/me"
GCAL = "https://www.googleapis.com/calendar/v3"

# ── In-memory stores ───────────────────────────────────────────────────────────
# Fine for single-process personal use; restart clears sessions (re-auth needed).

_state_store: dict[str, dict] = {}   # our_state  → OAuth flow params
_code_store: dict[str, dict] = {}    # our_code   → {jti, email, code_challenge, ...}
_token_store: dict[str, dict] = {}   # jti        → {access_token, refresh_token, expiry, email}

# ── Per-request context ────────────────────────────────────────────────────────

_google_token: ContextVar[str] = ContextVar("google_token", default="")
_user_email: ContextVar[str] = ContextVar("user_email", default="")

# ── Helpers ────────────────────────────────────────────────────────────────────

def _pkce_ok(verifier: str, challenge: str) -> bool:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode() == challenge


async def _refresh(jti: str) -> str:
    d = _token_store[jti]
    async with httpx.AsyncClient() as c:
        r = await c.post("https://oauth2.googleapis.com/token", data={
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "refresh_token": d["refresh_token"],
            "grant_type": "refresh_token",
        })
        t = r.json()
    d["access_token"] = t["access_token"]
    d["expiry"] = time.time() + t.get("expires_in", 3600)
    return d["access_token"]


async def _google_access_token(jti: str) -> str:
    d = _token_store.get(jti)
    if not d:
        raise ValueError("session not found")
    if time.time() >= d["expiry"] - 60:
        return await _refresh(jti)
    return d["access_token"]


def _auth() -> dict:
    t = _google_token.get()
    if not t:
        raise RuntimeError("not authenticated")
    return {"Authorization": f"Bearer {t}"}


def _build_email(to: str, subject: str, body: str, cc: str = "") -> str:
    msg = MIMEText(body)
    msg["to"] = to
    msg["subject"] = subject
    if cc:
        msg["cc"] = cc
    return base64.urlsafe_b64encode(msg.as_bytes()).decode()


# ── FastMCP tools ──────────────────────────────────────────────────────────────

mcp = FastMCP("Gmail MCP")


@mcp.tool
async def get_profile() -> dict:
    """Get the authenticated Gmail account's profile."""
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{GMAIL}/profile", headers=_auth())
        r.raise_for_status()
        return r.json()


@mcp.tool
async def search_emails(query: str, max_results: int = 20) -> list[dict]:
    """Search Gmail. Supports all Gmail search operators (from:, subject:, has:attachment, etc.)."""
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{GMAIL}/messages", headers=_auth(),
                        params={"q": query, "maxResults": max_results})
        r.raise_for_status()
        return r.json().get("messages", [])


@mcp.tool
async def read_message(message_id: str) -> dict:
    """Read a Gmail message by ID. Returns headers and decoded body."""
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{GMAIL}/messages/{message_id}", headers=_auth(),
                        params={"format": "full"})
        r.raise_for_status()
        data = r.json()

    def _body(part: dict) -> str:
        raw = part.get("body", {}).get("data", "")
        return base64.urlsafe_b64decode(raw + "==").decode("utf-8", errors="replace") if raw else ""

    payload = data.get("payload", {})
    body = _body(payload)
    if not body:
        for part in payload.get("parts", []):
            if part.get("mimeType") == "text/plain":
                body = _body(part)
                break
        if not body:
            for part in payload.get("parts", []):
                if part.get("mimeType") == "text/html":
                    body = _body(part)
                    break

    hdrs = {h["name"]: h["value"] for h in payload.get("headers", [])}
    return {
        "id": data["id"],
        "threadId": data["threadId"],
        "from": hdrs.get("From", ""),
        "to": hdrs.get("To", ""),
        "subject": hdrs.get("Subject", ""),
        "date": hdrs.get("Date", ""),
        "snippet": data.get("snippet", ""),
        "labels": data.get("labelIds", []),
        "body": body,
    }


@mcp.tool
async def read_thread(thread_id: str) -> dict:
    """Read a full Gmail thread."""
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{GMAIL}/threads/{thread_id}", headers=_auth())
        r.raise_for_status()
        return r.json()


@mcp.tool
async def send_email(to: str, subject: str, body: str, cc: str = "",
                     reply_to_message_id: str = "") -> dict:
    """Send an email. Use reply_to_message_id to reply within a thread."""
    payload: dict = {"raw": _build_email(to, subject, body, cc)}
    if reply_to_message_id:
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{GMAIL}/messages/{reply_to_message_id}",
                            headers=_auth(), params={"format": "minimal"})
            if r.is_success:
                payload["threadId"] = r.json().get("threadId", "")
    async with httpx.AsyncClient() as c:
        r = await c.post(f"{GMAIL}/messages/send", headers=_auth(), json=payload)
        r.raise_for_status()
        return r.json()


@mcp.tool
async def create_draft(to: str, subject: str, body: str, cc: str = "") -> dict:
    """Create a Gmail draft."""
    async with httpx.AsyncClient() as c:
        r = await c.post(f"{GMAIL}/drafts", headers=_auth(),
                         json={"message": {"raw": _build_email(to, subject, body, cc)}})
        r.raise_for_status()
        return r.json()


@mcp.tool
async def list_drafts(max_results: int = 10) -> list[dict]:
    """List Gmail drafts."""
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{GMAIL}/drafts", headers=_auth(),
                        params={"maxResults": max_results})
        r.raise_for_status()
        return r.json().get("drafts", [])


@mcp.tool
async def list_labels() -> list[dict]:
    """List all Gmail labels."""
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{GMAIL}/labels", headers=_auth())
        r.raise_for_status()
        return r.json().get("labels", [])


@mcp.tool
async def modify_labels(message_id: str, add: list[str] = [],
                        remove: list[str] = []) -> dict:
    """Add or remove labels on a Gmail message."""
    async with httpx.AsyncClient() as c:
        r = await c.post(f"{GMAIL}/messages/{message_id}/modify", headers=_auth(),
                         json={"addLabelIds": add, "removeLabelIds": remove})
        r.raise_for_status()
        return r.json()


@mcp.tool
async def trash_message(message_id: str) -> dict:
    """Move a Gmail message to trash."""
    async with httpx.AsyncClient() as c:
        r = await c.post(f"{GMAIL}/messages/{message_id}/trash", headers=_auth())
        r.raise_for_status()
        return r.json()


@mcp.tool
async def list_calendars() -> list[dict]:
    """List all Google Calendars."""
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{GCAL}/users/me/calendarList", headers=_auth())
        r.raise_for_status()
        return r.json().get("items", [])


@mcp.tool
async def list_events(calendar_id: str = "primary", time_min: str = "",
                      time_max: str = "", max_results: int = 20) -> list[dict]:
    """List calendar events. time_min/time_max in RFC3339 (e.g. 2026-05-20T00:00:00Z)."""
    params: dict = {"maxResults": max_results, "singleEvents": True, "orderBy": "startTime"}
    if time_min:
        params["timeMin"] = time_min
    if time_max:
        params["timeMax"] = time_max
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{GCAL}/calendars/{calendar_id}/events",
                        headers=_auth(), params=params)
        r.raise_for_status()
        return r.json().get("items", [])


@mcp.tool
async def search_events(query: str, calendar_id: str = "primary",
                        max_results: int = 10) -> list[dict]:
    """Search calendar events by keyword."""
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{GCAL}/calendars/{calendar_id}/events", headers=_auth(),
                        params={"q": query, "maxResults": max_results, "singleEvents": True})
        r.raise_for_status()
        return r.json().get("items", [])


@mcp.tool
async def get_event(event_id: str, calendar_id: str = "primary") -> dict:
    """Get a specific calendar event by ID."""
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{GCAL}/calendars/{calendar_id}/events/{event_id}",
                        headers=_auth())
        r.raise_for_status()
        return r.json()


# ── OAuth endpoints ────────────────────────────────────────────────────────────

async def _oauth_server_metadata(req: Request) -> JSONResponse:
    return JSONResponse({
        "issuer": BASE_URL,
        "authorization_endpoint": f"{BASE_URL}/authorize",
        "token_endpoint": f"{BASE_URL}/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["gmail"],
    })


async def _openid_configuration(req: Request) -> JSONResponse:
    return JSONResponse({
        "issuer": BASE_URL,
        "authorization_endpoint": f"{BASE_URL}/authorize",
        "token_endpoint": f"{BASE_URL}/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "gmail"],
    })


async def _protected_resource(req: Request) -> JSONResponse:
    return JSONResponse({
        "resource": BASE_URL,
        "authorization_servers": [BASE_URL],
    })


async def _authorize(req: Request):
    p = req.query_params
    redirect_uri = p.get("redirect_uri", "https://claude.ai/api/mcp/auth_callback")
    if redirect_uri not in ALLOWED_REDIRECT_URIS:
        return Response("Unknown redirect_uri", status_code=400)
    if not p.get("code_challenge"):
        return Response("PKCE code_challenge is required", status_code=400)

    our_state = secrets.token_urlsafe(16)
    _state_store[our_state] = {
        "client_state": p.get("state"),
        "client_redirect_uri": redirect_uri,
        "code_challenge": p.get("code_challenge"),
    }
    return RedirectResponse(
        "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode({
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": f"{BASE_URL}/auth/callback",
            "response_type": "code",
            "scope": GOOGLE_SCOPES,
            "state": our_state,
            "access_type": "offline",
            "prompt": "consent",
        })
    )


async def _auth_callback(req: Request):
    error = req.query_params.get("error")
    if error:
        return Response(f"Google OAuth error: {error}", status_code=400)

    state_data = _state_store.pop(req.query_params.get("state", ""), None)
    if not state_data:
        return Response("Invalid or expired state", status_code=400)

    async with httpx.AsyncClient() as c:
        r = await c.post("https://oauth2.googleapis.com/token", data={
            "code": req.query_params.get("code"),
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": f"{BASE_URL}/auth/callback",
            "grant_type": "authorization_code",
        })
        tokens = r.json()

    if "error" in tokens:
        return Response(f"Token exchange failed: {tokens['error']}", status_code=400)

    async with httpx.AsyncClient() as c:
        ui = await c.get("https://www.googleapis.com/oauth2/v3/userinfo",
                         headers={"Authorization": f"Bearer {tokens['access_token']}"})
        userinfo = ui.json()

    jti = secrets.token_urlsafe(16)
    _token_store[jti] = {
        "access_token": tokens["access_token"],
        "refresh_token": tokens.get("refresh_token"),
        "expiry": time.time() + tokens.get("expires_in", 3600),
        "email": userinfo.get("email"),
    }

    our_code = secrets.token_urlsafe(16)
    _code_store[our_code] = {
        "jti": jti,
        "email": userinfo.get("email"),
        "code_challenge": state_data["code_challenge"],
        "client_redirect_uri": state_data["client_redirect_uri"],
        "client_state": state_data["client_state"],
    }

    params: dict = {"code": our_code}
    if state_data["client_state"]:
        params["state"] = state_data["client_state"]
    return RedirectResponse(f"{state_data['client_redirect_uri']}?{urlencode(params)}")


async def _token(req: Request) -> JSONResponse:
    data = await req.form()
    code_data = _code_store.pop(data.get("code", ""), None)
    if not code_data:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    verifier = data.get("code_verifier")
    if not verifier or not _pkce_ok(verifier, code_data["code_challenge"]):
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    now = int(time.time())
    token = jwt.encode({
        "jti": code_data["jti"],
        "email": code_data["email"],
        "iat": now,
        "exp": now + 86400 * 30,
    }, JWT_SECRET, algorithm="HS256")

    return JSONResponse({"access_token": token, "token_type": "Bearer",
                         "expires_in": 86400 * 30})


# ── Bearer auth middleware (raw ASGI — preserves ContextVar across await) ──────

_WWW_AUTH = (
    f'Bearer realm="Gmail MCP", '
    f'resource_metadata="{BASE_URL}/.well-known/oauth-protected-resource"'
).encode()

_OAUTH_PATHS = frozenset([
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-protected-resource",
    "/authorize",
    "/auth/callback",
    "/token",
])


class _App:
    """Dispatches OAuth paths to Starlette, everything else to FastMCP."""

    def __init__(self) -> None:
        self._oauth = Starlette(routes=[
            Route("/.well-known/oauth-authorization-server", _oauth_server_metadata),
            Route("/.well-known/openid-configuration", _openid_configuration),
            Route("/.well-known/oauth-protected-resource", _protected_resource),
            Route("/authorize", _authorize),
            Route("/auth/callback", _auth_callback),
            Route("/token", _token, methods=["POST"]),
        ])
        self._mcp = mcp.http_app()

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            await self._mcp(scope, receive, send)
            return

        if scope["type"] == "http":
            path = scope["path"]

            # Normalize /<alias>/mcp → /mcp so two Claude connectors can share one server
            parts = path.split("/")  # "/edgar/mcp" → ["", "edgar", "mcp"]
            if len(parts) == 3 and parts[2] == "mcp":
                scope = {**scope, "path": "/mcp", "raw_path": b"/mcp"}
                path = "/mcp"

            # Auth check for MCP endpoint only
            if path == "/mcp" or path.startswith("/mcp/"):
                headers = dict(scope.get("headers", []))
                auth = headers.get(b"authorization", b"").decode()
                if not auth.startswith("Bearer "):
                    await self._send_401(send)
                    return
                try:
                    payload = jwt.decode(auth[7:], JWT_SECRET, algorithms=["HS256"])
                    google_tok = await _google_access_token(payload["jti"])
                    _google_token.set(google_tok)
                    _user_email.set(payload.get("email", ""))
                except Exception:
                    await self._send_401(send)
                    return

            if path in _OAUTH_PATHS:
                await self._oauth(scope, receive, send)
                return

        await self._mcp(scope, receive, send)

    @staticmethod
    async def _send_401(send) -> None:
        await send({"type": "http.response.start", "status": 401,
                    "headers": [(b"content-type", b"text/plain"),
                                (b"www-authenticate", _WWW_AUTH)]})
        await send({"type": "http.response.body", "body": b"Unauthorized"})


app = _App()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
