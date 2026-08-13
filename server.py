"""
Gmail MCP Server — FastMCP + Google OAuth proxy

Flow:
  Claude.ai ──[OAuth]──► This server ──[OAuth]──► Google
  Claude.ai ──[MCP]────► This server ──[Gmail API]──► Gmail/Calendar
"""
import asyncio
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

HTTPX_TIMEOUT = 30.0
STATE_TTL = 600  # seconds; abandoned OAuth flows are purged after this

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

_state_store: dict[str, dict] = {}   # our_state  → {..., "created": ts}
_code_store: dict[str, dict] = {}    # our_code   → {jti, email, code_challenge, ..., "created": ts}
_token_store: dict[str, dict] = {}   # jti        → {access_token, refresh_token, expiry, email, jwt_exp}
_refresh_locks: dict[str, asyncio.Lock] = {}  # jti → lock guarding concurrent token refreshes

# ── Per-request context ────────────────────────────────────────────────────────

_google_token: ContextVar[str] = ContextVar("google_token", default="")
_user_email: ContextVar[str] = ContextVar("user_email", default="")

# ── Helpers ────────────────────────────────────────────────────────────────────

class ReauthRequired(Exception):
    """Raised when a session is unknown or Google has revoked/expired the refresh token."""


def _pkce_ok(verifier: str, challenge: str) -> bool:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode() == challenge


def _purge_expired_states() -> None:
    now = time.time()
    expired = [k for k, v in _state_store.items() if now - v.get("created", now) > STATE_TTL]
    for k in expired:
        _state_store.pop(k, None)
    expired = [k for k, v in _code_store.items() if now - v.get("created", now) > STATE_TTL]
    for k in expired:
        _code_store.pop(k, None)


def _purge_expired_tokens() -> None:
    now = time.time()
    expired = [jti for jti, d in _token_store.items() if now >= d.get("jwt_exp", float("inf"))]
    for jti in expired:
        _token_store.pop(jti, None)
        _refresh_locks.pop(jti, None)


async def _refresh(jti: str) -> str:
    # Lock per session so two concurrent requests hitting an expired token don't
    # both fire a refresh_token grant (Google can reject the second as reused).
    lock = _refresh_locks.setdefault(jti, asyncio.Lock())
    async with lock:
        d = _token_store.get(jti)
        if not d:
            raise ReauthRequired("session not found")
        if time.time() < d["expiry"] - 60:
            # Another coroutine already refreshed while we waited on the lock.
            return d["access_token"]
        async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as c:
            r = await c.post("https://oauth2.googleapis.com/token", data={
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "refresh_token": d["refresh_token"],
                "grant_type": "refresh_token",
            })
            t = r.json()
        if "access_token" not in t:
            _token_store.pop(jti, None)
            raise ReauthRequired(t.get("error_description", t.get("error", "refresh failed")))
        d["access_token"] = t["access_token"]
        d["expiry"] = time.time() + t.get("expires_in", 3600)
        return d["access_token"]


async def _google_access_token(jti: str) -> str:
    d = _token_store.get(jti)
    if not d:
        raise ReauthRequired("session not found")
    if time.time() >= d["expiry"] - 60:
        return await _refresh(jti)
    return d["access_token"]


def _auth() -> dict:
    t = _google_token.get()
    if not t:
        raise RuntimeError("not authenticated")
    return {"Authorization": f"Bearer {t}"}


def _build_email(to: str, subject: str, body: str, cc: str = "",
                 in_reply_to: str = "", references: str = "") -> str:
    msg = MIMEText(body)
    msg["to"] = to
    msg["subject"] = subject
    if cc:
        msg["cc"] = cc
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    if references:
        msg["References"] = references
    return base64.urlsafe_b64encode(msg.as_bytes()).decode()


# ── FastMCP tools ──────────────────────────────────────────────────────────────

mcp = FastMCP("Gmail MCP")


@mcp.tool
async def get_profile() -> dict:
    """Get the authenticated Gmail account's profile."""
    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as c:
        r = await c.get(f"{GMAIL}/profile", headers=_auth())
        r.raise_for_status()
        return r.json()


@mcp.tool
async def search_emails(query: str, max_results: int = 20) -> list[dict]:
    """Search Gmail. Supports all Gmail search operators (from:, subject:, has:attachment, etc.)."""
    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as c:
        r = await c.get(f"{GMAIL}/messages", headers=_auth(),
                        params={"q": query, "maxResults": max_results})
        r.raise_for_status()
        return r.json().get("messages", [])


@mcp.tool
async def read_message(message_id: str) -> dict:
    """Read a Gmail message by ID. Returns headers and decoded body."""
    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as c:
        r = await c.get(f"{GMAIL}/messages/{message_id}", headers=_auth(),
                        params={"format": "full"})
        r.raise_for_status()
        data = r.json()

    def _extract_body(part: dict, mime: str) -> str:
        # Recurses into nested parts (e.g. multipart/mixed > multipart/alternative > text/plain).
        if part.get("mimeType") == mime:
            raw = part.get("body", {}).get("data", "")
            if raw:
                return base64.urlsafe_b64decode(raw + "==").decode("utf-8", errors="replace")
        for sub in part.get("parts", []):
            found = _extract_body(sub, mime)
            if found:
                return found
        return ""

    payload = data.get("payload", {})
    body = _extract_body(payload, "text/plain") or _extract_body(payload, "text/html")

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
    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as c:
        r = await c.get(f"{GMAIL}/threads/{thread_id}", headers=_auth())
        r.raise_for_status()
        return r.json()


@mcp.tool
async def send_email(to: str, subject: str, body: str, cc: str = "",
                     reply_to_message_id: str = "") -> dict:
    """Send an email. Use reply_to_message_id to reply within a thread."""
    thread_id = ""
    in_reply_to = ""
    references = ""
    if reply_to_message_id:
        async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as c:
            r = await c.get(f"{GMAIL}/messages/{reply_to_message_id}", headers=_auth(),
                            params={"format": "metadata",
                                    "metadataHeaders": ["Message-ID", "References"]})
            # Fail loudly rather than silently sending an unthreaded standalone email
            # when the caller explicitly asked for a reply.
            r.raise_for_status()
            msg = r.json()
            thread_id = msg.get("threadId", "")
            hdrs = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
            in_reply_to = hdrs.get("Message-ID", "")
            references = (hdrs.get("References", "") + " " + in_reply_to).strip()

    payload: dict = {"raw": _build_email(to, subject, body, cc, in_reply_to, references)}
    if thread_id:
        payload["threadId"] = thread_id
    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as c:
        r = await c.post(f"{GMAIL}/messages/send", headers=_auth(), json=payload)
        r.raise_for_status()
        return r.json()


@mcp.tool
async def create_draft(to: str, subject: str, body: str, cc: str = "") -> dict:
    """Create a Gmail draft."""
    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as c:
        r = await c.post(f"{GMAIL}/drafts", headers=_auth(),
                         json={"message": {"raw": _build_email(to, subject, body, cc)}})
        r.raise_for_status()
        return r.json()


@mcp.tool
async def list_drafts(max_results: int = 10) -> list[dict]:
    """List Gmail drafts."""
    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as c:
        r = await c.get(f"{GMAIL}/drafts", headers=_auth(),
                        params={"maxResults": max_results})
        r.raise_for_status()
        return r.json().get("drafts", [])


@mcp.tool
async def list_labels() -> list[dict]:
    """List all Gmail labels."""
    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as c:
        r = await c.get(f"{GMAIL}/labels", headers=_auth())
        r.raise_for_status()
        return r.json().get("labels", [])


@mcp.tool
async def modify_labels(message_id: str, add: list[str] | None = None,
                        remove: list[str] | None = None) -> dict:
    """Add or remove labels on a Gmail message."""
    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as c:
        r = await c.post(f"{GMAIL}/messages/{message_id}/modify", headers=_auth(),
                         json={"addLabelIds": add or [], "removeLabelIds": remove or []})
        r.raise_for_status()
        return r.json()


@mcp.tool
async def trash_message(message_id: str) -> dict:
    """Move a Gmail message to trash."""
    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as c:
        r = await c.post(f"{GMAIL}/messages/{message_id}/trash", headers=_auth())
        r.raise_for_status()
        return r.json()


@mcp.tool
async def list_calendars() -> list[dict]:
    """List all Google Calendars."""
    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as c:
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
    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as c:
        r = await c.get(f"{GCAL}/calendars/{calendar_id}/events",
                        headers=_auth(), params=params)
        r.raise_for_status()
        return r.json().get("items", [])


@mcp.tool
async def search_events(query: str, calendar_id: str = "primary",
                        max_results: int = 10) -> list[dict]:
    """Search calendar events by keyword."""
    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as c:
        r = await c.get(f"{GCAL}/calendars/{calendar_id}/events", headers=_auth(),
                        params={"q": query, "maxResults": max_results, "singleEvents": True})
        r.raise_for_status()
        return r.json().get("items", [])


@mcp.tool
async def get_event(event_id: str, calendar_id: str = "primary") -> dict:
    """Get a specific calendar event by ID."""
    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as c:
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
        "created": time.time(),
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

    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as c:
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

    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as c:
        ui = await c.get("https://www.googleapis.com/oauth2/v3/userinfo",
                         headers={"Authorization": f"Bearer {tokens['access_token']}"})
        userinfo = ui.json()

    jti = secrets.token_urlsafe(16)
    _token_store[jti] = {
        "access_token": tokens["access_token"],
        "refresh_token": tokens.get("refresh_token"),
        "expiry": time.time() + tokens.get("expires_in", 3600),
        "email": userinfo.get("email"),
        # Provisional; replaced with the real 30-day expiry once /token mints the client JWT.
        # Ensures flows abandoned between here and /token still get purged.
        "jwt_exp": time.time() + STATE_TTL,
    }

    our_code = secrets.token_urlsafe(16)
    _code_store[our_code] = {
        "jti": jti,
        "email": userinfo.get("email"),
        "code_challenge": state_data["code_challenge"],
        "client_redirect_uri": state_data["client_redirect_uri"],
        "client_state": state_data["client_state"],
        "created": time.time(),
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
    exp = now + 86400 * 30
    token = jwt.encode({
        "jti": code_data["jti"],
        "email": code_data["email"],
        "iat": now,
        "exp": exp,
    }, JWT_SECRET, algorithm="HS256")

    if code_data["jti"] in _token_store:
        _token_store[code_data["jti"]]["jwt_exp"] = exp

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

_KNOWN_PATHS = _OAUTH_PATHS | {"/mcp"}


def _normalise_path(path: str) -> str:
    """Strip a leading /<alias> segment so /personal/mcp, /work/.well-known/... etc.
    resolve the same as their unaliased routes — lets two Claude connectors share one server."""
    if path in _KNOWN_PATHS or path.startswith("/mcp/"):
        return path
    segments = path.lstrip("/").split("/", 1)
    if len(segments) == 2:
        candidate = "/" + segments[1]
        if candidate in _KNOWN_PATHS or candidate.startswith("/mcp/"):
            return candidate
    return path


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
            _purge_expired_states()
            _purge_expired_tokens()

            path = _normalise_path(scope["path"])
            if path != scope["path"]:
                scope = {**scope, "path": path, "raw_path": path.encode()}

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
    # PaaS platforms (Railway, Render, etc.) inject PORT and route to whatever it's set to.
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), log_level="info")
