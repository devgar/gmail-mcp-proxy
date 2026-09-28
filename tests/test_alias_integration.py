"""End-to-end tests for alias routing and read-only enforcement.

These drive the real ASGI app so the alias travels the same path it does in
production: request path -> scope["state"] -> discovery metadata -> /authorize.
"""
import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
import respx
from starlette.testclient import TestClient

import server


class _ReadOnlySpy:
    """Stands in for the _read_only ContextVar so a test can observe what the
    middleware decided — the value itself is set inside the request's own context."""

    def __init__(self):
        self.values = []

    def set(self, value):
        self.values.append(value)

    def get(self):
        return self.values[-1] if self.values else False


@pytest.fixture
def read_only_work(monkeypatch):
    monkeypatch.setattr(server, "READ_ONLY_ALIASES", frozenset({"work"}))


def _session_jwt(read_only: bool) -> str:
    """A valid session for a live token, as /token would have minted it."""
    jti = f"jti-{read_only}"
    server._token_store[jti] = {
        "access_token": "at", "refresh_token": "rt",
        "expiry": time.time() + 3600, "email": "a@example.com",
        "jwt_exp": time.time() + 3600,
    }
    return jwt.encode({"jti": jti, "email": "a@example.com",
                       "read_only": read_only,
                       "exp": int(time.time()) + 3600},
                      server.JWT_SECRET, algorithm="HS256")


def test_read_only_alias_requests_only_read_scopes(read_only_work):
    with TestClient(server.app) as c:
        r = c.get("/work/authorize", follow_redirects=False, params={
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "code_challenge": "abc123",
        })
    assert r.status_code == 307
    scope = parse_qs(urlparse(r.headers["location"]).query)["scope"][0]
    assert "gmail.readonly" in scope
    for write_scope in ("gmail.send", "gmail.compose", "gmail.modify"):
        assert write_scope not in scope, f"{write_scope} granted to a read-only alias"


def test_read_write_alias_still_requests_write_scopes(read_only_work):
    with TestClient(server.app) as c:
        r = c.get("/personal/authorize", follow_redirects=False, params={
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "code_challenge": "abc123",
        })
    scope = parse_qs(urlparse(r.headers["location"]).query)["scope"][0]
    assert "gmail.send" in scope


def test_discovery_through_alias_points_authorize_at_that_alias(read_only_work):
    with TestClient(server.app) as c:
        meta = c.get("/work/.well-known/oauth-authorization-server").json()
        bare = c.get("/.well-known/oauth-authorization-server").json()
    assert meta["authorization_endpoint"] == f"{server.BASE_URL}/work/authorize"
    assert bare["authorization_endpoint"] == f"{server.BASE_URL}/authorize"


def test_protected_resource_identifies_the_aliased_resource(read_only_work):
    with TestClient(server.app) as c:
        assert c.get("/work/.well-known/oauth-protected-resource").json()["resource"] \
            == f"{server.BASE_URL}/work/mcp"
        assert c.get("/.well-known/oauth-protected-resource").json()["resource"] \
            == f"{server.BASE_URL}/mcp"


def test_401_challenge_carries_the_alias(read_only_work):
    with TestClient(server.app) as c:
        r = c.post("/work/mcp", json={})
    assert r.status_code == 401
    assert "/work/.well-known/oauth-protected-resource" in r.headers["www-authenticate"]


@respx.mock
def test_read_write_grant_is_still_read_only_at_a_read_only_alias(
        read_only_work, monkeypatch):
    """The property the redesign exists for.

    A session whose JWT says read_only=False — e.g. issued before the alias was added
    to READ_ONLY_ALIASES, or through a client that never sent the alias at all — must
    still be refused writes when the request arrives at /work/mcp. The decision is
    derived from our own routing, so no client behaviour can opt out of it.
    """
    spy = _ReadOnlySpy()
    monkeypatch.setattr(server, "_read_only", spy)
    token = _session_jwt(read_only=False)

    with TestClient(server.app) as c:
        c.post("/work/mcp", json={}, headers={"Authorization": f"Bearer {token}"})

    assert spy.values == [True], (
        f"expected the read-only alias to force read-only, got {spy.values}")


@respx.mock
def test_unaliased_connector_keeps_write_access(read_only_work, monkeypatch):
    spy = _ReadOnlySpy()
    monkeypatch.setattr(server, "_read_only", spy)
    token = _session_jwt(read_only=False)

    with TestClient(server.app) as c:
        c.post("/mcp", json={}, headers={"Authorization": f"Bearer {token}"})

    assert spy.values == [False]


@respx.mock
def test_read_only_grant_stays_read_only_at_any_alias(read_only_work, monkeypatch):
    """A read-only JWT presented at a read/write alias must stay read-only —
    the grant it was issued under only ever had read scopes from Google."""
    spy = _ReadOnlySpy()
    monkeypatch.setattr(server, "_read_only", spy)
    token = _session_jwt(read_only=True)

    with TestClient(server.app) as c:
        c.post("/personal/mcp", json={}, headers={"Authorization": f"Bearer {token}"})

    assert spy.values == [True]


def test_resource_param_is_honoured_as_a_fallback(read_only_work):
    """Clients that only fetch unaliased discovery still get the narrowed Google
    grant, via the RFC 8707 resource parameter."""
    with TestClient(server.app) as c:
        r = c.get("/authorize", follow_redirects=False, params={
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "code_challenge": "abc123",
            "resource": f"{server.BASE_URL}/work/mcp",
        })
    scope = parse_qs(urlparse(r.headers["location"]).query)["scope"][0]
    assert "gmail.send" not in scope


def test_read_only_survives_the_full_oauth_round_trip(read_only_work):
    """/work/authorize -> Google -> /auth/callback -> /token, and the minted JWT
    carries read_only so enforcement holds even without the alias in the path."""
    with respx.mock:
        respx.post("https://oauth2.googleapis.com/token").mock(
            return_value=httpx.Response(200, json={
                "access_token": "at", "refresh_token": "rt", "expires_in": 3600}))
        respx.get("https://www.googleapis.com/oauth2/v3/userinfo").mock(
            return_value=httpx.Response(200, json={"email": "work@example.com"}))

        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        import base64
        import hashlib
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()

        with TestClient(server.app) as c:
            r = c.get("/work/authorize", follow_redirects=False, params={
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "code_challenge": challenge,
            })
            state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
            r = c.get("/auth/callback", follow_redirects=False,
                      params={"code": "gc", "state": state})
            code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
            r = c.post("/token", data={"code": code, "code_verifier": verifier,
                                       "grant_type": "authorization_code"})

    assert r.status_code == 200
    claims = jwt.decode(r.json()["access_token"], server.JWT_SECRET,
                        algorithms=["HS256"])
    assert claims["read_only"] is True
