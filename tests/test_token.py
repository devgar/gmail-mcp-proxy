"""Tests for the /token endpoint's handling of malformed grant requests."""
import time

import pytest
from starlette.testclient import TestClient

import server


@pytest.fixture(autouse=True)
def _code(monkeypatch):
    server._code_store["thecode"] = {
        "jti": "j1", "email": "a@example.com",
        "code_challenge": "somechallenge", "created": time.time(),
    }
    yield
    server._code_store.pop("thecode", None)


def test_token_rejects_multipart_form_values_cleanly():
    """Regression test, found by mypy: Starlette form values are `UploadFile | str`, so a
    multipart POST to /token used to reach _pkce_ok with an UploadFile and crash on
    .encode() — an unhandled 500 on an unauthenticated endpoint."""
    with TestClient(server.app) as c:
        r = c.post("/token",
                   data={"code": "thecode", "grant_type": "authorization_code"},
                   files={"code_verifier": ("v.txt", b"whatever", "text/plain")})
    assert r.status_code == 400
    assert r.json() == {"error": "invalid_grant"}


def test_token_rejects_missing_verifier():
    with TestClient(server.app) as c:
        r = c.post("/token", data={"code": "thecode",
                                   "grant_type": "authorization_code"})
    assert r.status_code == 400
    assert r.json() == {"error": "invalid_grant"}


def test_token_rejects_unknown_code():
    with TestClient(server.app) as c:
        r = c.post("/token", data={"code": "nope", "code_verifier": "v",
                                   "grant_type": "authorization_code"})
    assert r.status_code == 400
