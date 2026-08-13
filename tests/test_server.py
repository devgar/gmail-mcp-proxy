import asyncio
import base64
import json
import time

import httpx
import pytest
import respx

import server


def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


@pytest.fixture(autouse=True)
async def http_client():
    server._http_client = httpx.AsyncClient(timeout=5)
    server._google_token.set("fake-token")
    yield
    await server._http_client.aclose()
    server._http_client = None


@respx.mock
async def test_read_message_prefers_plain_over_html():
    payload = {
        "id": "123", "threadId": "t123", "snippet": "hi", "labelIds": ["INBOX"],
        "payload": {
            "headers": [{"name": "From", "value": "a@example.com"}],
            "mimeType": "multipart/alternative",
            "parts": [
                {"mimeType": "text/plain", "body": {"data": _b64("plain body")}},
                {"mimeType": "text/html", "body": {"data": _b64("<p>html body</p>")}},
            ],
        },
    }
    respx.get(f"{server.GMAIL}/messages/123").mock(return_value=httpx.Response(200, json=payload))

    result = await server.read_message("123")

    assert result["body"] == "plain body"


@respx.mock
async def test_read_message_falls_back_to_html_when_no_plain_part():
    payload = {
        "id": "123", "threadId": "t123", "snippet": "hi", "labelIds": ["INBOX"],
        "payload": {
            "headers": [],
            "mimeType": "text/html",
            "body": {"data": _b64("<p>only html</p>")},
        },
    }
    respx.get(f"{server.GMAIL}/messages/123").mock(return_value=httpx.Response(200, json=payload))

    result = await server.read_message("123")

    assert result["body"] == "<p>only html</p>"


@respx.mock
async def test_read_message_finds_deeply_nested_plain_body():
    # Regression test: the previous single-level scan of payload["parts"] returned an
    # empty body for any message whose text/plain part sat below the first level.
    payload = {
        "id": "123", "threadId": "t123", "snippet": "hi", "labelIds": [],
        "payload": {
            "headers": [],
            "mimeType": "multipart/mixed",
            "parts": [
                {"mimeType": "application/pdf", "body": {"attachmentId": "att1"}},
                {
                    "mimeType": "multipart/alternative",
                    "parts": [
                        {"mimeType": "text/plain", "body": {"data": _b64("buried plain")}},
                        {"mimeType": "text/html", "body": {"data": _b64("<p>buried</p>")}},
                    ],
                },
            ],
        },
    }
    respx.get(f"{server.GMAIL}/messages/123").mock(return_value=httpx.Response(200, json=payload))

    result = await server.read_message("123")

    assert result["body"] == "buried plain"


@respx.mock
async def test_send_email_raises_when_reply_lookup_fails():
    # Regression test: a failed reply lookup used to fall through and send the message
    # as a standalone email, silently losing the threading the caller asked for.
    respx.get(f"{server.GMAIL}/messages/missing").mock(return_value=httpx.Response(404))
    send_route = respx.post(f"{server.GMAIL}/messages/send").mock(
        return_value=httpx.Response(200, json={"id": "sent"})
    )

    with pytest.raises(httpx.HTTPStatusError):
        await server.send_email("a@example.com", "Hi", "body",
                                reply_to_message_id="missing")

    assert not send_route.called, "must not send anything when the reply lookup failed"


@respx.mock
async def test_send_email_threads_reply_with_standard_headers():
    respx.get(f"{server.GMAIL}/messages/orig").mock(return_value=httpx.Response(200, json={
        "threadId": "thread-1",
        "payload": {"headers": [
            {"name": "Message-ID", "value": "<msg1@mail>"},
            {"name": "References", "value": "<msg0@mail>"},
        ]},
    }))
    send_route = respx.post(f"{server.GMAIL}/messages/send").mock(
        return_value=httpx.Response(200, json={"id": "sent"})
    )

    await server.send_email("a@example.com", "Re: Hi", "body",
                            reply_to_message_id="orig")

    payload = json.loads(send_route.calls.last.request.content)
    body = base64.urlsafe_b64decode(payload["raw"] + "==").decode()
    assert payload["threadId"] == "thread-1"
    assert "In-Reply-To: <msg1@mail>" in body
    assert "References: <msg0@mail> <msg1@mail>" in body


@respx.mock
async def test_refresh_raises_reauth_required_on_revoked_token():
    # Regression test: Google answers a revoked refresh token with 400 +
    # {"error": "invalid_grant"}, which used to surface as an unhandled KeyError.
    server._token_store["jti-1"] = {
        "access_token": "old", "refresh_token": "revoked",
        "expiry": 0, "email": "a@example.com",
    }
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(400, json={"error": "invalid_grant"})
    )
    try:
        with pytest.raises(server.ReauthRequired):
            await server._google_access_token("jti-1")
        # The dead session and its lock are dropped rather than left to leak.
        assert "jti-1" not in server._token_store
        assert "jti-1" not in server._refresh_locks
    finally:
        server._token_store.pop("jti-1", None)
        server._refresh_locks.pop("jti-1", None)


@respx.mock
async def test_concurrent_refresh_fires_one_grant():
    # Regression test: two requests hitting an expired token used to fire two
    # refresh_token grants concurrently; Google can reject the second as reused.
    server._token_store["jti-2"] = {
        "access_token": "old", "refresh_token": "rt",
        "expiry": 0, "email": "a@example.com",
    }
    route = respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(200, json={"access_token": "new", "expires_in": 3600})
    )
    try:
        results = await asyncio.gather(*(server._google_access_token("jti-2")
                                         for _ in range(5)))
        assert results == ["new"] * 5
        assert route.call_count == 1, f"expected 1 refresh grant, got {route.call_count}"
    finally:
        server._token_store.pop("jti-2", None)
        server._refresh_locks.pop("jti-2", None)


def test_purge_expired_states_drops_stale_entries_only():
    server._state_store.clear()
    server._code_store.clear()
    server._state_store["fresh"] = {"created": time.time()}
    server._state_store["stale"] = {"created": time.time() - server.STATE_TTL - 1}
    server._code_store["fresh"] = {"created": time.time()}
    server._code_store["stale"] = {"created": time.time() - server.STATE_TTL - 1}

    server._purge_expired_states()

    assert set(server._state_store) == {"fresh"}
    assert set(server._code_store) == {"fresh"}
    server._state_store.clear()
    server._code_store.clear()


@respx.mock
async def test_delete_draft_handles_204_no_content():
    # drafts.delete answers 204 with an empty body, so calling .json() the way the
    # other write tools do would raise instead of reporting success.
    respx.delete(f"{server.GMAIL}/drafts/abc").mock(return_value=httpx.Response(204))

    assert await server.delete_draft("abc") == {"deleted": "abc"}


@respx.mock
async def test_delete_label_handles_204_no_content():
    respx.delete(f"{server.GMAIL}/labels/Label_1").mock(return_value=httpx.Response(204))

    assert await server.delete_label("Label_1") == {"deleted": "Label_1"}


@respx.mock
async def test_delete_draft_still_raises_on_real_error():
    respx.delete(f"{server.GMAIL}/drafts/abc").mock(return_value=httpx.Response(404))

    with pytest.raises(httpx.HTTPStatusError):
        await server.delete_draft("abc")


@respx.mock
async def test_update_label_sends_only_provided_fields():
    # PATCH semantics: omitting a field must leave it untouched rather than blanking it.
    route = respx.patch(f"{server.GMAIL}/labels/Label_1").mock(
        return_value=httpx.Response(200, json={"id": "Label_1", "name": "Renamed"})
    )

    await server.update_label("Label_1", name="Renamed")

    assert json.loads(route.calls.last.request.content) == {"name": "Renamed"}


@respx.mock
async def test_update_draft_replaces_content():
    route = respx.put(f"{server.GMAIL}/drafts/d1").mock(
        return_value=httpx.Response(200, json={"id": "d1"})
    )

    await server.update_draft("d1", "a@example.com", "New subject", "new body")

    raw = json.loads(route.calls.last.request.content)["message"]["raw"]
    decoded = base64.urlsafe_b64decode(raw + "==").decode()
    assert "New subject" in decoded and "new body" in decoded


@respx.mock
async def test_report_phishing_moves_message_to_spam():
    route = respx.post(f"{server.GMAIL}/messages/m1/modify").mock(
        return_value=httpx.Response(200, json={"id": "m1"})
    )

    await server.report_phishing("m1")

    assert json.loads(route.calls.last.request.content) == {
        "addLabelIds": ["SPAM"], "removeLabelIds": ["INBOX"],
    }


@respx.mock
async def test_search_emails_enriches_results_with_headers():
    respx.get(f"{server.GMAIL}/messages").mock(return_value=httpx.Response(200, json={
        "messages": [{"id": "1", "threadId": "t1"}],
    }))
    respx.get(f"{server.GMAIL}/messages/1").mock(return_value=httpx.Response(200, json={
        "snippet": "hello there", "labelIds": ["INBOX"],
        "payload": {"headers": [
            {"name": "From", "value": "a@example.com"},
            {"name": "Subject", "value": "Lunch"},
        ]},
    }))

    results = await server.search_emails("test query")

    assert results[0]["from"] == "a@example.com"
    assert results[0]["subject"] == "Lunch"
    assert results[0]["snippet"] == "hello there"
    assert results[0]["labels"] == ["INBOX"]


@respx.mock
async def test_search_emails_degrades_gracefully_on_network_error():
    # Regression test: a network-level exception enriching one message used to fail the
    # whole search instead of falling back to bare id/threadId for that one message.
    respx.get(f"{server.GMAIL}/messages").mock(return_value=httpx.Response(200, json={
        "messages": [{"id": "1", "threadId": "t1"}, {"id": "2", "threadId": "t2"}],
    }))
    respx.get(f"{server.GMAIL}/messages/1").mock(return_value=httpx.Response(200, json={
        "snippet": "hi", "labelIds": [],
        "payload": {"headers": [{"name": "From", "value": "a@example.com"}]},
    }))
    respx.get(f"{server.GMAIL}/messages/2").mock(side_effect=httpx.ConnectTimeout("boom"))

    results = await server.search_emails("test query")

    assert len(results) == 2
    assert next(r for r in results if r["id"] == "1")["from"] == "a@example.com"
    assert "from" not in next(r for r in results if r["id"] == "2")


@respx.mock
async def test_search_emails_degrades_on_http_error_status():
    respx.get(f"{server.GMAIL}/messages").mock(return_value=httpx.Response(200, json={
        "messages": [{"id": "1", "threadId": "t1"}]}))
    respx.get(f"{server.GMAIL}/messages/1").mock(return_value=httpx.Response(500))

    assert await server.search_emails("q") == [{"id": "1", "threadId": "t1"}]


@respx.mock
async def test_search_emails_enrich_limit_zero_skips_enrichment():
    respx.get(f"{server.GMAIL}/messages").mock(return_value=httpx.Response(200, json={
        "messages": [{"id": "1", "threadId": "t1"}]}))
    detail = respx.get(f"{server.GMAIL}/messages/1")

    results = await server.search_emails("q", enrich_limit=0)

    assert results == [{"id": "1", "threadId": "t1"}]
    assert not detail.called, "enrich_limit=0 must not fetch any message metadata"


@respx.mock
async def test_search_emails_enriches_only_up_to_limit():
    msgs = [{"id": str(i), "threadId": f"t{i}"} for i in range(5)]
    respx.get(f"{server.GMAIL}/messages").mock(
        return_value=httpx.Response(200, json={"messages": msgs}))
    for i in range(5):
        respx.get(f"{server.GMAIL}/messages/{i}").mock(return_value=httpx.Response(
            200, json={"snippet": "s", "labelIds": [], "payload": {"headers": []}}))

    results = await server.search_emails("q", enrich_limit=2)

    assert [("snippet" in r) for r in results] == [True, True, False, False, False]


@respx.mock
async def test_search_emails_clamps_enrich_limit_to_ceiling():
    # A caller asking for 500 must not fan out into 500 concurrent Gmail calls.
    msgs = [{"id": str(i), "threadId": f"t{i}"} for i in range(server.SEARCH_ENRICH_MAX + 10)]
    respx.get(f"{server.GMAIL}/messages").mock(
        return_value=httpx.Response(200, json={"messages": msgs}))
    detail = respx.get(url__regex=rf"{server.GMAIL}/messages/\d+").mock(
        return_value=httpx.Response(200, json={"snippet": "s", "labelIds": [],
                                               "payload": {"headers": []}}))

    await server.search_emails("q", enrich_limit=500)

    assert detail.call_count == server.SEARCH_ENRICH_MAX
