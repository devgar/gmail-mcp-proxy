# Gmail MCP Server

Self-hosted [MCP](https://modelcontextprotocol.io) server that exposes Gmail and Google Calendar to Claude.ai (or any MCP client) via a standard OAuth 2.0 flow — no stored tokens, no pre-generated credentials.

## How it works

```
Claude.ai ──[OAuth]──► This server ──[OAuth]──► Google
Claude.ai ──[MCP]────► This server ──[Gmail API]──► Gmail / Calendar
```

The server acts as an OAuth proxy: it presents itself as an OAuth 2.0 authorization server to Claude, and internally delegates authentication to Google. After the user grants access, Google tokens are stored server-side (in memory) and injected per-request. A short-lived JWT is issued to Claude as the bearer token.

**Multiple accounts** — add the server twice in Claude with different alias URLs (`/personal/mcp`, `/work/mcp`). Each session is isolated; authenticate each with a different Google account.

## Tools

| Tool | Description |
|------|-------------|
| `get_profile` | Gmail account profile |
| `search_emails` | Search with Gmail operators (`from:`, `subject:`, `has:attachment`, …). The first `enrich_limit` results (default 25) also include from/to/subject/date/snippet/labels. |
| `read_message` | Full message with decoded body |
| `read_thread` | Full thread |
| `send_email` | Send or reply to a thread |
| `create_draft` | Save a draft |
| `list_drafts` | List drafts |
| `send_draft` | Send an existing draft |
| `update_draft` | Replace the content of an existing draft |
| `delete_draft` | Permanently delete a draft |
| `list_labels` | All Gmail labels |
| `create_label` | Create a new label |
| `update_label` | Rename or change visibility of a label |
| `delete_label` | Permanently delete a label |
| `modify_labels` | Add/remove labels on a message |
| `report_phishing` | Mark a message as spam |
| `trash_message` | Move to trash |
| `list_calendars` | All calendars |
| `list_events` | Events with optional time range filter |
| `search_events` | Search events by keyword |
| `get_event` | Single event by ID |

## Prerequisites

- Python 3.12+ (or Docker — a `Dockerfile` is included)
- A reverse proxy that terminates HTTPS in front of the server's port `8000`
- A Google Cloud project with:
  - **Gmail API** and **Google Calendar API** enabled
  - An OAuth 2.0 **Web application** client
  - Authorized redirect URI: `https://<your-domain>/gmail/auth/callback`

## Setup

### 1. Google Cloud

1. Go to [console.cloud.google.com](https://console.cloud.google.com) → APIs & Services → Credentials
2. Create an **OAuth 2.0 Client ID** (type: Web application)
3. Add `https://<your-domain>/gmail/auth/callback` to **Authorized redirect URIs**
4. Copy the Client ID and Client Secret

### 2. Deploy

```bash
git clone https://github.com/devgar/gmail-mcp-proxy
cd gmail-mcp-proxy

cp .env.example .env
# Fill in GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
# JWT_SECRET can be any long random string: openssl rand -hex 32
# BASE_URL should be https://<your-domain>/gmail
```

Run it however you prefer — the server listens on port `8000`:

```bash
# With Python directly
pip install -r requirements.txt
set -a && . ./.env && set +a   # load the variables from .env
python server.py

# Or with the included Dockerfile
docker build -t gmail-mcp .
docker run -d --env-file .env -p 8000:8000 gmail-mcp
```

Put it behind any reverse proxy that terminates HTTPS (Caddy, nginx, Traefik, …) and forwards `https://<your-domain>/gmail` to port `8000`.

#### Docker Compose example

A minimal `compose.yml` to run the container — uncomment the labels for whichever proxy you use:

```yaml
services:
  gmail-mcp:
    build: .
    # image: gmail-mcp           # or a prebuilt image instead of build
    env_file: .env
    restart: unless-stopped
    # expose the port only if your proxy reaches it directly (not via a shared network)
    # ports:
    #   - "8000:8000"

    labels:
      # ── caddy-docker-proxy ────────────────────────────────────────────────
      # caddy: your-domain.com
      # caddy.handle_path: /gmail*
      # caddy.handle_path.reverse_proxy: "{{upstreams 8000}}"

      # ── Traefik (strips the /gmail prefix before forwarding) ──────────────
      # traefik.enable: "true"
      # traefik.http.routers.gmail-mcp.rule: "Host(`your-domain.com`) && PathPrefix(`/gmail`)"
      # traefik.http.routers.gmail-mcp.tls.certresolver: "le"
      # traefik.http.routers.gmail-mcp.middlewares: "gmail-strip"
      # traefik.http.middlewares.gmail-strip.stripprefix.prefixes: "/gmail"
      # traefik.http.services.gmail-mcp.loadbalancer.server.port: "8000"
```

With **nginx** (no labels — point a `location` block at the container):

```nginx
location /gmail/ {
    proxy_pass http://gmail-mcp:8000/;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Note: `BASE_URL` must match the public path the proxy serves (e.g. `https://your-domain.com/gmail`), since the server builds its OAuth redirect URIs from it.

#### Deploying to Railway / Render

On a PaaS platform (Railway, Render, etc.) there's no path prefix or reverse proxy to
configure — the platform gives the container its own domain and terminates HTTPS itself:

1. Create a new service from this repo (the `Dockerfile` is detected automatically).
2. Generate a public domain for the service, e.g. `your-app.up.railway.app`.
3. Set `BASE_URL` to that bare domain — `https://your-app.up.railway.app`, no path suffix.
4. Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `JWT_SECRET` as usual (see
   Configuration below).
5. Use `https://your-app.up.railway.app/auth/callback` as the Authorized redirect URI
   in the Google Cloud OAuth client.

The server reads the platform-injected `PORT` env var automatically, so no port
configuration is needed.

### 3. Connect to Claude.ai

In Claude.ai → Settings → Integrations → Add MCP server:

| Field | Value |
|-------|-------|
| URL | `https://<your-domain>/gmail/mcp` |
| OAuth Client ID | your Google client ID |
| OAuth Client Secret | your Google client secret |

Click **Connect** and authenticate with your Google account.

**Two accounts:** add a second connector with URL `https://<your-domain>/gmail/work/mcp` (any alias works — `/personal/mcp`, `/work/mcp`, etc.) and authenticate with the second account. Both share the same server and OAuth flow.

## Configuration

| Variable | Description |
|----------|-------------|
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `JWT_SECRET` | Secret for signing session JWTs (any random string) |
| `BASE_URL` | Public base URL, e.g. `https://example.com/gmail` (no trailing slash) |
| `ALLOWED_REDIRECT_URIS` | Optional. Comma-separated allowlist of OAuth redirect URIs `/authorize` will accept. Defaults to Claude.ai's callback (`https://claude.ai/api/mcp/auth_callback`) — only change this if you're connecting a non-Claude.ai MCP client. |
| `LOG_LEVEL` | Optional. Python logging level (`INFO`, `WARNING`, `DEBUG`, etc.). Defaults to `INFO`. |

## Development

```bash
pip install -r requirements-dev.txt
pytest          # test suite
ruff check .    # lint
mypy            # type check (config in pyproject.toml)
```

All three run in CI on every push and pull request, against Python 3.12 (the version the
Docker image uses), 3.13 and 3.14.

Tests mock all Gmail/Calendar API calls (via `respx`) and cover the pure-logic helpers
(PKCE, alias path normalisation, MIME building) plus the behaviour that's easy to get
wrong — deeply nested MIME bodies, reply threading, token-refresh races and revoked
refresh tokens, and expiry-based store cleanup. No live Google credentials needed.

## Notes

- Sessions are stored in memory — a server restart requires re-authentication in Claude.ai
- Google access tokens are refreshed automatically using the stored refresh token
- The server issues 30-day JWTs; Claude re-authenticates when they expire
