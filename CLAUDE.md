# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the Project

This project has two independent processes that must run separately:

**1. MCP Server** (start first, port 8000):
```
uv run python -m src.main
```

**2. Chat API** (requires MCP server running, port 8001):
```
uv run python app/main.py
```

**Manual testing scripts:**
```
uv run python -m test.check_server   # verify MCP server connectivity
uv run python -m test.debug_tool     # debug individual tools
```

There is no formal test suite — testing is done via the scripts in `test/`.

## Environment Setup

Copy `.env.example` to `.env` and fill in:

```
WAZUH_URL=https://your-wazuh-manager:55000
WAZUH_USER=your-username
WAZUH_PASS=your-password
WAZUH_SSL_VERIFY=false          # set false for self-signed certs
WAZUH_TIMEOUT=30
MCP_SERVER_HOST=127.0.0.1
MCP_SERVER_PORT=8000
LOG_LEVEL=INFO
OPENAI_API_KEY=sk-...           # required only for app/main.py
GROQ_API_KEY=gsk_...            # optional alternative LLM
```

Tool filtering (optional):
```
WAZUH_DISABLED_TOOLS=DeleteAgentTool,RestartManagerTool
WAZUH_DISABLED_CATEGORIES=dangerous,write
WAZUH_READ_ONLY=false
```

## Architecture

This is a two-tier system:

**Tier 1 — MCP Server** (`src/`): Exposes Wazuh SIEM operations as MCP tools over HTTP/SSE using [FastMCP](https://github.com/jlowin/fastmcp). It authenticates with the Wazuh REST API using JWT tokens (auto-managed by `WazuhClient`) and wraps responses as tool results.

**Tier 2 — Chat API** (`app/main.py`): A FastAPI service that connects to the MCP server at startup via `MultiServerMCPClient`, loads all registered tools, and uses a LangChain agent loop with OpenAI GPT-4o to answer natural language queries by orchestrating tool calls.

```
User → POST /chat (port 8001)
  → LangChain agent loop (GPT-4o)
    → MCP tool calls (SSE to port 8000)
      → WazuhClient (JWT) → Wazuh REST API
```

The two tiers are decoupled: the MCP server can be used independently by any MCP-compatible client (Claude Desktop, etc.), not just the chat API.

## Key Files

- [src/config.py](src/config.py) — `Config`, `WazuhConfig`, `ServerConfig` dataclasses; all env var loading lives here.
- [src/client.py](src/client.py) — Async HTTP client wrapping the Wazuh REST API with JWT token lifecycle management.
- [src/server.py](src/server.py) — `WazuhMCPServer`: creates the `FastMCP` instance, conditionally registers tool modules based on `disabled_tools`/`disabled_categories` config, exposes `sse_app` for uvicorn.
- [src/tools/wazuh_manager/](src/tools/wazuh_manager/) — One file per tool category. Each exports a `register_*_tools(app, get_client, truncate)` function called by `server.py`.
- [app/main.py](app/main.py) — Self-contained FastAPI app; connects to the MCP server on startup and runs the LangChain agent loop per request.

## Adding New Tools

Each tool module follows the same pattern: define a `register_*_tools(app, get_client, safe_truncate)` function, decorate handlers with `@app.tool()`, and call `get_client()` inside each handler to obtain the `WazuhClient`. Then import and call your register function from `server.py`'s `_register_tools` method, guarding it with the disabled-tools check.

## Chat API Endpoints

- `GET /` — health check
- `GET /health` — readiness check (503 if not initialized)
- `GET /tools` — list all MCP tools loaded at startup
- `POST /chat` — accepts `{"message": "...", "session_id": "...", "model": "gpt-4o"}`, returns response with tool call trace
