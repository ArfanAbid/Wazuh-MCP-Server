# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the Project

Two processes must run separately, MCP server first:

```
uv run python -m src.main        # MCP server — port 8000, start this first
uv run python app/main.py        # Chat API  — port 8001, requires MCP server running
```

**Testing scripts:**
```
uv run python -m test.check_server    # verify Wazuh Manager auth + agent fetch
uv run python -m test.check_indexer   # verify Wazuh Indexer connection + alert queries
uv run python -m test.debug_tool      # debug individual tool calls
```

There is no formal test suite — testing is done via the scripts in `test/`.

## Environment Setup

Copy `.env.example` to `.env` and fill in:

```
# Wazuh Manager (required)
WAZUH_URL=https://your-wazuh-manager:55000
WAZUH_USER=your-username
WAZUH_PASS=your-password
WAZUH_SSL_VERIFY=false
WAZUH_TIMEOUT=30

# MCP Server
MCP_SERVER_HOST=127.0.0.1
MCP_SERVER_PORT=8000
LOG_LEVEL=INFO

# Wazuh Indexer / OpenSearch (optional — activates 6 alert tools when set)
WAZUH_INDEXER_URL=https://your-indexer:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=your-password
WAZUH_INDEXER_SSL_VERIFY=false

# LLM (required only for app/main.py)
OPENAI_API_KEY=sk-...
GROQ_API_KEY=gsk_...
```

Tool filtering (optional):
```
WAZUH_DISABLED_TOOLS=GetRuleFileContentTool,AuthenticateTool
WAZUH_DISABLED_CATEGORIES=syscollector,sca,rules,indexer
WAZUH_READ_ONLY=false
```

## Architecture

Three-layer system with two independent backend connections:

```
User / Claude Desktop / Chat API
         ↓ MCP (SSE)
   WazuhMCPServer (port 8000)
    ↙                    ↘
WazuhClient          WazuhIndexerClient
JWT auth             Basic Auth
Wazuh Manager        Wazuh Indexer
REST API :55000      OpenSearch :9200
```

**`WazuhClient`** ([src/client.py](src/client.py)) — JWT lifecycle: auto-refreshes token every 15 min via `POST /security/user/authenticate`. Used by all Manager tools.

**`WazuhIndexerClient`** ([src/indexer_client.py](src/indexer_client.py)) — HTTP Basic Auth on every request. Three methods: `search(query_dsl)`, `count(query_dsl)`, `get_by_id(doc_id)`. Only instantiated when `WAZUH_INDEXER_URL` is set.

**`WazuhMCPServer`** ([src/server.py](src/server.py)) — holds both clients lazily (`_get_client()`, `_get_indexer_client()`). Registers tool modules in `_register_tools()`, guarding each with `disabled_tools`/`disabled_categories` checks. Indexer tools are additionally guarded by `if self.config.indexer`.

**Chat API** ([app/main.py](app/main.py)) — standalone FastAPI app. On startup connects to the MCP server via `MultiServerMCPClient`, loads all registered tools, and runs a LangChain GPT-4o agent loop per `/chat` request.

## Key Files

- [src/config.py](src/config.py) — `WazuhConfig`, `IndexerConfig`, `ServerConfig`, `Config` dataclasses. `Config.from_env()` only creates `IndexerConfig` if `WAZUH_INDEXER_URL` is set, making the indexer fully opt-in.
- [src/server.py](src/server.py) — `WazuhMCPServer._register_tools()` is the single place that wires tool modules to the FastMCP app.
- [src/tools/wazuh_manager/](src/tools/wazuh_manager/) — 5 files, each exports `register_*_tools(app, get_client, safe_truncate)`.
- [src/tools/wazuh_indexer/alert_tools.py](src/tools/wazuh_indexer/alert_tools.py) — 6 alert tools. Shares a `_build_filters()` helper that constructs the OpenSearch `bool.filter` array.

## Adding New Tools

**Manager tool** (talks to Wazuh REST API):
1. Add a file to `src/tools/wazuh_manager/` with a `register_*_tools(app, get_client_func, safe_truncate_func)` function.
2. Decorate each handler with `@app.tool(name=..., description=...)`.
3. Call `get_client_func()` inside the handler to get `WazuhClient`.
4. Import and call your register function in `server.py`'s `_register_tools()`, guarded by the disabled-tools check.

**Indexer tool** (queries OpenSearch):
Same pattern but use `get_indexer_client_func()` to get `WazuhIndexerClient`, call `client.search(dsl)` / `client.count(dsl)`, and register under the `if self.config.indexer` block in `server.py`.

## Tool Response Pattern

All tools return: `[{"type": "text", "text": safe_truncate_func(json.dumps(data, indent=2))}]`

`safe_truncate` caps output at **32,000 characters**. Most Manager tools default `limit=500` — this hits the cap on busy systems. Indexer search tools default to `limit=50`.

## Chat API Endpoints

- `GET /` — status
- `GET /health` — readiness (503 if LLM or MCP client not ready)
- `GET /tools` — list all loaded MCP tools
- `POST /chat` — `{"message": "...", "session_id": "...", "model": "gpt-4o"}` → response + tool call trace
