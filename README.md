# Wazuh MCP Server

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that connects AI assistants (Claude, GPT-4o, etc.) directly to your [Wazuh SIEM](https://wazuh.com) — both the **Wazuh Manager** (agents, rules, compliance, system inventory) and the **Wazuh Indexer** (live security alerts stored in OpenSearch). Ask questions about your infrastructure in plain English and get real-time answers backed by actual SIEM data.

---

## Architecture

The project has three layers that work together:

```
┌──────────────────────────────────────────────────────┐
│             You / AI Client                          │
│  Claude Desktop  ·  Chat API  ·  Custom Agent        │
└──────────────────────────┬───────────────────────────┘
                           │ MCP (SSE)
┌──────────────────────────▼───────────────────────────┐
│          Tier 1 — MCP Server  (port 8000)            │
│          FastMCP over HTTP/SSE                       │
│                                                      │
│  ┌─────────────────────┐  ┌───────────────────────┐  │
│  │  Manager Tools (10) │  │  Indexer Tools  (6)   │  │
│  │  agents · rules     │  │  search · count       │  │
│  │  SCA · syscollector │  │  aggregate · recent   │  │
│  └──────────┬──────────┘  └──────────┬────────────┘  │
└─────────────┼────────────────────────┼───────────────┘
              │ HTTPS + JWT            │ HTTPS + Basic Auth
┌─────────────▼──────────┐  ┌─────────▼──────────────┐
│   Wazuh Manager        │  │   Wazuh Indexer        │
│   REST API             │  │   OpenSearch REST API  │
│   port 55000           │  │   port 9200 / 9443     │
└────────────────────────┘  └────────────────────────┘
```

**Wazuh Manager** handles configuration and state — agent registration, detection rules, SCA benchmarks, and system inventory (packages, ports, processes).

**Wazuh Indexer** is an OpenSearch cluster that stores every security alert Wazuh fires. It holds the historical and real-time alert stream that security teams monitor.

**MCP Server** wraps both into a single MCP endpoint. Each data source authenticates differently: the Manager uses JWT tokens (auto-refreshed every 15 min), the Indexer uses HTTP Basic Auth on every request.

**Chat API** (optional, port 8001) is a FastAPI service with a LangChain GPT-4o agent loop. It connects to the MCP server on startup, loads all registered tools, and lets you query everything via a `/chat` endpoint.

---

## Prerequisites

- Python 3.12+
- [`uv`](https://docs.astral.sh/uv/getting-started/installation/) package manager (recommended) or `pip`
- A running Wazuh Manager with REST API accessible
- A running Wazuh Indexer (OpenSearch) — optional, enables alert tools
- OpenAI API key — only required for the Chat API

---

## Installation

```bash
git clone https://github.com/ArfanAbid/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

uv pip install -r requirements.txt
```

---

## Configuration

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Then fill in your values:

```env
# ── Wazuh Manager (required) ──────────────────────────────────────────
WAZUH_URL=https://your-wazuh-manager:55000
WAZUH_USER=your-username
WAZUH_PASS=your-password
WAZUH_SSL_VERIFY=false          # false for self-signed certificates
WAZUH_TIMEOUT=30

# ── Wazuh Indexer / OpenSearch (optional) ────────────────────────────
# When set, activates 6 additional alert query tools automatically.
WAZUH_INDEXER_URL=https://your-wazuh-indexer:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=your-indexer-password
WAZUH_INDEXER_SSL_VERIFY=false
WAZUH_INDEXER_TIMEOUT=30
# WAZUH_INDEXER_INDEX=wazuh-alerts-4.x-*    # default index pattern

# ── MCP Server ────────────────────────────────────────────────────────
MCP_SERVER_HOST=127.0.0.1
MCP_SERVER_PORT=8000

# ── LLM keys (only needed for app/main.py Chat API) ──────────────────
OPENAI_API_KEY=sk-...
GROQ_API_KEY=gsk_...            # optional alternative LLM provider

# ── Logging ───────────────────────────────────────────────────────────
LOG_LEVEL=INFO

# ── Tool filtering (optional) ─────────────────────────────────────────
# WAZUH_DISABLED_TOOLS=GetRuleFileContentTool,AuthenticateTool
# WAZUH_DISABLED_CATEGORIES=syscollector,sca,rules,indexer
# WAZUH_READ_ONLY=false
```

> The Indexer block is fully optional. If `WAZUH_INDEXER_URL` is not set, the server starts normally with only the 10 Manager tools registered.

---

## Running

### Step 1 — Start the MCP Server

```bash
uv run python -m src.main
```

Expected startup output:
```
Starting Wazuh MCP Server...
INFO  Starting Wazuh MCP Server on 127.0.0.1:8000
INFO  Wazuh URL: https://your-manager:55000
INFO  Wazuh Indexer alert tools registered (index: wazuh-alerts-4.x-*)
```

The SSE endpoint is available at `http://127.0.0.1:8000/sse/`

### Step 2 — Start the Chat API (optional)

Requires the MCP server already running.

```bash
uv run python app/main.py
```

Expected startup output:
```
Connecting to Wazuh MCP Server...
✓ Connected to MCP Server. Available tools: 16
  - SearchAlertsTool: Search Wazuh security alerts...
  - GetAgentsTool: Retrieve a list of Wazuh agents...
  ...
✓ OpenAI GPT Model initialized successfully
```

Swagger docs available at `http://127.0.0.1:8001/docs`

---

## Testing the Connection

### Test Wazuh Manager connectivity

```bash
uv run python -m test.check_server
```

Verifies authentication and fetches active agents directly from the Manager API.

### Test Wazuh Indexer connectivity

```bash
uv run python -m test.check_indexer
```

Runs 4 checks against the Indexer:
1. Total alert count in the index
2. 3 most recent alerts with timestamps
3. High-severity alert count (level ≥ 10) in last 24h
4. Top 5 agents by alert volume

---

## Available MCP Tools

The server exposes **16 tools** across 6 categories. The first 10 connect to the **Wazuh Manager**, the last 6 connect to the **Wazuh Indexer**.

---

### Authentication

| Tool | Parameters | Description |
|------|-----------|-------------|
| `AuthenticateTool` | none | Forces a fresh JWT token from the Wazuh Manager. Useful if you get auth errors mid-session. |

**Example questions:**
- *"Refresh the Wazuh authentication token"*

---

### Agent Management

| Tool | Key Parameters | Description |
|------|---------------|-------------|
| `GetAgentsTool` | `status`, `search`, `q`, `limit`, `offset`, `sort`, `select` | List all registered agents with optional filtering. Status values: `active`, `disconnected`, `never_connected`. The `q` param supports Wazuh query expressions like `name=web-server`. |

**Example questions:**
- *"Show me all active agents"*
- *"Which agents are currently disconnected?"*
- *"How many agents are registered in total?"*
- *"Find the agent named web-server"*
- *"List agents that have never connected"*

---

### System Inventory (Syscollector)

These tools query the Wazuh syscollector module which periodically scans each agent's system state.

| Tool | Key Parameters | Description |
|------|---------------|-------------|
| `GetAgentPortsTool` | `agent_id`*, `protocol`, `local_ip`, `local_port`, `state`, `process` | Open network ports on a specific agent. Filter by protocol (tcp/udp), port state (listening/established), or the process holding the port. |
| `GetAgentPackagesTool` | `agent_id`*, `name`, `vendor`, `version`, `architecture`, `format` | Installed software packages. Filter by package name, vendor, version, or format (deb/rpm). |
| `GetAgentProcessesTool` | `agent_id`*, `name`, `pid`, `state`, `euser`, `ppid`, `priority` | Running processes. Filter by process name, PID, run state, or the user running the process. |

*required parameter

**Example questions:**
- *"What ports are open on agent 001?"*
- *"Is port 22 listening on agent web-server?"*
- *"Show me all TCP connections on agent 003"*
- *"What packages are installed on agent 001?"*
- *"Is nginx installed on agent web-server and what version?"*
- *"List all packages from vendor OpenSSL on agent 002"*
- *"What processes are running on agent 001?"*
- *"Is there a process named malware.sh running anywhere?"*
- *"Show me all processes running as root on agent 003"*

---

### Rules Management

| Tool | Key Parameters | Description |
|------|---------------|-------------|
| `ListRulesTool` | `level`, `group`, `status`, `search`, `pci_dss`, `gdpr`, `hipaa`, `nist_800_53`, `mitre`, `rule_ids` | List Wazuh detection rules. The `level` field accepts a range like `"10-15"` for high severity. Filter by compliance framework to find all rules mapped to a specific standard. |
| `GetRuleFilesTool` | `status`, `filename`, `search` | List all rule XML files and whether they are enabled or disabled. |
| `GetRuleFileContentTool` | `filename`*, `raw` | Get the raw XML content of a specific rule file. Set `raw=true` for plain text output. |

**Example questions:**
- *"Show me all rules at level 12 or higher"*
- *"List all rules related to SSH brute force"*
- *"What rules are mapped to MITRE technique T1110?"*
- *"Show me all PCI DSS rules"*
- *"Which rules are currently disabled?"*
- *"List all rule files"*
- *"Show me the content of sshd_rules.xml"*

---

### Security Configuration Assessment (SCA)

SCA performs automated security benchmark scans against standards like CIS, PCI DSS, and NIST on each agent.

| Tool | Key Parameters | Description |
|------|---------------|-------------|
| `GetAgentSCATool` | `agent_id`*, `name`, `search` | Get the SCA scan summary for an agent — which policies have been checked and their overall pass/fail scores. |
| `GetSCAPolicyChecksTool` | `agent_id`*, `policy_id`*, `result`, `title`, `remediation` | Get individual check results for a specific SCA policy. Use `result=failed` to see only failing checks with their remediation steps. |

**Example questions:**
- *"What is the CIS compliance score for agent 001?"*
- *"Which security benchmarks has agent web-server been scanned against?"*
- *"Show me all failed SCA checks on agent 001"*
- *"What are the remediation steps for failed CIS checks on agent 003?"*
- *"How many SCA checks passed vs failed on agent 002?"*

---

### Alert Queries — Wazuh Indexer

These tools query OpenSearch directly where Wazuh stores all fired alerts. They are only active when `WAZUH_INDEXER_URL` is configured.

Time range parameters use OpenSearch date math: `now-1h`, `now-24h`, `now-7d`, `now-30d`, or an ISO date like `2024-01-01`.

| Tool | Key Parameters | Description |
|------|---------------|-------------|
| `SearchAlertsTool` | `query`, `agent_id`, `agent_name`, `rule_level_min`, `rule_level_max`, `rule_id`, `rule_group`, `mitre_id`, `time_from`, `time_to`, `limit`, `sort_order` | Full alert search with free-text plus structured filters. This is the main tool for investigating specific incidents. Rule levels run 1–15; levels ≥ 12 are high severity. |
| `GetRecentAlertsTool` | `limit`, `rule_level_min`, `agent_id` | Fetch the most recent N alerts, newest first. Quick way to see what's happening right now. |
| `CountAlertsTool` | `agent_id`, `rule_level_min`, `rule_group`, `time_from`, `time_to` | Returns a single integer count. Use this before `SearchAlertsTool` when you only need numbers — it costs a fraction of the tokens. |
| `GetTopAgentsByAlertsTool` | `time_from`, `time_to`, `size`, `rule_level_min` | Aggregation query that ranks agents by alert volume. Does not return individual alerts — returns a ranked list with counts. |
| `GetAlertsByRuleGroupTool` | `time_from`, `time_to`, `size`, `agent_id` | Aggregation query that ranks alert categories (rule groups) by frequency. Useful for understanding which threat types are most active. |
| `GetAlertByIdTool` | `alert_id`* | Retrieve one specific alert document by its OpenSearch document ID. Returns all fields. |

**Example questions:**
- *"Show me the 10 most recent alerts"*
- *"What alerts happened in the last hour?"*
- *"Show me all critical alerts (level 12+) today"*
- *"Find alerts related to SSH brute force in the last 6 hours"*
- *"Show me all alerts from agent web-server this week"*
- *"Find alerts with MITRE technique T1110"*
- *"Search for alerts mentioning failed login"*
- *"How many alerts were generated in the last 24 hours?"*
- *"How many critical alerts happened today?"*
- *"How many SSH-related alerts in the last hour?"*
- *"Which agents are generating the most alerts right now?"*
- *"What are the top 5 noisiest agents this week?"*
- *"Which attack categories are most active today?"*
- *"Break down today's alerts by threat type"*
- *"Give me a full security summary of agent 001"*

---

## Chat API Reference

### `POST /chat`

The main endpoint. Accepts a natural language question, runs the LangChain agent loop, calls whatever tools are needed, and returns a human-readable answer along with a trace of every tool call made.

**Request:**
```json
{
  "message": "Which agents have the most alerts in the last 24 hours?",
  "session_id": "optional-session-id",
  "model": "gpt-4o"
}
```

**Response:**
```json
{
  "response": "Based on the last 24 hours, the top agents by alert volume are:\n1. web-server-01 — 1,243 alerts\n2. db-server-02 — 876 alerts\n3. agent-003 — 412 alerts",
  "tool_calls": [
    {
      "tool": "GetTopAgentsByAlertsTool",
      "args": {"time_from": "now-24h", "size": 10},
      "result": "{\"top_agents\": [{\"agent\": \"web-server-01\", \"alert_count\": 1243}...]}"
    }
  ],
  "model_used": "gpt-4o"
}
```

**More example requests:**

```bash
# Alert investigation
curl -X POST http://127.0.0.1:8001/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Show me all critical alerts from the last hour"}'

# Agent inventory
curl -X POST http://127.0.0.1:8001/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Which agents are disconnected right now?"}'

# Compliance
curl -X POST http://127.0.0.1:8001/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Show me all failed SCA checks on agent 001 with remediation steps"}'

# Threat summary
curl -X POST http://127.0.0.1:8001/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Give me a full security summary of agent web-server"}'

# Rule investigation
curl -X POST http://127.0.0.1:8001/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What Wazuh rules are mapped to MITRE T1110 brute force technique?"}'
```

### `GET /tools`

Lists all MCP tools currently loaded with their names and descriptions.

```bash
curl http://127.0.0.1:8001/tools
```

### `GET /health`

Returns `200 OK` when both the LLM and MCP client are initialized, `503` if not ready.

### `GET /`

Basic status check — shows which components are online.

---

## Using with Claude Desktop

Connect Claude Desktop directly to the MCP server without needing the Chat API. Add to your Claude Desktop config file (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "wazuh": {
      "transport": "sse",
      "url": "http://127.0.0.1:8000/sse/"
    }
  }
}
```

Start the MCP server first, then restart Claude Desktop. All 16 tools will appear automatically in Claude's tool list. You can then ask Claude questions like:

- *"Use the Wazuh tools to check which agents are active"*
- *"Search for any critical alerts from the last hour"*
- *"What failed SCA checks does agent 001 have?"*

---

## Disabling Tools

Control which tools are registered at startup via environment variables. This is useful for read-only deployments or when you want to limit what the AI can access.

```env
# Disable specific tools by exact name (comma-separated)
WAZUH_DISABLED_TOOLS=GetRuleFileContentTool,AuthenticateTool

# Disable entire categories at once
# Available categories: syscollector, rules, sca, indexer
WAZUH_DISABLED_CATEGORIES=syscollector,sca

# Restrict to read-only mode (disables any write/mutating tools)
WAZUH_READ_ONLY=true
```

To disable all Indexer alert tools without removing `WAZUH_INDEXER_URL`:

```env
WAZUH_DISABLED_CATEGORIES=indexer
```

---

## Project Structure

```text
WAZUH-MCP/
├── __pycache__/                          # Python cache files
├── .venv/                                # Python virtual environment
│
├── app/                                  # Chat API (optional tier 2)
│   ├── __init__.py
│   └── main.py                           # FastAPI + LangChain GPT-4o agent loop
│
├── src/                                  # Core MCP server
│   ├── __init__.py
│   ├── client.py                         # Async Wazuh Manager API client (JWT auth)
│   ├── indexer_client.py                 # Async Wazuh Indexer client (Basic Auth)
│   ├── config.py                         # WazuhConfig, IndexerConfig, ServerConfig
│   ├── exceptions.py                     # Custom exception hierarchy
│   ├── main.py                           # Entry point — starts MCP server
│   ├── server.py                         # WazuhMCPServer — registers all tools
│   │
│   └── tools/
│       ├── wazuh_manager/                # Tools that talk to Wazuh Manager API
│       │   ├── agent_tools.py            # GetAgentsTool
│       │   ├── auth_tools.py             # AuthenticateTool
│       │   ├── rules_tools.py            # ListRulesTool, GetRuleFilesTool, GetRuleFileContentTool
│       │   ├── sca_tools.py              # GetAgentSCATool, GetSCAPolicyChecksTool
│       │   └── syscollector_tools.py     # GetAgentPortsTool, GetAgentPackagesTool, GetAgentProcessesTool
│       │
│       └── wazuh_indexer/                # Tools that query OpenSearch alerts
│           └── alert_tools.py            # SearchAlertsTool, GetRecentAlertsTool, CountAlertsTool,
│                                         # GetTopAgentsByAlertsTool, GetAlertsByRuleGroupTool, GetAlertByIdTool
│
├── test/                                 # Connectivity and verification scripts
│   ├── check_server.py                   # Tests Wazuh Manager auth + agent fetch
│   ├── check_indexer.py                  # Tests Indexer connection + 4 alert queries
│   └── debug_tool.py                     # Debug individual tool calls
│
├── .env                                  # Local environment variables (never commit)
├── .env.example                          # Template with all supported variables
├── .python-version                       # Python 3.12+
├── pyproject.toml                        # Project metadata
├── requirements.txt                      # Python dependencies
└── uv.lock                               # Locked dependency versions
```

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `fastmcp` | ≥0.4 | MCP server framework — handles SSE transport and tool registration |
| `httpx[http2]` | ≥0.27 | Async HTTP client for both Wazuh Manager and Indexer APIs |
| `fastapi` | ≥0.128 | Web framework for the Chat API |
| `uvicorn[standard]` | ≥0.30 | ASGI server |
| `langchain` | ≥1.2 | Agent loop orchestration |
| `langchain-openai` | ≥1.1.6 | GPT-4o integration |
| `langchain-groq` | ≥1.1.1 | Groq LLM integration (alternative) |
| `langchain-mcp-adapters` | ≥0.2.1 | Converts MCP tools into LangChain-compatible tools |
| `pydantic` | ≥2.7 | Tool argument validation and config dataclasses |
| `python-dotenv` | ≥1.0 | `.env` file loading |
