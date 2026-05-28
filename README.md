# Wazuh MCP Server

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that exposes your [Wazuh SIEM](https://wazuh.com) data as callable tools — so AI assistants (Claude, GPT-4o, etc.) can query agents, rules, security compliance, and system inventory in real time. Includes an optional FastAPI chat interface that lets you ask questions about your infrastructure in plain English.

---

## How It Works

The project has two independent tiers:

```
┌─────────────────────────────────────┐
│  Tier 2 — Chat API  (port 8001)     │
│  FastAPI + LangChain + GPT-4o       │
│  Natural language → tool calls      │
└────────────────┬────────────────────┘
                 │ SSE (MCP protocol)
┌────────────────▼────────────────────┐
│  Tier 1 — MCP Server  (port 8000)   │
│  FastMCP over HTTP/SSE              │
│  10 tools across 5 categories       │
└────────────────┬────────────────────┘
                 │ HTTPS + JWT
┌────────────────▼────────────────────┐
│  Wazuh Manager  (your SIEM)         │
│  REST API on port 55000             │
└─────────────────────────────────────┘
```

**Tier 1 (MCP Server)** is the core. It authenticates with the Wazuh REST API using auto-managed JWT tokens (refreshed every 15 minutes) and wraps the API responses as MCP tool results. Any MCP-compatible client — Claude Desktop, the Chat API, custom agents — can connect to it.

**Tier 2 (Chat API)** is optional. On startup it connects to the MCP server, loads all registered tools, and uses a LangChain agent loop with GPT-4o to turn natural language questions into tool calls and human-readable answers.

---

## Prerequisites

- Python 3.12+
- [`uv`](https://docs.astral.sh/uv/getting-started/installation/) (recommended) or `pip`
- A running Wazuh Manager instance with REST API access
- OpenAI API key (only required for the Chat API tier)

---

## Installation

```bash
git clone https://github.com/ArfanAbid/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Install dependencies
uv pip install -r requirements.txt
```

---

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```env
# Wazuh Manager connection (required)
WAZUH_URL=https://your-wazuh-manager:55000
WAZUH_USER=your-username
WAZUH_PASS=your-password
WAZUH_SSL_VERIFY=false        # set to false for self-signed certificates
WAZUH_TIMEOUT=30

# MCP Server
MCP_SERVER_HOST=127.0.0.1
MCP_SERVER_PORT=8000

# LLM keys (only needed for Chat API)
OPENAI_API_KEY=sk-...
GROQ_API_KEY=gsk_...          # optional alternative to OpenAI

# Logging
LOG_LEVEL=INFO

# Tool filtering (optional — see "Disabling Tools" section below)
# WAZUH_DISABLED_TOOLS=DeleteAgentTool,RestartManagerTool
# WAZUH_DISABLED_CATEGORIES=dangerous,write
# WAZUH_READ_ONLY=false
```

---

## Running

The two tiers must be started as separate processes.

**Step 1 — Start the MCP Server:**

```bash
uv run python -m src.main
# Server listening at http://127.0.0.1:8000
# SSE endpoint: http://127.0.0.1:8000/sse/
```

**Step 2 — Start the Chat API** *(optional, requires MCP server running first)*:

```bash
uv run python app/main.py
# API available at http://127.0.0.1:8001
# Swagger docs at http://127.0.0.1:8001/docs
```

---

## Available MCP Tools

The MCP server exposes 10 tools across 5 categories:

### Authentication
| Tool | Description |
|------|-------------|
| `AuthenticateTool` | Force a JWT token refresh. Takes no parameters. |

### Agent Management
| Tool | Description |
|------|-------------|
| `GetAgentsTool` | List agents with optional filters: `status` (active/disconnected/never_connected), `search`, `q` (query expression), `limit`, `offset`, `sort`, `select`. |

### System Inventory (Syscollector)
| Tool | Description |
|------|-------------|
| `GetAgentPortsTool` | Open network ports on an agent. Filter by `protocol`, `local_ip`, `local_port`, `state` (listening/established), `process`. Requires `agent_id`. |
| `GetAgentPackagesTool` | Installed packages on an agent. Filter by `name`, `vendor`, `version`, `architecture`, `format`. Requires `agent_id`. |
| `GetAgentProcessesTool` | Running processes on an agent. Filter by `name`, `pid`, `state`, `euser`, `priority`. Requires `agent_id`. |

### Rules Management
| Tool | Description |
|------|-------------|
| `ListRulesTool` | List detection rules. Filter by `level` (severity, e.g. `"4"` or `"2-4"`), `group`, `status`, compliance frameworks (`pci_dss`, `gdpr`, `hipaa`, `nist_800_53`, `mitre`), `search`. |
| `GetRuleFilesTool` | List all rule files and their enabled/disabled status. |
| `GetRuleFileContentTool` | Get raw XML content of a specific rule file. Requires `filename`. |

### Security Configuration Assessment (SCA)
| Tool | Description |
|------|-------------|
| `GetAgentSCATool` | SCA compliance scan results for an agent (CIS benchmarks, PCI DSS, etc.). Requires `agent_id`. |
| `GetSCAPolicyChecksTool` | Individual check results for a specific SCA policy. Filter by `result` (passed/failed/not_applicable) to focus on failures. Requires `agent_id` and `policy_id`. |

---

## Chat API

When the Chat API is running, it exposes three endpoints:

### `POST /chat`

Send a natural language question about your Wazuh environment.

```bash
curl -X POST http://127.0.0.1:8001/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Show me all active agents"}'
```

```bash
curl -X POST http://127.0.0.1:8001/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What ports are open on agent 001?"}'
```

```bash
curl -X POST http://127.0.0.1:8001/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "List failed SCA checks for agent 002"}'
```

**Response:**
```json
{
  "response": "Agent 001 has 3 listening ports: 22 (ssh), 80 (nginx), 443 (nginx)...",
  "tool_calls": [
    {"tool": "GetAgentPortsTool", "args": {"agent_id": "001"}, "result": "..."}
  ],
  "model_used": "gpt-4o"
}
```

### `GET /tools`

List all MCP tools currently loaded.

### `GET /health`

Returns `200` if both the LLM and MCP client are ready, `503` otherwise.

---

## Using with Claude Desktop

Connect Claude Desktop directly to the MCP server (no Chat API needed). Add to your Claude Desktop config (`claude_desktop_config.json`):

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

Start the MCP server first, then restart Claude Desktop. Claude will automatically discover and use all 10 Wazuh tools.

---

## Disabling Tools

Selectively disable tools or categories via environment variables:

```env
# Disable specific tools by name (comma-separated)
WAZUH_DISABLED_TOOLS=AuthenticateTool,GetRuleFileContentTool

# Disable entire categories
WAZUH_DISABLED_CATEGORIES=syscollector,sca,rules

# Restrict to read-only operations only
WAZUH_READ_ONLY=true
```

---

## Project Structure

```text
WAZUH-MCP/
├── __pycache__/                          # Python cache files
├── .venv/                                # Python virtual environment
│
├── app/                                  # Application entry point
│   ├── __pycache__/
│   ├── __init__.py                       # Package initialization
│   └── main.py                           # Starts the MCP application
│
├── src/                                  # Core source code
│   ├── __pycache__/
│   ├── __init__.py
│   ├── client.py                         # Async Wazuh API client
│   ├── config.py                         # Configuration management
│   ├── exceptions.py                     # Custom exception classes
│   ├── main.py                           # Main tool runner
│   ├── server.py                         # MCP server implementation
│   │
│   └── tools/                            # MCP tool implementations
│       ├── __pycache__/
│       ├── __init__.py
│       │
│       └── wazuh_manager/                # Wazuh manager related tools
│           ├── __pycache__/
│           ├── __init__.py
│           ├── agent_tools.py            # Agent management tools
│           ├── auth_tools.py             # Authentication tools
│           ├── rules_tools.py            # Rules management tools
│           ├── sca_tools.py              # Security configuration assessment tools
│           └── syscollector_tools.py     # System inventory (ports, packages, processes)
│
├── test/                                 # Testing and debugging scripts
│   ├── __pycache__/
│   ├── __init__.py
│   ├── check_server.py                   # Script to verify server functionality
│   └── debug_tool.py                     # Tool debugging helper
│
├── .env                                  # Local environment variables
├── .env.example                          # Example environment configuration
├── .gitignore                            # Git ignore rules
├── .python-version                       # Python version specification
│
├── pyproject.toml                        # Project metadata and build configuration
├── requirements.txt                      # Python dependencies
├── uv.lock                               # Dependency lock file (uv package manager)
│
└── README.md                             # Project documentation
```

---

## Requirements

See [requirements.txt](requirements.txt) for the full list. Key dependencies:

| Package | Purpose |
|---------|---------|
| `fastmcp>=0.4` | MCP server framework |
| `httpx[http2]>=0.27` | Async HTTP client for Wazuh API |
| `fastapi>=0.128.0` | Chat API web framework |
| `langchain-mcp-adapters>=0.2.1` | Bridge between LangChain and MCP tools |
| `langchain-openai>=1.1.6` | GPT-4o integration |
| `pydantic>=2.7` | Request/response validation |
