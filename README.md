# Wazuh MCP Server

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