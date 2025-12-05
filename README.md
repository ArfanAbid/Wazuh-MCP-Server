# Wazuh MCP Server


### Project Structure:

```
wazuh-mcp-server/
├── src/
│   ├── __init__.py                    # Package initialization
│   ├── client.py                      # Async Wazuh API client
│   ├── config.py                      # Configuration management
│   ├── exceptions.py                  # Custom exceptions
│   ├── server.py                      # Main MCP server
│   └── tools/
│       ├── __init__.py
│       └── wazuh_manager/
│           ├── __init__.py
│           ├── auth_tools.py          # Authentication
│           ├── agent_tools.py         # Agent management
│           ├── syscollector_tools.py  # Ports, packages, processes
│           ├── rules_tools.py         # Rules management
│           └── sca_tools.py           # Security compliance
├── .env.example                       # Environment template
├── requirements.txt                   # Dependencies
└── README.md                          # Complete documentation

```