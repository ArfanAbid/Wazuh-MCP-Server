"""
Tool modules for Wazuh MCP Server.
"""

from .wazuh_manager import (
    agent_tools,
    auth_tools,
    rules_tools,
    sca_tools,
    syscollector_tools,
)

__all__ = [
    "auth_tools",
    "agent_tools",
    "syscollector_tools",
    "rules_tools",
    "sca_tools",
]