"""
Wazuh MCP Server - A Model Context Protocol server for Wazuh SIEM integration.
"""

__version__ = "0.1.0"
__author__ = "Arfan Abid"
__license__ = "MIT"

from .client import WazuhClient
from .config import Config, ServerConfig, WazuhConfig
from .exceptions import (
    ConfigurationError,
    WazuhAPIError,
    WazuhAuthenticationError,
    WazuhMCPError,
)
from .server import WazuhMCPServer, create_server

__all__ = [
    "WazuhClient",
    "Config",
    "ServerConfig",
    "WazuhConfig",
    "WazuhMCPError",
    "WazuhAuthenticationError",
    "WazuhAPIError",
    "ConfigurationError",
    "WazuhMCPServer",
    "create_server",
]