"""
Wazuh MCP Server - A Model Context Protocol server for Wazuh SIEM integration.
"""

__version__ = "0.1.0"
__author__ = "Arfan Abid"
__license__ = "MIT"

from .client import WazuhClient
from .config import Config, IndexerConfig, ServerConfig, WazuhConfig
from .exceptions import (
    ConfigurationError,
    WazuhAPIError,
    WazuhAuthenticationError,
    WazuhMCPError,
)
from .indexer_client import WazuhIndexerClient
from .server import WazuhMCPServer, create_server

__all__ = [
    "WazuhClient",
    "WazuhIndexerClient",
    "Config",
    "ServerConfig",
    "WazuhConfig",
    "IndexerConfig",
    "WazuhMCPError",
    "WazuhAuthenticationError",
    "WazuhAPIError",
    "ConfigurationError",
    "WazuhMCPServer",
    "create_server",
]