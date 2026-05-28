"""
Main MCP server implementation for Wazuh integration.
"""

import logging
from typing import Optional

from fastmcp import FastMCP

from .client import WazuhClient
from .config import Config
from .indexer_client import WazuhIndexerClient
from .tools.wazuh_manager import (
    agent_tools,
    auth_tools,
    rules_tools,
    sca_tools,
    syscollector_tools,
)
from .tools.wazuh_indexer import alert_tools

logger = logging.getLogger(__name__)


class WazuhMCPServer:
    """Main MCP server for Wazuh integration."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self._client: Optional[WazuhClient] = None
        self._indexer_client: Optional[WazuhIndexerClient] = None
        self.app = FastMCP(name="Wazuh MCP Server", version="0.1.0")

        # Register all tools
        self._register_tools()

    def _get_client(self) -> WazuhClient:
        """Get or create Wazuh Manager client."""
        if self._client is None:
            self._client = WazuhClient(self.config.wazuh)
        return self._client

    def _get_indexer_client(self) -> WazuhIndexerClient:
        """Get or create Wazuh Indexer client."""
        if self._indexer_client is None:
            self._indexer_client = WazuhIndexerClient(self.config.indexer)
        return self._indexer_client

    def _safe_truncate(self, text: str, max_length: int = 32000) -> str:
        """Truncate text to avoid overwhelming the client."""
        if len(text) <= max_length:
            return text
        return text[:max_length] + f"\n\n[... truncated {len(text) - max_length} characters ...]"

    def _register_tools(self) -> None:
        """Register all available tools."""
        # Register authentication tools
        if "AuthenticateTool" not in self.config.server.disabled_tools:
            auth_tools.register_auth_tools(self.app, self._get_client)

        # Register agent tools
        if "GetAgentsTool" not in self.config.server.disabled_tools:
            agent_tools.register_agent_tools(self.app, self._get_client, self._safe_truncate)

        # Register syscollector tools
        if "syscollector" not in self.config.server.disabled_categories:
            if "GetAgentPortsTool" not in self.config.server.disabled_tools:
                syscollector_tools.register_syscollector_tools(
                    self.app, self._get_client, self._safe_truncate
                )

        # Register rules tools
        if "rules" not in self.config.server.disabled_categories:
            if "ListRulesTool" not in self.config.server.disabled_tools:
                rules_tools.register_rules_tools(self.app, self._get_client, self._safe_truncate)

        # Register SCA tools
        if "sca" not in self.config.server.disabled_categories:
            if "GetAgentSCATool" not in self.config.server.disabled_tools:
                sca_tools.register_sca_tools(self.app, self._get_client, self._safe_truncate)

        # Register Indexer alert tools (only when WAZUH_INDEXER_URL is configured)
        if self.config.indexer and "indexer" not in self.config.server.disabled_categories:
            if "SearchAlertsTool" not in self.config.server.disabled_tools:
                alert_tools.register_alert_tools(
                    self.app, self._get_indexer_client, self._safe_truncate
                )
                logger.info("Wazuh Indexer alert tools registered (index: %s)", self.config.indexer.index)

    def start(self, host: str = None, port: int = None) -> None:
        """Start the MCP server."""
        import uvicorn

        host = host or self.config.server.host
        port = port or self.config.server.port

        logger.info("Starting Wazuh MCP Server on %s:%d", host, port)
        logger.info("Wazuh URL: %s", self.config.wazuh.url)
        logger.info("SSL Verify: %s", self.config.wazuh.ssl_verify)

        # Start server with sse transport
        uvicorn.run(
            self.app.sse_app,
            host=host,
            port=port,
            log_level=self.config.server.log_level.lower(),
        )

    async def close(self) -> None:
        """Close the server and cleanup resources."""
        if self._client:
            await self._client.close()
        if self._indexer_client:
            await self._indexer_client.close()


def create_server(config: Config = None) -> WazuhMCPServer:
    """Factory function to create a WazuhMCPServer instance."""
    if config is None:
        config = Config.from_env()

    config.validate()
    config.setup_logging()

    return WazuhMCPServer(config)
