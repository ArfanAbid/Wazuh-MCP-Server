"""
Async HTTP client for Wazuh Indexer (OpenSearch) API.
Uses HTTP Basic Auth on every request — no JWT lifecycle needed.
"""

import logging
from typing import Any, Dict, Optional

import httpx

from .config import IndexerConfig

logger = logging.getLogger(__name__)


class WazuhIndexerClient:
    """Async HTTP client for the Wazuh Indexer (OpenSearch) REST API."""

    def __init__(self, config: IndexerConfig) -> None:
        self.config = config
        self._auth = (config.username, config.password)
        self._client = httpx.AsyncClient(
            base_url=config.url,
            verify=config.ssl_verify,
            timeout=config.timeout,
            http2=True,
        )

    async def search(
        self,
        query: Dict[str, Any],
        index: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute an OpenSearch query and return the full response dict."""
        target = index or self.config.index
        response = await self._client.post(
            f"/{target}/_search",
            json=query,
            auth=self._auth,
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()
        return response.json()

    async def count(
        self,
        query: Dict[str, Any],
        index: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute an OpenSearch count query."""
        target = index or self.config.index
        response = await self._client.post(
            f"/{target}/_count",
            json=query,
            auth=self._auth,
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()
        return response.json()

    async def get_by_id(self, doc_id: str, index: Optional[str] = None) -> Dict[str, Any]:
        """Retrieve a single alert document by its ID."""
        target = index or self.config.index
        response = await self._client.get(
            f"/{target}/_doc/{doc_id}",
            auth=self._auth,
        )
        response.raise_for_status()
        return response.json()

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
