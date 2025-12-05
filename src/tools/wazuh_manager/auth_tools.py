"""
Authentication tools for Wazuh Manager API.
"""

import json
import logging
from typing import Callable

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class AuthenticateArgs(BaseModel):
    """Arguments for authentication tool (no parameters needed)."""

    pass


def register_auth_tools(app, get_client_func: Callable):
    """Register authentication tools with the FastMCP app."""

    @app.tool(
        name="AuthenticateTool",
        description="Force a new JWT token acquisition from Wazuh Manager. This tool requires no parameters and will refresh the authentication token for subsequent API calls.",
    )
    async def authenticate_tool(args: AuthenticateArgs):
        """Force a new JWT token acquisition from Wazuh Manager.

        This tool does not require any parameters. Simply call it to refresh
        the authentication token for subsequent Wazuh API operations.

        Returns:
            Success message with authentication details or error message.
        """
        try:
            client = get_client_func()
            result = await client.authenticate()
            return [
                {
                    "type": "text",
                    "text": f"Authentication successful: {json.dumps(result)}",
                },
            ]
        except Exception as e:
            logger.error("Authentication failed: %s", e)
            return [{"type": "text", "text": f"Authentication failed: {str(e)}"}]