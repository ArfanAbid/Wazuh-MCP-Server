"""
Agent management tools for Wazuh Manager API.
"""

import json
import logging
from typing import Callable, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class GetAgentsArgs(BaseModel):
    """Arguments for getting agents from Wazuh Manager."""

    status: Optional[List[str]] = Field(
        None,
        description="Filter by agent status",
        examples=[["active"]],
    )
    limit: Optional[int] = Field(500, description="Maximum number of agents to return")
    offset: Optional[int] = Field(0, description="Offset for pagination")
    sort: Optional[str] = Field(None, description="Sort results by field(s)")
    search: Optional[str] = Field(
        None,
        description="Search for elements containing the specified string",
    )
    select: Optional[List[str]] = Field(None, description="Select which fields to return")
    q: Optional[str] = Field(None, description="Query to filter results by")
    distinct: Optional[bool] = Field(False, description="Look for distinct values")


def register_agent_tools(app, get_client_func: Callable, safe_truncate_func: Callable):
    """Register agent management tools with the FastMCP app."""

    @app.tool(
        name="GetAgentsTool",
        description="Retrieve a list of Wazuh agents with optional filtering. Use this to get information about all agents or filter by status (active, disconnected, never_connected). Parameters should be passed in an 'args' object with 'status', 'limit', and 'offset' fields.",
    )
    async def get_agents_tool(args: GetAgentsArgs):
        """Return agents from Wazuh Manager matching optional filters.

        Args:
            args: An object containing:
                - status (optional): List of strings to filter by agent status (e.g., ["active"])
                - limit (optional): Maximum number of agents to return (default: 500)
                - offset (optional): Offset for pagination (default: 0)
                - sort (optional): Sort results by field(s) (e.g., "name", "-id")
                - search (optional): Search for elements containing the specified string
                - select (optional): List of fields to return (e.g., ["id", "name", "status"])
                - q (optional): Query to filter results by (e.g., "name=agent_name")
                - distinct (optional): Look for distinct values (default: false)

        Example usage:
            {"args": {"q": "name=agent_name"}}
            {"args": {"search": "agent_name"}}
            {"args": {"status": ["active"], "limit": 100}}
            {"args": {"offset": 50}}
            {"args": {}} for all agents

        Returns:
            JSON list of agents with their details including ID, name, status, IP, etc.
        """
        try:
            client = get_client_func()
            params = {"limit": args.limit, "offset": args.offset}

            if args.status:
                params["status"] = ",".join(args.status)
            if args.sort:
                params["sort"] = args.sort
            if args.search:
                params["search"] = args.search
            if args.select:
                params["select"] = ",".join(args.select)
            if args.q:
                params["q"] = args.q
            if args.distinct:
                params["distinct"] = "true"

            response = await client.get("/agents", params=params)
            data = response.json()
            return [
                {"type": "text", "text": safe_truncate_func(json.dumps(data, indent=2))},
            ]
        except Exception as e:
            logger.error("Failed to get agents: %s", e)
            return [{"type": "text", "text": f"Error retrieving agents: {str(e)}"}]