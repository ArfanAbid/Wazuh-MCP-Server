"""
Security Configuration Assessment (SCA) tools for Wazuh Manager API.
"""

import json
import logging
from typing import Callable, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class GetAgentSCAArgs(BaseModel):
    """Arguments for getting agent SCA results."""

    agent_id: str = Field(..., description="Agent ID to get SCA results from")
    name: Optional[str] = Field(None, description="Filter by policy name")
    description: Optional[str] = Field(None, description="Filter by policy description")
    references: Optional[str] = Field(None, description="Filter by references")
    limit: Optional[int] = Field(500, description="Maximum number of SCA policies to return")
    offset: Optional[int] = Field(0, description="Offset for pagination")
    sort: Optional[str] = Field(None, description="Sort results by field(s)")
    search: Optional[str] = Field(
        None,
        description="Search for elements containing the specified string",
    )
    select: Optional[List[str]] = Field(None, description="Select which fields to return")
    q: Optional[str] = Field(None, description="Query to filter results by")
    distinct: Optional[bool] = Field(False, description="Look for distinct values")


class GetSCAPolicyChecksArgs(BaseModel):
    """Arguments for getting SCA policy check details."""

    agent_id: str = Field(..., description="Agent ID to get SCA policy checks from")
    policy_id: str = Field(..., description="Policy ID to get checks for")
    title: Optional[str] = Field(None, description="Filter by check title")
    description: Optional[str] = Field(None, description="Filter by check description")
    rationale: Optional[str] = Field(None, description="Filter by rationale")
    remediation: Optional[str] = Field(None, description="Filter by remediation")
    command: Optional[str] = Field(None, description="Filter by command")
    reason: Optional[str] = Field(None, description="Filter by reason")
    file: Optional[str] = Field(None, description="Filter by file path")
    process: Optional[str] = Field(None, description="Filter by process name")
    directory: Optional[str] = Field(None, description="Filter by directory")
    registry: Optional[str] = Field(None, description="Filter by registry")
    references: Optional[str] = Field(None, description="Filter by references")
    result: Optional[str] = Field(
        None,
        description="Filter by result (passed, failed, not_applicable)",
    )
    condition: Optional[str] = Field(None, description="Filter by condition")
    limit: Optional[int] = Field(500, description="Maximum number of checks to return")
    offset: Optional[int] = Field(0, description="Offset for pagination")
    sort: Optional[str] = Field(None, description="Sort results by field(s)")
    search: Optional[str] = Field(
        None,
        description="Search for elements containing the specified string",
    )
    select: Optional[List[str]] = Field(None, description="Select which fields to return")
    q: Optional[str] = Field(None, description="Query to filter results by")
    distinct: Optional[bool] = Field(False, description="Look for distinct values")


def register_sca_tools(app, get_client_func: Callable, safe_truncate_func: Callable):
    """Register SCA tools with the FastMCP app."""

    @app.tool(
        name="GetAgentSCATool",
        description="Get Security Configuration Assessment (SCA) results for a specific Wazuh agent. Requires agent_id in 'args' object. SCA provides security compliance scanning results for various benchmarks (CIS, PCI DSS, etc.). Optional filters include policy name, description, references.",
    )
    async def get_agent_sca_tool(args: GetAgentSCAArgs):
        """Get SCA (Security Configuration Assessment) results for an agent."""
        try:
            client = get_client_func()
            params = {"limit": args.limit, "offset": args.offset}

            if args.name:
                params["name"] = args.name
            if args.description:
                params["description"] = args.description
            if args.references:
                params["references"] = args.references
            if args.sort:
                params["sort"] = args.sort
            if args.search:
                params["search"] = args.search
            if args.select:
                params["select"] = ",".join(args.select)
            if args.q:
                params["q"] = args.q
            if args.distinct:
                params["distinct"] = args.distinct

            response = await client.get(f"/sca/{args.agent_id}", params=params)
            data = response.json()
            return [
                {"type": "text", "text": safe_truncate_func(json.dumps(data, indent=2))},
            ]
        except Exception as e:
            logger.error("Failed to get agent SCA: %s", e)
            return [{"type": "text", "text": f"Error retrieving agent SCA: {str(e)}"}]

    @app.tool(
        name="GetSCAPolicyChecksTool",
        description="Get detailed SCA policy check results for a specific policy on a Wazuh agent. Requires agent_id and policy_id in 'args' object. Shows individual security checks with pass/fail status, remediation steps, compliance mappings, etc. Use result filter to focus on failed checks.",
    )
    async def get_sca_policy_checks_tool(args: GetSCAPolicyChecksArgs):
        """Get detailed SCA policy check results for a specific policy."""
        try:
            client = get_client_func()
            params = {"limit": args.limit, "offset": args.offset}

            if args.title:
                params["title"] = args.title
            if args.description:
                params["description"] = args.description
            if args.rationale:
                params["rationale"] = args.rationale
            if args.remediation:
                params["remediation"] = args.remediation
            if args.command:
                params["command"] = args.command
            if args.reason:
                params["reason"] = args.reason
            if args.file:
                params["file"] = args.file
            if args.process:
                params["process"] = args.process
            if args.directory:
                params["directory"] = args.directory
            if args.registry:
                params["registry"] = args.registry
            if args.references:
                params["references"] = args.references
            if args.result:
                params["result"] = args.result
            if args.condition:
                params["condition"] = args.condition
            if args.sort:
                params["sort"] = args.sort
            if args.search:
                params["search"] = args.search
            if args.select:
                params["select"] = ",".join(args.select)
            if args.q:
                params["q"] = args.q
            if args.distinct:
                params["distinct"] = args.distinct

            response = await client.get(f"/sca/{args.agent_id}/checks/{args.policy_id}", params=params)
            data = response.json()
            return [
                {"type": "text", "text": safe_truncate_func(json.dumps(data, indent=2))},
            ]
        except Exception as e:
            logger.error("Failed to get SCA policy checks: %s", e)
            return [
                {"type": "text", "text": f"Error retrieving SCA policy checks: {str(e)}"},
            ]