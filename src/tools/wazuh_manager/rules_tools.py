"""
Rules management tools for Wazuh Manager API.
"""

import json
import logging
from typing import Callable, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ListRulesArgs(BaseModel):
    """Arguments for listing rules."""

    rule_ids: Optional[List[int]] = Field(None, description="List of rule IDs to filter by")
    limit: Optional[int] = Field(500, description="Maximum number of rules to return")
    offset: Optional[int] = Field(0, description="Offset for pagination")
    select: Optional[List[str]] = Field(None, description="Select which fields to return")
    sort: Optional[str] = Field(None, description="Sort results by field(s)")
    search: Optional[str] = Field(
        None,
        description="Search for elements containing the specified string",
    )
    q: Optional[str] = Field(None, description="Query to filter results by")
    status: Optional[str] = Field(None, description="Filter by status (enabled, disabled, all)")
    group: Optional[str] = Field(None, description="Filter by rule group")
    level: Optional[str] = Field(None, description="Filter by rule level (e.g., '4' or '2-4')")
    filename: Optional[List[str]] = Field(None, description="Filter by filename")
    relative_dirname: Optional[str] = Field(None, description="Filter by relative directory name")
    pci_dss: Optional[str] = Field(None, description="Filter by PCI_DSS requirement")
    gdpr: Optional[str] = Field(None, description="Filter by GDPR requirement")
    gpg13: Optional[str] = Field(None, description="Filter by GPG13 requirement")
    hipaa: Optional[str] = Field(None, description="Filter by HIPAA requirement")
    nist_800_53: Optional[str] = Field(None, description="Filter by NIST-800-53 requirement")
    tsc: Optional[str] = Field(None, description="Filter by TSC requirement")
    mitre: Optional[str] = Field(None, description="Filter by MITRE technique ID")
    distinct: Optional[bool] = Field(False, description="Look for distinct values")


class GetRuleFileContentArgs(BaseModel):
    """Arguments for getting rule file content."""

    filename: str = Field(..., description="Filename of the rule file to get content from")
    raw: Optional[bool] = Field(False, description="Format response in plain text")
    relative_dirname: Optional[str] = Field(None, description="Filter by relative directory name")


class GetRuleFilesArgs(BaseModel):
    """Arguments for getting rule files."""

    pretty: Optional[bool] = Field(False, description="Show results in human-readable format")
    wait_for_complete: Optional[bool] = Field(False, description="Disable timeout response")
    offset: Optional[int] = Field(0, description="First element to return in the collection")
    limit: Optional[int] = Field(500, description="Maximum number of elements to return")
    sort: Optional[str] = Field(None, description="Sort the collection by a field or fields")
    search: Optional[str] = Field(
        None,
        description="Look for elements containing the specified string",
    )
    relative_dirname: Optional[str] = Field(None, description="Filter by relative directory name")
    filename: Optional[List[str]] = Field(
        None,
        description="Filter by filename of one or more rule or decoder files",
    )
    status: Optional[str] = Field(
        None,
        description="Filter by list status (enabled, disabled, all)",
    )
    q: Optional[str] = Field(None, description="Query to filter results by")
    select: Optional[List[str]] = Field(None, description="Select which fields to return")
    distinct: Optional[bool] = Field(False, description="Look for distinct values")


def register_rules_tools(app, get_client_func: Callable, safe_truncate_func: Callable):
    """Register rules management tools with the FastMCP app."""

    @app.tool(
        name="ListRulesTool",
        description="List Wazuh detection rules with optional filtering. All parameters should be passed in an 'args' object. Use filters like 'search' for text search, 'group' for rule categories, 'level' for severity, 'status' for enabled/disabled rules, compliance filters (pci_dss, gdpr, hipaa, mitre), etc.",
    )
    async def list_rules_tool(args: ListRulesArgs):
        """List rules from Wazuh Manager matching optional filters."""
        try:
            client = get_client_func()
            params = {"limit": args.limit, "offset": args.offset}

            if args.rule_ids:
                params["rule_ids"] = ",".join(map(str, args.rule_ids))
            if args.select:
                params["select"] = ",".join(args.select)
            if args.sort:
                params["sort"] = args.sort
            if args.search:
                params["search"] = args.search
            if args.q:
                params["q"] = args.q
            if args.status:
                params["status"] = args.status
            if args.group:
                params["group"] = args.group
            if args.level:
                params["level"] = args.level
            if args.filename:
                params["filename"] = ",".join(args.filename)
            if args.relative_dirname:
                params["relative_dirname"] = args.relative_dirname
            if args.pci_dss:
                params["pci_dss"] = args.pci_dss
            if args.gdpr:
                params["gdpr"] = args.gdpr
            if args.gpg13:
                params["gpg13"] = args.gpg13
            if args.hipaa:
                params["hipaa"] = args.hipaa
            if args.nist_800_53:
                params["nist-800-53"] = args.nist_800_53
            if args.tsc:
                params["tsc"] = args.tsc
            if args.mitre:
                params["mitre"] = args.mitre
            if args.distinct:
                params["distinct"] = args.distinct

            response = await client.get("/rules", params=params)
            data = response.json()
            return [
                {"type": "text", "text": safe_truncate_func(json.dumps(data, indent=2))},
            ]
        except Exception as e:
            logger.error("Failed to list rules: %s", e)
            return [{"type": "text", "text": f"Error listing rules: {str(e)}"}]

    @app.tool(
        name="GetRuleFileContentTool",
        description="Get the raw XML content of a specific Wazuh rule file. Requires 'filename' in 'args' object. Use 'raw=true' for plain text format. Useful for examining rule definitions and syntax.",
    )
    async def get_rule_file_content_tool(args: GetRuleFileContentArgs):
        """Get the content of a specific rule file."""
        try:
            client = get_client_func()
            params = {}

            if args.raw:
                params["raw"] = "true"
            if args.relative_dirname:
                params["relative_dirname"] = args.relative_dirname

            response = await client.get(f"/rules/files/{args.filename}", params=params)

            # Handle both raw text and JSON responses
            if args.raw:
                content = response.text
                result = {"content": content, "raw": True, "filename": args.filename}
                return [{"type": "text", "text": safe_truncate_func(result["content"])}]
            else:
                data = response.json()
                return [
                    {"type": "text", "text": safe_truncate_func(json.dumps(data, indent=2))},
                ]
        except Exception as e:
            logger.error("Failed to get rule file content: %s", e)
            return [
                {"type": "text", "text": f"Error retrieving rule file content: {str(e)}"},
            ]

    @app.tool(
        name="GetRuleFilesTool",
        description="Get a list of all rule files and their status from Wazuh Manager. Supports filtering, sorting, and field selection.",
    )
    async def get_rule_files_tool(args: GetRuleFilesArgs):
        """Get rule files from Wazuh Manager."""
        try:
            client = get_client_func()
            params = {"limit": args.limit, "offset": args.offset}

            if args.pretty:
                params["pretty"] = "true"
            if args.wait_for_complete:
                params["wait_for_complete"] = "true"
            if args.sort:
                params["sort"] = args.sort
            if args.search:
                params["search"] = args.search
            if args.relative_dirname:
                params["relative_dirname"] = args.relative_dirname
            if args.filename:
                params["filename"] = ",".join(args.filename)
            if args.status:
                params["status"] = args.status
            if args.q:
                params["q"] = args.q
            if args.select:
                params["select"] = ",".join(args.select)
            if args.distinct:
                params["distinct"] = "true"

            response = await client.get("/rules/files", params=params)
            data = response.json()
            return [
                {"type": "text", "text": safe_truncate_func(json.dumps(data, indent=2))},
            ]
        except Exception as e:
            logger.error("Failed to get rule files: %s", e)
            return [
                {"type": "text", "text": f"Error retrieving rule files: {str(e)}"},
            ]