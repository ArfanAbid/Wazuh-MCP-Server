"""
Syscollector tools for Wazuh Manager API.
"""

import json
import logging
from typing import Callable, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class GetAgentPortsArgs(BaseModel):
    """Arguments for getting agent ports information."""

    agent_id: str = Field(..., description="Agent ID to get ports from")
    limit: Optional[int] = Field(500, description="Maximum number of ports to return")
    offset: Optional[int] = Field(0, description="Offset for pagination")
    protocol: Optional[str] = Field(None, description="Filter by protocol (tcp, udp)")
    local_ip: Optional[str] = Field(None, description="Filter by local IP address")
    local_port: Optional[str] = Field(None, description="Filter by local port")
    remote_ip: Optional[str] = Field(None, description="Filter by remote IP address")
    state: Optional[str] = Field(None, description="Filter by state (listening, established, etc.)")
    process: Optional[str] = Field(None, description="Filter by process name")
    pid: Optional[str] = Field(None, description="Filter by process ID")
    tx_queue: Optional[str] = Field(None, description="Filter by tx_queue")
    sort: Optional[str] = Field(None, description="Sort results by field(s)")
    search: Optional[str] = Field(
        None,
        description="Search for elements containing the specified string",
    )
    select: Optional[List[str]] = Field(None, description="Select which fields to return")
    q: Optional[str] = Field(None, description="Query to filter results by")
    distinct: Optional[bool] = Field(False, description="Look for distinct values")


class GetAgentPackagesArgs(BaseModel):
    """Arguments for getting agent packages information."""

    agent_id: str = Field(..., description="Agent ID to get packages from")
    limit: Optional[int] = Field(500, description="Maximum number of packages to return")
    offset: Optional[int] = Field(0, description="Offset for pagination")
    vendor: Optional[str] = Field(None, description="Filter by vendor")
    name: Optional[str] = Field(None, description="Filter by package name")
    architecture: Optional[str] = Field(None, description="Filter by architecture")
    format: Optional[str] = Field(None, description="Filter by file format (e.g., 'deb')")
    version: Optional[str] = Field(None, description="Filter by package version")
    sort: Optional[str] = Field(None, description="Sort results by field(s)")
    search: Optional[str] = Field(
        None,
        description="Search for elements containing the specified string",
    )
    select: Optional[List[str]] = Field(None, description="Select which fields to return")
    q: Optional[str] = Field(None, description="Query to filter results by")
    distinct: Optional[bool] = Field(False, description="Look for distinct values")


class GetAgentProcessesArgs(BaseModel):
    """Arguments for getting agent processes information."""

    agent_id: str = Field(..., description="Agent ID to get processes from")
    limit: Optional[int] = Field(500, description="Maximum number of processes to return")
    offset: Optional[int] = Field(0, description="Offset for pagination")
    pid: Optional[str] = Field(None, description="Filter by process PID")
    state: Optional[str] = Field(None, description="Filter by process state")
    ppid: Optional[str] = Field(None, description="Filter by process parent PID")
    egroup: Optional[str] = Field(None, description="Filter by process egroup")
    euser: Optional[str] = Field(None, description="Filter by process euser")
    fgroup: Optional[str] = Field(None, description="Filter by process fgroup")
    name: Optional[str] = Field(None, description="Filter by process name")
    nlwp: Optional[str] = Field(None, description="Filter by process nlwp")
    pgrp: Optional[str] = Field(None, description="Filter by process pgrp")
    priority: Optional[str] = Field(None, description="Filter by process priority")
    rgroup: Optional[str] = Field(None, description="Filter by process rgroup")
    ruser: Optional[str] = Field(None, description="Filter by process ruser")
    sgroup: Optional[str] = Field(None, description="Filter by process sgroup")
    suser: Optional[str] = Field(None, description="Filter by process suser")
    sort: Optional[str] = Field(None, description="Sort results by field(s)")
    search: Optional[str] = Field(
        None,
        description="Search for elements containing the specified string",
    )
    select: Optional[List[str]] = Field(None, description="Select which fields to return")
    q: Optional[str] = Field(None, description="Query to filter results by")
    distinct: Optional[bool] = Field(False, description="Look for distinct values")


def register_syscollector_tools(app, get_client_func: Callable, safe_truncate_func: Callable):
    """Register syscollector tools with the FastMCP app."""

    @app.tool(
        name="GetAgentPortsTool",
        description="Get network port information for a specific Wazuh agent from syscollector. Requires agent_id in 'args' object. Optional filters include protocol (tcp/udp), local_ip, local_port, remote_ip, state (listening/established), process name, etc.",
    )
    async def get_agent_ports_tool(args: GetAgentPortsArgs):
        """Get agent ports information from syscollector."""
        try:
            client = get_client_func()
            params = {"limit": args.limit, "offset": args.offset}

            if args.protocol:
                params["protocol"] = args.protocol
            if args.local_ip:
                params["local.ip"] = args.local_ip
            if args.local_port:
                params["local.port"] = args.local_port
            if args.remote_ip:
                params["remote.ip"] = args.remote_ip
            if args.state:
                params["state"] = args.state
            if args.process:
                params["process"] = args.process
            if args.pid:
                params["pid"] = args.pid
            if args.tx_queue:
                params["tx_queue"] = args.tx_queue
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

            response = await client.get(f"/syscollector/{args.agent_id}/ports", params=params)
            data = response.json()
            return [
                {"type": "text", "text": safe_truncate_func(json.dumps(data, indent=2))},
            ]
        except Exception as e:
            logger.error("Failed to get agent ports: %s", e)
            return [{"type": "text", "text": f"Error retrieving agent ports: {str(e)}"}]

    @app.tool(
        name="GetAgentPackagesTool",
        description="Get installed package information for a specific Wazuh agent from syscollector. Requires agent_id in 'args' object. Optional filters include vendor, package name, architecture, format (deb/rpm), version, etc.",
    )
    async def get_agent_packages_tool(args: GetAgentPackagesArgs):
        """Get agent packages information from syscollector."""
        try:
            client = get_client_func()
            params = {"limit": args.limit, "offset": args.offset}

            if args.vendor:
                params["vendor"] = args.vendor
            if args.name:
                params["name"] = args.name
            if args.architecture:
                params["architecture"] = args.architecture
            if args.format:
                params["format"] = args.format
            if args.version:
                params["version"] = args.version
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

            response = await client.get(f"/syscollector/{args.agent_id}/packages", params=params)
            data = response.json()
            return [
                {"type": "text", "text": safe_truncate_func(json.dumps(data, indent=2))},
            ]
        except Exception as e:
            logger.error("Failed to get agent packages: %s", e)
            return [{"type": "text", "text": f"Error retrieving agent packages: {str(e)}"}]

    @app.tool(
        name="GetAgentProcessesTool",
        description="Get running process information for a specific Wazuh agent from syscollector. Requires agent_id in 'args' object. Optional filters include PID, process name, state, user/group information, priority, etc.",
    )
    async def get_agent_processes_tool(args: GetAgentProcessesArgs):
        """Get agent processes information from syscollector."""
        try:
            client = get_client_func()
            params = {"limit": args.limit, "offset": args.offset}

            if args.pid:
                params["pid"] = args.pid
            if args.state:
                params["state"] = args.state
            if args.ppid:
                params["ppid"] = args.ppid
            if args.egroup:
                params["egroup"] = args.egroup
            if args.euser:
                params["euser"] = args.euser
            if args.fgroup:
                params["fgroup"] = args.fgroup
            if args.name:
                params["name"] = args.name
            if args.nlwp:
                params["nlwp"] = args.nlwp
            if args.pgrp:
                params["pgrp"] = args.pgrp
            if args.priority:
                params["priority"] = args.priority
            if args.rgroup:
                params["rgroup"] = args.rgroup
            if args.ruser:
                params["ruser"] = args.ruser
            if args.sgroup:
                params["sgroup"] = args.sgroup
            if args.suser:
                params["suser"] = args.suser
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

            response = await client.get(f"/syscollector/{args.agent_id}/processes", params=params)
            data = response.json()
            return [
                {"type": "text", "text": safe_truncate_func(json.dumps(data, indent=2))},
            ]
        except Exception as e:
            logger.error("Failed to get agent processes: %s", e)
            return [{"type": "text", "text": f"Error retrieving agent processes: {str(e)}"}]