"""
Alert query tools for Wazuh Indexer (OpenSearch).
"""

import json
import logging
from typing import Callable, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Argument models
# ---------------------------------------------------------------------------

class SearchAlertsArgs(BaseModel):
    query: Optional[str] = Field(
        None,
        description="Free-text search across all alert fields (rule description, agent name, log data, etc.)",
    )
    agent_id: Optional[str] = Field(None, description="Filter by agent ID (e.g. '001')")
    agent_name: Optional[str] = Field(None, description="Filter by agent name")
    rule_level_min: Optional[int] = Field(
        None, description="Minimum rule severity level (1–15). Levels ≥12 are high severity."
    )
    rule_level_max: Optional[int] = Field(None, description="Maximum rule severity level (1–15)")
    rule_id: Optional[str] = Field(None, description="Filter by specific rule ID")
    rule_group: Optional[str] = Field(
        None, description="Filter by rule group (e.g. 'web', 'sshd', 'attack')"
    )
    mitre_id: Optional[str] = Field(
        None, description="Filter by MITRE ATT&CK technique ID (e.g. 'T1110')"
    )
    time_from: Optional[str] = Field(
        "now-24h",
        description="Start of the time range in OpenSearch date math (e.g. 'now-1h', 'now-7d', '2024-01-01'). Defaults to last 24 hours.",
    )
    time_to: Optional[str] = Field("now", description="End of the time range. Defaults to now.")
    limit: Optional[int] = Field(50, description="Maximum number of alerts to return (max 500)")
    sort_order: Optional[str] = Field(
        "desc", description="Sort order by timestamp: 'asc' or 'desc'"
    )


class GetRecentAlertsArgs(BaseModel):
    limit: Optional[int] = Field(20, description="Number of most recent alerts to return (max 500)")
    rule_level_min: Optional[int] = Field(
        None, description="Only return alerts at or above this severity level"
    )
    agent_id: Optional[str] = Field(None, description="Filter by agent ID")


class CountAlertsArgs(BaseModel):
    agent_id: Optional[str] = Field(None, description="Filter by agent ID")
    rule_level_min: Optional[int] = Field(None, description="Minimum rule severity level")
    rule_group: Optional[str] = Field(None, description="Filter by rule group")
    time_from: Optional[str] = Field("now-24h", description="Start of the time range")
    time_to: Optional[str] = Field("now", description="End of the time range")


class GetTopAgentsByAlertsArgs(BaseModel):
    time_from: Optional[str] = Field("now-24h", description="Start of the time range")
    time_to: Optional[str] = Field("now", description="End of the time range")
    size: Optional[int] = Field(10, description="Number of top agents to return")
    rule_level_min: Optional[int] = Field(
        None, description="Only count alerts at or above this severity level"
    )


class GetAlertsByRuleGroupArgs(BaseModel):
    time_from: Optional[str] = Field("now-24h", description="Start of the time range")
    time_to: Optional[str] = Field("now", description="End of the time range")
    size: Optional[int] = Field(10, description="Number of top rule groups to return")
    agent_id: Optional[str] = Field(None, description="Scope to a specific agent")


class GetAlertByIdArgs(BaseModel):
    alert_id: str = Field(..., description="OpenSearch document ID of the alert")


# ---------------------------------------------------------------------------
# Helper: build filter clauses
# ---------------------------------------------------------------------------

def _build_filters(
    agent_id=None,
    agent_name=None,
    rule_level_min=None,
    rule_level_max=None,
    rule_id=None,
    rule_group=None,
    mitre_id=None,
    time_from="now-24h",
    time_to="now",
) -> list:
    filters = [
        {"range": {"@timestamp": {"gte": time_from, "lte": time_to}}}
    ]
    if agent_id:
        filters.append({"term": {"agent.id": agent_id}})
    if agent_name:
        filters.append({"match": {"agent.name": agent_name}})
    if rule_id:
        filters.append({"term": {"rule.id": rule_id}})
    if rule_group:
        filters.append({"match": {"rule.groups": rule_group}})
    if mitre_id:
        filters.append({"term": {"rule.mitre.id": mitre_id}})
    if rule_level_min is not None or rule_level_max is not None:
        level_range: dict = {}
        if rule_level_min is not None:
            level_range["gte"] = rule_level_min
        if rule_level_max is not None:
            level_range["lte"] = rule_level_max
        filters.append({"range": {"rule.level": level_range}})
    return filters


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_alert_tools(app, get_client_func: Callable, safe_truncate_func: Callable) -> None:
    """Register Wazuh Indexer alert tools with the FastMCP app."""

    @app.tool(
        name="SearchAlertsTool",
        description=(
            "Search Wazuh security alerts stored in the Indexer (OpenSearch). "
            "Supports free-text search plus filters: agent_id, agent_name, rule_level_min/max, "
            "rule_id, rule_group, mitre_id, and time range (time_from / time_to using date math "
            "like 'now-1h', 'now-7d'). Returns matching alert documents sorted by timestamp."
        ),
    )
    async def search_alerts_tool(args: SearchAlertsArgs):
        try:
            client = get_client_func()
            filters = _build_filters(
                agent_id=args.agent_id,
                agent_name=args.agent_name,
                rule_level_min=args.rule_level_min,
                rule_level_max=args.rule_level_max,
                rule_id=args.rule_id,
                rule_group=args.rule_group,
                mitre_id=args.mitre_id,
                time_from=args.time_from or "now-24h",
                time_to=args.time_to or "now",
            )

            bool_clause: dict = {"filter": filters}
            if args.query:
                bool_clause["must"] = [{"query_string": {"query": args.query}}]

            dsl = {
                "query": {"bool": bool_clause},
                "sort": [{"@timestamp": {"order": args.sort_order or "desc"}}],
                "size": min(args.limit or 50, 500),
                "_source": [
                    "@timestamp",
                    "agent.id",
                    "agent.name",
                    "rule.id",
                    "rule.level",
                    "rule.description",
                    "rule.groups",
                    "rule.mitre.id",
                    "rule.mitre.tactic",
                    "data",
                    "full_log",
                    "location",
                ],
            }

            data = await client.search(dsl)
            hits = data.get("hits", {})
            result = {
                "total": hits.get("total", {}).get("value", 0),
                "alerts": [h["_source"] for h in hits.get("hits", [])],
            }
            return [{"type": "text", "text": safe_truncate_func(json.dumps(result, indent=2))}]
        except Exception as e:
            logger.error("SearchAlertsTool failed: %s", e)
            return [{"type": "text", "text": f"Error searching alerts: {str(e)}"}]

    @app.tool(
        name="GetRecentAlertsTool",
        description=(
            "Get the most recent Wazuh alerts from the Indexer. "
            "Optionally filter by minimum severity level (rule_level_min) or agent_id. "
            "Useful as a quick overview of what has happened recently."
        ),
    )
    async def get_recent_alerts_tool(args: GetRecentAlertsArgs):
        try:
            client = get_client_func()
            filters = _build_filters(
                agent_id=args.agent_id,
                rule_level_min=args.rule_level_min,
            )
            dsl = {
                "query": {"bool": {"filter": filters}},
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": min(args.limit or 20, 500),
                "_source": [
                    "@timestamp",
                    "agent.id",
                    "agent.name",
                    "rule.id",
                    "rule.level",
                    "rule.description",
                    "rule.groups",
                    "rule.mitre.id",
                    "full_log",
                ],
            }
            data = await client.search(dsl)
            hits = data.get("hits", {})
            result = {
                "total": hits.get("total", {}).get("value", 0),
                "alerts": [h["_source"] for h in hits.get("hits", [])],
            }
            return [{"type": "text", "text": safe_truncate_func(json.dumps(result, indent=2))}]
        except Exception as e:
            logger.error("GetRecentAlertsTool failed: %s", e)
            return [{"type": "text", "text": f"Error retrieving recent alerts: {str(e)}"}]

    @app.tool(
        name="CountAlertsTool",
        description=(
            "Count Wazuh alerts matching optional filters: agent_id, rule_level_min, "
            "rule_group, and time range. Returns a single count value. "
            "Useful for 'how many critical alerts in the last hour?' type questions."
        ),
    )
    async def count_alerts_tool(args: CountAlertsArgs):
        try:
            client = get_client_func()
            filters = _build_filters(
                agent_id=args.agent_id,
                rule_level_min=args.rule_level_min,
                rule_group=args.rule_group,
                time_from=args.time_from or "now-24h",
                time_to=args.time_to or "now",
            )
            dsl = {"query": {"bool": {"filter": filters}}}
            data = await client.count(dsl)
            return [{"type": "text", "text": json.dumps({"count": data.get("count", 0)}, indent=2)}]
        except Exception as e:
            logger.error("CountAlertsTool failed: %s", e)
            return [{"type": "text", "text": f"Error counting alerts: {str(e)}"}]

    @app.tool(
        name="GetTopAgentsByAlertsTool",
        description=(
            "Aggregate Wazuh alerts by agent to find which agents generated the most alerts. "
            "Supports time range and optional minimum severity filter. "
            "Returns a ranked list of agents with alert counts."
        ),
    )
    async def get_top_agents_by_alerts_tool(args: GetTopAgentsByAlertsArgs):
        try:
            client = get_client_func()
            filters = _build_filters(
                rule_level_min=args.rule_level_min,
                time_from=args.time_from or "now-24h",
                time_to=args.time_to or "now",
            )
            dsl = {
                "query": {"bool": {"filter": filters}},
                "size": 0,
                "aggs": {
                    "top_agents": {
                        "terms": {
                            "field": "agent.name",
                            "size": args.size or 10,
                            "order": {"_count": "desc"},
                        }
                    }
                },
            }
            data = await client.search(dsl)
            buckets = data.get("aggregations", {}).get("top_agents", {}).get("buckets", [])
            result = {
                "total_alerts": data.get("hits", {}).get("total", {}).get("value", 0),
                "top_agents": [{"agent": b["key"], "alert_count": b["doc_count"]} for b in buckets],
            }
            return [{"type": "text", "text": json.dumps(result, indent=2)}]
        except Exception as e:
            logger.error("GetTopAgentsByAlertsTool failed: %s", e)
            return [{"type": "text", "text": f"Error aggregating alerts by agent: {str(e)}"}]

    @app.tool(
        name="GetAlertsByRuleGroupTool",
        description=(
            "Aggregate Wazuh alerts by rule group to see which threat categories are most active. "
            "Supports time range and optional agent scope. "
            "Returns a ranked breakdown of alert counts per rule group (e.g. web, sshd, attack)."
        ),
    )
    async def get_alerts_by_rule_group_tool(args: GetAlertsByRuleGroupArgs):
        try:
            client = get_client_func()
            filters = _build_filters(
                agent_id=args.agent_id,
                time_from=args.time_from or "now-24h",
                time_to=args.time_to or "now",
            )
            dsl = {
                "query": {"bool": {"filter": filters}},
                "size": 0,
                "aggs": {
                    "rule_groups": {
                        "terms": {
                            "field": "rule.groups",
                            "size": args.size or 10,
                            "order": {"_count": "desc"},
                        }
                    }
                },
            }
            data = await client.search(dsl)
            buckets = data.get("aggregations", {}).get("rule_groups", {}).get("buckets", [])
            result = {
                "total_alerts": data.get("hits", {}).get("total", {}).get("value", 0),
                "rule_groups": [{"group": b["key"], "alert_count": b["doc_count"]} for b in buckets],
            }
            return [{"type": "text", "text": json.dumps(result, indent=2)}]
        except Exception as e:
            logger.error("GetAlertsByRuleGroupTool failed: %s", e)
            return [{"type": "text", "text": f"Error aggregating alerts by rule group: {str(e)}"}]

    @app.tool(
        name="GetAlertByIdTool",
        description=(
            "Retrieve a single Wazuh alert document from the Indexer by its OpenSearch document ID. "
            "Returns the full alert with all fields."
        ),
    )
    async def get_alert_by_id_tool(args: GetAlertByIdArgs):
        try:
            client = get_client_func()
            data = await client.get_by_id(args.alert_id)
            return [{"type": "text", "text": safe_truncate_func(json.dumps(data, indent=2))}]
        except Exception as e:
            logger.error("GetAlertByIdTool failed: %s", e)
            return [{"type": "text", "text": f"Error retrieving alert {args.alert_id}: {str(e)}"}]
