"""
Test script to verify Wazuh Indexer (OpenSearch) connectivity and alert tools.
Run with: uv run python -m test.check_indexer
"""

import asyncio
import json
from src.config import Config
from src.indexer_client import WazuhIndexerClient


async def test_indexer_connection():
    print("\n====== Wazuh Indexer: Connection Test ======\n")

    config = Config.from_env()

    if not config.indexer:
        print("✗ WAZUH_INDEXER_URL is not set in .env — indexer is not configured.")
        return

    print(f"  URL  : {config.indexer.url}")
    print(f"  User : {config.indexer.username}")
    print(f"  Index: {config.indexer.index}")
    print(f"  SSL  : {config.indexer.ssl_verify}\n")

    client = WazuhIndexerClient(config.indexer)

    try:
        # ── 1. Count all alerts in the index ──────────────────────────────
        print("── Test 1: Count total alerts ──")
        result = await client.count({"query": {"match_all": {}}})
        total = result.get("count", 0)
        print(f"  ✔ Total alerts in index: {total}\n")

        # ── 2. Get 3 most recent alerts ───────────────────────────────────
        print("── Test 2: Fetch 3 most recent alerts ──")
        result = await client.search({
            "query": {"match_all": {}},
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": 3,
            "_source": ["@timestamp", "agent.name", "rule.level", "rule.description"],
        })
        hits = result.get("hits", {}).get("hits", [])
        if hits:
            for h in hits:
                src = h["_source"]
                print(f"  [{src.get('@timestamp','?')}] "
                      f"agent={src.get('agent', {}).get('name','?')}  "
                      f"level={src.get('rule', {}).get('level','?')}  "
                      f"rule={src.get('rule', {}).get('description','?')}")
            print()
        else:
            print("  No alerts found in the index.\n")

        # ── 3. Count high-severity alerts (level ≥ 10) in last 24h ───────
        print("── Test 3: Count high-severity alerts (level ≥ 10) in last 24h ──")
        result = await client.count({
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-24h"}}},
                        {"range": {"rule.level": {"gte": 10}}},
                    ]
                }
            }
        })
        print(f"  ✔ High-severity alerts (last 24h): {result.get('count', 0)}\n")

        # ── 4. Top 5 agents by alert count (last 24h) ─────────────────────
        print("── Test 4: Top 5 agents by alert count (last 24h) ──")
        result = await client.search({
            "query": {
                "bool": {
                    "filter": [{"range": {"@timestamp": {"gte": "now-24h"}}}]
                }
            },
            "size": 0,
            "aggs": {
                "top_agents": {
                    "terms": {"field": "agent.name", "size": 5, "order": {"_count": "desc"}}
                }
            },
        })
        buckets = result.get("aggregations", {}).get("top_agents", {}).get("buckets", [])
        if buckets:
            for b in buckets:
                print(f"  {b['key']:<30} {b['doc_count']} alerts")
        else:
            print("  No data (index may be empty or no alerts in last 24h)")
        print()

        print("✔ ALL INDEXER TESTS PASSED — Indexer is working!\n")

    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(test_indexer_connection())
