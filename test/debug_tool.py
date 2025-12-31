"""
Debug utility to inspect tools and schemas sent to LLM (MCP version)
"""

import asyncio
import json
from langchain_mcp_adapters.client import MultiServerMCPClient


async def main():
    print(" Connecting to MCP server...\n")

    mcp_client = MultiServerMCPClient({
        "wazuh": {
            "transport": "sse",
            "url": "http://127.0.0.1:8000/sse/"
        }
    })

    tools = await mcp_client.get_tools()

    print(f" Total tools exposed to LLM: {len(tools)}")
    print("=" * 80)

    for idx, tool in enumerate(tools, start=1):
        print(f"\n🛠️ TOOL #{idx}")
        print(f"Name        : {tool.name}")
        print(f"Description : {tool.description}")

        if tool.args_schema:
            print("\n Args Schema (EXACT JSON sent to LLM):")
            print(json.dumps(tool.args_schema, indent=2))

            required = tool.args_schema.get("required", [])
            properties = tool.args_schema.get("properties", {})

            print("\n Required fields:", required)
            print(" Properties:", list(properties.keys()))

            if "args" in properties:
                print("⚠️  EXPECTS 'args' WRAPPER")
        else:
            print("\n No arguments required")

        print("-" * 80)


if __name__ == "__main__":
    asyncio.run(main())
