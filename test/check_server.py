import asyncio
import json
from src import create_server, Config


async def test_server_connection():
    print("\n====== Wazuh MCP Server: Connection Test ======\n")

    try:
        config = Config.from_env()

        server = create_server(config)

        print("→ Connecting to Wazuh MCP client...")

        async with server._get_client() as client:

            print("→ Authenticating...")
            await client.authenticate()
            print("✔ Authentication successful")

            print("→ Fetching active agents...")
            response = await client.get("/agents", params={"status": "active"})

            data = response.json()
            print("✔ Agents retrieved successfully")

            print("\n--- Active Agents ---")
            print(json.dumps(data, indent=4))

            print("\n✔ SERVER TEST PASSED — Everything is working!\n")

    except Exception as e:
        print("\n TEST FAILED — Something went wrong")
        print("Error:", e)
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(test_server_connection())


# uv run python -m test.check_server



# async def check_server():
#     server = create_server()
#     async with server._get_client() as client:
#         await client.authenticate()
#         response = await client.get("/agents", params={"status": "active"})
#         print("Active agents:", response.json())

# asyncio.run(check_server())

