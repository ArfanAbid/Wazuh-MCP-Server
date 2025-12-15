'''
Main entry point for Wazuh MCP Server.
'''


from src import create_server

def main():
    print("=" * 60)
    print("Starting Wazuh MCP Server...")
    print("=" * 60)
    
    try:
        server = create_server()
        server.start()
    except KeyboardInterrupt:
        print("\n\n👋 Server stopped by user")
    except Exception as e:
        print(f"\n Error starting server: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()