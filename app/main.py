"""
FastAPI Chat Interface for Wazuh MCP Server
Now using Groq for ultra-fast responses with direct tool calling!
"""

import os
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_core.tools import BaseTool
from langchain_groq import ChatGroq
from langchain_mcp_adapters.client import MultiServerMCPClient
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(
    title="Wazuh Chat API for Wazuh SIEM(MCP Server)",
    description="Chat interface for Wazuh SIEM using natural language",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

llm = None
tools: List[BaseTool] = []
mcp_client = None


class ChatRequest(BaseModel):
    """Request model for chat endpoint"""
    message: str
    session_id: Optional[str] = "default"
    model: Optional[str] = "llama-3.3-70b-versatile"


class ChatResponse(BaseModel):
    """Response model for chat endpoint"""
    response: str
    tool_calls: Optional[list] = None
    error: Optional[str] = None
    model_used: Optional[str] = None



SYSTEM_PROMPT = """You are a helpful assistant for the Wazuh SIEM platform. 
You have access to various tools to query and analyze security data.

When answering questions:
1. Use the available tools to get real-time data from Wazuh
2. Provide clear, concise answers
3. If data is missing or tools fail, explain what went wrong
4. Format responses in a user-friendly way

Available information you can retrieve:
- Agent status and information
- Security alerts
- Vulnerability scans
- SCA (Security Configuration Assessment) results
- System inventory data

When you need to use a tool, the system will automatically execute it for you."""


async def run_agent_loop(message: str, max_iterations: int = 10) -> Dict[str, Any]:
    """
    Simple agent loop that uses tool calling
    """
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=message)
    ]
    
    tool_calls_log = []
    
    for iteration in range(max_iterations):
        # Bind tools to the model
        llm_with_tools = llm.bind_tools(tools)
        
        # Get response from LLM
        response = await llm_with_tools.ainvoke(messages)
        
        # Add AI response to messages
        messages.append(response)
        
        # Check if there are tool calls
        if not response.tool_calls:
            # No more tool calls, return final answer
            return {
                "output": response.content,
                "tool_calls": tool_calls_log,
                "iterations": iteration + 1
            }
        
        # Execute tool calls
        for tool_call in response.tool_calls:
            tool_name = tool_call["name"]
            tool_args = tool_call["args"]
            
            print(f"🔧 Calling tool: {tool_name} with args: {tool_args}")
            
            # Find and execute the tool
            tool = next((t for t in tools if t.name == tool_name), None)
            if tool:
                try:
                    result = await tool.ainvoke(tool_args)
                    tool_calls_log.append({
                        "tool": tool_name,
                        "args": tool_args,
                        "result": str(result)[:500]  
                    })
                    
                    # Add tool result to messages
                    from langchain_core.messages import ToolMessage
                    messages.append(
                        ToolMessage(
                            content=str(result),
                            tool_call_id=tool_call["id"]
                        )
                    )
                except Exception as e:
                    error_msg = f"Error executing tool {tool_name}: {str(e)}"
                    print(f"❌ {error_msg}")
                    messages.append(
                        ToolMessage(
                            content=error_msg,
                            tool_call_id=tool_call["id"]
                        )
                    )
    
    return {
        "output": "Max iterations reached without final answer",
        "tool_calls": tool_calls_log,
        "iterations": max_iterations
    }


@app.on_event("startup")
async def startup_event():
    """Initialize MCP client and Groq model on startup"""
    global llm, tools, mcp_client
    
    try:
        # Check for Groq API key
        groq_key = os.getenv("GROQ_API_KEY")
        if not groq_key:
            raise ValueError(
                "GROQ_API_KEY environment variable not set. "
                "Get your free key from: https://console.groq.com/"
            )
        
        print("🚀 Connecting to Wazuh MCP Server...")
        
        mcp_client = MultiServerMCPClient({
            "wazuh": {
                "transport": "sse",
                "url": "http://127.0.0.1:8000/sse/"
            }
        })
        
        tools = await mcp_client.get_tools()
        print(f"✓ Connected to MCP Server. Available tools: {len(tools)}")
        for tool in tools:
            print(f"  - {tool.name}: {tool.description}")
        
        print("🧠 Initializing Groq AI (Llama 3.1 70B)...")
        llm = ChatGroq(
            model="llama-3.3-70b-versatile",
            api_key=groq_key,
            temperature=0,
            max_tokens=4096
        )
        
        print("✓ Groq Model initialized successfully")
        print("⚡ Ready for ultra-fast responses!")
        
    except Exception as e:
        print(f"✗ Failed to initialize: {e}")
        raise


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "service": "Wazuh Chat API (Groq-Powered)",
        "ai_provider": "Groq",
        "mcp_connected": mcp_client is not None,
        "agent_ready": llm is not None,
        "speed": "⚡ Ultra-fast (500+ tokens/sec)"
    }


@app.get("/health")
async def health():
    """Detailed health check"""
    if not llm or not mcp_client:
        raise HTTPException(status_code=503, detail="Service not ready")
    
    return {
        "status": "healthy",
        "mcp_server": "http://127.0.0.1:8000",
        "ai_provider": "Groq",
        "tools_available": len(tools)
    }



@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Main chat endpoint - send natural language queries about Wazuh
    Now powered by Groq for ultra-fast responses!
    
    Example requests:
    - "Show me all active agents"
    - "What ports are open on agent 001?"
    - "List failed SCA checks"
    """
    if not llm:
        raise HTTPException(
            status_code=503,
            detail="Agent not initialized. Check server logs."
        )
    
    try:
        result = await run_agent_loop(request.message)
        
        return ChatResponse(
            response=result.get("output", "No response generated"),
            tool_calls=result.get("tool_calls", []),
            model_used=request.model or "llama-3.1-70b-versatile"
        )
        
    except Exception as e:
        print(f"Error processing chat: {e}")
        import traceback
        traceback.print_exc()
        return ChatResponse(
            response="",
            error=f"Error processing request: {str(e)}",
            model_used=request.model
        )


@app.get("/tools")
async def list_tools():
    """List all available Wazuh tools"""
    if not mcp_client:
        raise HTTPException(status_code=503, detail="MCP client not ready")
    
    try:
        return {
            "count": len(tools),
            "tools": [
                {
                    "name": tool.name,
                    "description": tool.description
                }
                for tool in tools
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    
    if not os.getenv("GROQ_API_KEY"):
        print("⚠️  GROQ_API_KEY not set!")
        print("Get your free key from: https://console.groq.com/")
        print("Set it with: export GROQ_API_KEY='gsk_...'")
        exit(1)
    
    print("Starting Wazuh Chat API (Groq-Powered)...")
    print("⚡ Ultra-fast responses with Groq!")
    print("Docs available at: http://127.0.0.1:8001/docs")
    
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="info")