#!/usr/bin/env python3
"""
Simple MCP Client Test
"""

import asyncio
import json
import subprocess
import os

async def test_mcp_communication():
    """Test basic MCP communication."""
    
    print("Testing MCP server communication...")
    
    # Start the server
    process = await asyncio.create_subprocess_exec(
        "python3", "firmware_analyzer_mcp.py",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    
    print(f"Server PID: {process.pid}")
    
    try:
        # Send initialize request
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        }
        
        request_str = json.dumps(init_request) + "\n"
        print(f"Sending: {request_str.strip()}")
        
        process.stdin.write(request_str.encode())
        await process.stdin.drain()
        
        # Read response
        response_line = await process.stdout.readline()
        if response_line:
            print(f"Received: {response_line.decode().strip()}")
            response = json.loads(response_line.decode().strip())
            print(f"Parsed response: {response}")
        else:
            print("No response received")
        
        # Try different method names for listing tools
        methods_to_try = ["tools/list", "list_tools", "tools.list"]
        
        for method in methods_to_try:
            print(f"\nTrying method: {method}")
            
            tools_request = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": method,
                "params": {}
            }
            
            request_str = json.dumps(tools_request) + "\n"
            print(f"Sending: {request_str.strip()}")
            
            process.stdin.write(request_str.encode())
            await process.stdin.drain()
            
            # Read response
            response_line = await process.stdout.readline()
            if response_line:
                print(f"Received: {response_line.decode().strip()}")
                response = json.loads(response_line.decode().strip())
                print(f"Parsed response: {response}")
                
                if "result" in response:
                    print(f"✅ Success with method: {method}")
                    break
                else:
                    print(f"❌ Failed with method: {method}")
            else:
                print("No response received")
        
    except Exception as e:
        print(f"Error: {e}")
    
    finally:
        process.terminate()
        await process.wait()
        print("Server stopped")

if __name__ == "__main__":
    asyncio.run(test_mcp_communication()) 