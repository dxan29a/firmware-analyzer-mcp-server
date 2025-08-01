#!/usr/bin/env python3
"""
MCP Client Script for Firmware Analysis
This script mimics an MCP client to call the firmware analyzer MCP server functions.
"""

import asyncio
import json
import subprocess
import sys
import os
from typing import Dict, Any, Optional

class MCPClient:
    def __init__(self, server_command: str):
        self.server_command = server_command
        self.process = None
        self.request_id = 1
    
    async def start_server(self):
        """Start the MCP server process."""
        try:
            self.process = await asyncio.create_subprocess_exec(
                *self.server_command.split(),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            print(f"Started MCP server with PID: {self.process.pid}")
            return True
        except Exception as e:
            print(f"Failed to start MCP server: {e}")
            return False
    
    async def send_request(self, method: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send a JSON-RPC request to the MCP server."""
        if not self.process:
            print("Server not started")
            return None
        
        request = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method,
            "params": params
        }
        
        self.request_id += 1
        
        try:
            # Send request
            request_str = json.dumps(request) + "\n"
            print(f"Sending request: {method}")
            self.process.stdin.write(request_str.encode())
            await self.process.stdin.drain()
            
            # Read response
            response_line = await self.process.stdout.readline()
            if response_line:
                response = json.loads(response_line.decode().strip())
                print(f"Received response for {method}")
                return response
            else:
                print("No response from server")
                return None
                
        except Exception as e:
            print(f"Error communicating with server: {e}")
            return None
    
    async def initialize(self) -> bool:
        """Initialize the MCP server."""
        init_params = {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "clientInfo": {
                "name": "firmware-analyzer-client",
                "version": "1.0.0"
            }
        }
        
        response = await self.send_request("initialize", init_params)
        if response and "result" in response:
            print("✅ Server initialized successfully")
            return True
        else:
            print("❌ Failed to initialize server")
            if response:
                print(f"Response: {response}")
            return False
    
    async def list_tools(self) -> Optional[Dict[str, Any]]:
        """List available tools from the MCP server."""
        response = await self.send_request("tools/list", {})
        if response and "result" in response:
            print("✅ Tools listed successfully")
            return response["result"]
        else:
            print("❌ Failed to list tools")
            if response:
                print(f"Response: {response}")
            return None
    
    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Call a specific tool on the MCP server."""
        params = {
            "name": name,
            "arguments": arguments
        }
        
        response = await self.send_request("tools/call", params)
        if response and "result" in response:
            print(f"✅ Tool '{name}' called successfully")
            return response["result"]
        else:
            print(f"❌ Failed to call tool '{name}'")
            if response and "error" in response:
                print(f"Error: {response['error']}")
            return None
    
    async def stop_server(self):
        """Stop the MCP server process."""
        if self.process:
            self.process.terminate()
            await self.process.wait()
            print("Server stopped")

async def analyze_firmware(firmware_path: str):
    """Main function to analyze firmware using the MCP server."""
    
    # Check if firmware file exists
    if not os.path.exists(firmware_path):
        print(f"❌ Firmware file not found: {firmware_path}")
        return
    
    print(f"🔍 Starting firmware analysis for: {firmware_path}")
    print("=" * 60)
    
    # Initialize MCP client
    client = MCPClient("python3 firmware_analyzer_mcp.py")
    
    try:
        # Start the server
        if not await client.start_server():
            return
        
        # Initialize the server
        if not await client.initialize():
            return
        
        # List available tools
        tools_result = await client.list_tools()
        if not tools_result:
            return
        
        print("\n📋 Available tools:")
        for tool in tools_result.get("tools", []):
            print(f"  - {tool['name']}: {tool['description']}")
        
        print("\n" + "=" * 60)
        
        # Step 1: Update firmware
        print("\n1️⃣ Updating firmware...")
        update_result = await client.call_tool("update_firmware", {
            "firmware_path": firmware_path
        })
        
        if update_result:
            content = update_result.get("content", [])
            for item in content:
                if item.get("type") == "text":
                    print(item.get("text", ""))
        
        # Step 2: Identify file format
        print("\n2️⃣ Identifying file format...")
        format_result = await client.call_tool("identify_file_format", {
            "file_path": firmware_path
        })
        
        if format_result:
            content = format_result.get("content", [])
            for item in content:
                if item.get("type") == "text":
                    print(item.get("text", ""))
        
        # Step 3: Extract with binwalk (if it's a binary file)
        print("\n3️⃣ Extracting with binwalk...")
        binwalk_result = await client.call_tool("extract_with_binwalk", {
            "binary_path": firmware_path
        })
        
        if binwalk_result:
            content = binwalk_result.get("content", [])
            for item in content:
                if item.get("type") == "text":
                    text = item.get("text", "")
                    print(text)
                    
                    # Extract the extraction directory path from the output
                    if "Extraction directory:" in text:
                        lines = text.split('\n')
                        for line in lines:
                            if "Extraction directory:" in line:
                                extract_dir = line.split("Extraction directory:")[1].strip()
                                print(f"\n📁 Found extraction directory: {extract_dir}")
                                
                                # Step 4: Find password files
                                print("\n4️⃣ Searching for password files...")
                                password_result = await client.call_tool("find_password_files", {
                                    "extracted_path": extract_dir
                                })
                                
                                if password_result:
                                    content = password_result.get("content", [])
                                    for item in content:
                                        if item.get("type") == "text":
                                            print(item.get("text", ""))
                                
                                break
        
        print("\n" + "=" * 60)
        print("✅ Firmware analysis completed!")
        
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
    
    finally:
        # Stop the server
        await client.stop_server()

def main():
    """Main entry point."""
    firmware_path = "/home/alan/Downloads/A8000RU_V7.1cu.643_B20200521.zip"
    
    if not os.path.exists(firmware_path):
        print(f"❌ Firmware file not found: {firmware_path}")
        print("Please make sure the file exists and the path is correct.")
        return
    
    print("🚀 Starting MCP Client for Firmware Analysis")
    print(f"📁 Target file: {firmware_path}")
    
    # Run the analysis
    asyncio.run(analyze_firmware(firmware_path))

if __name__ == "__main__":
    main() 