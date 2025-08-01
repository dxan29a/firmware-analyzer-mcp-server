#!/usr/bin/env python3
"""
Network MCP Client for Firmware Analysis
This client connects to the network-based MCP server for firmware analysis.
"""

import asyncio
import json
import os
import ssl
import logging
from typing import Dict, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class NetworkMCPClient:
    def __init__(self, host='localhost', port=8080, use_ssl=False, verify_ssl=True):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.verify_ssl = verify_ssl
        self.reader = None
        self.writer = None
        self.request_id = 1
    
    async def connect(self):
        """Connect to the MCP server."""
        try:
            if self.use_ssl:
                context = ssl.create_default_context()
                if not self.verify_ssl:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                
                self.reader, self.writer = await asyncio.open_connection(
                    self.host, self.port, ssl=context
                )
            else:
                self.reader, self.writer = await asyncio.open_connection(
                    self.host, self.port
                )
            
            logger.info(f"Connected to MCP server at {self.host}:{self.port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to server: {e}")
            return False
    
    async def disconnect(self):
        """Disconnect from the MCP server."""
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
            logger.info("Disconnected from MCP server")
    
    async def send_request(self, method: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send a JSON-RPC request to the MCP server."""
        if not self.writer:
            logger.error("Not connected to server")
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
            self.writer.write(request_str.encode())
            await self.writer.drain()
            
            # Read response
            response_line = await self.reader.readline()
            if response_line:
                response = json.loads(response_line.decode().strip())
                return response
            else:
                logger.error("No response from server")
                return None
                
        except Exception as e:
            logger.error(f"Error communicating with server: {e}")
            return None
    
    async def initialize(self) -> bool:
        """Initialize the MCP server."""
        init_params = {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "clientInfo": {
                "name": "network-firmware-analyzer-client",
                "version": "1.0.0"
            }
        }
        
        response = await self.send_request("initialize", init_params)
        if response and "result" in response:
            logger.info("✅ Server initialized successfully")
            return True
        else:
            logger.error("❌ Failed to initialize server")
            if response:
                logger.error(f"Response: {response}")
            return False
    
    async def list_tools(self) -> Optional[Dict[str, Any]]:
        """List available tools from the MCP server."""
        response = await self.send_request("tools/list", {})
        if response and "result" in response:
            logger.info("✅ Tools listed successfully")
            return response["result"]
        else:
            logger.error("❌ Failed to list tools")
            if response:
                logger.error(f"Response: {response}")
            return None
    
    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Call a specific tool on the MCP server."""
        params = {
            "name": name,
            "arguments": arguments
        }
        
        response = await self.send_request("tools/call", params)
        if response and "result" in response:
            logger.info(f"✅ Tool '{name}' called successfully")
            return response["result"]
        else:
            logger.error(f"❌ Failed to call tool '{name}'")
            if response and "error" in response:
                logger.error(f"Error: {response['error']}")
            return None

async def analyze_firmware_network(firmware_path: str, host='localhost', port=8080, use_ssl=False):
    """Analyze firmware using the network MCP server."""
    
    # Check if firmware file exists
    if not os.path.exists(firmware_path):
        logger.error(f"❌ Firmware file not found: {firmware_path}")
        return
    
    logger.info(f"🔍 Starting firmware analysis for: {firmware_path}")
    logger.info("=" * 60)
    
    # Initialize network MCP client
    client = NetworkMCPClient(host=host, port=port, use_ssl=use_ssl)
    
    try:
        # Connect to the server
        if not await client.connect():
            return
        
        # Initialize the server
        if not await client.initialize():
            return
        
        # List available tools
        tools_result = await client.list_tools()
        if not tools_result:
            return
        
        logger.info("\n📋 Available tools:")
        for tool in tools_result.get("tools", []):
            logger.info(f"  - {tool['name']}: {tool['description']}")
        
        logger.info("\n" + "=" * 60)
        
        # Step 1: Update firmware
        logger.info("\n1️⃣ Updating firmware...")
        update_result = await client.call_tool("update_firmware", {
            "firmware_path": firmware_path
        })
        
        if update_result:
            content = update_result.get("content", [])
            for item in content:
                if item.get("type") == "text":
                    logger.info(item.get("text", ""))
        
        # Step 2: Identify file format
        logger.info("\n2️⃣ Identifying file format...")
        format_result = await client.call_tool("identify_file_format", {
            "file_path": firmware_path
        })
        
        if format_result:
            content = format_result.get("content", [])
            for item in content:
                if item.get("type") == "text":
                    logger.info(item.get("text", ""))
        
        # Step 3: Extract with binwalk
        logger.info("\n3️⃣ Extracting with binwalk...")
        binwalk_result = await client.call_tool("extract_with_binwalk", {
            "binary_path": firmware_path
        })
        
        if binwalk_result:
            content = binwalk_result.get("content", [])
            for item in content:
                if item.get("type") == "text":
                    text = item.get("text", "")
                    logger.info(text)
                    
                    # Extract the extraction directory path from the output
                    if "Extraction directory:" in text:
                        lines = text.split('\n')
                        for line in lines:
                            if "Extraction directory:" in line:
                                extract_dir = line.split("Extraction directory:")[1].strip()
                                logger.info(f"\n📁 Found extraction directory: {extract_dir}")
                                
                                # Step 4: Find password files
                                logger.info("\n4️⃣ Searching for password files...")
                                password_result = await client.call_tool("find_password_files", {
                                    "extracted_path": extract_dir
                                })
                                
                                if password_result:
                                    content = password_result.get("content", [])
                                    for item in content:
                                        if item.get("type") == "text":
                                            logger.info(item.get("text", ""))
                                
                                break
        
        logger.info("\n" + "=" * 60)
        logger.info("✅ Firmware analysis completed!")
        
    except Exception as e:
        logger.error(f"❌ Error during analysis: {e}")
    
    finally:
        # Disconnect from the server
        await client.disconnect()

def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Network MCP Client for Firmware Analysis')
    parser.add_argument('--host', default='localhost', help='MCP server host (default: localhost)')
    parser.add_argument('--port', type=int, default=8080, help='MCP server port (default: 8080)')
    parser.add_argument('--ssl', action='store_true', help='Use SSL/TLS connection')
    parser.add_argument('--firmware', required=True, help='Path to firmware file to analyze')
    
    args = parser.parse_args()
    
    firmware_path = args.firmware
    
    if not os.path.exists(firmware_path):
        logger.error(f"❌ Firmware file not found: {firmware_path}")
        return
    
    logger.info("🚀 Starting Network MCP Client for Firmware Analysis")
    logger.info(f"📁 Target file: {firmware_path}")
    logger.info(f"🌐 Server: {args.host}:{args.port}")
    if args.ssl:
        logger.info("🔒 Using SSL/TLS connection")
    
    # Run the analysis
    asyncio.run(analyze_firmware_network(
        firmware_path=firmware_path,
        host=args.host,
        port=args.port,
        use_ssl=args.ssl
    ))

if __name__ == "__main__":
    main() 