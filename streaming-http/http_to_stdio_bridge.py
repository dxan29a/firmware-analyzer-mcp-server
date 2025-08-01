#!/usr/bin/env python3
"""
HTTP to stdio bridge for MCP protocol
This script allows VS Code to connect to the HTTP MCP server via stdio.
"""

import asyncio
import json
import sys
import aiohttp
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HTTPToStdioBridge:
    def __init__(self, http_url="http://localhost:8082"):
        self.http_url = http_url
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def send_request(self, method, params=None):
        """Send request to HTTP MCP server."""
        if not self.session:
            return None
        
        url = f"{self.http_url}/mcp/{method}"
        data = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params or {}
        }
        
        try:
            async with self.session.post(url, json=data) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    logger.error(f"HTTP error: {response.status}")
                    return None
        except Exception as e:
            logger.error(f"Request failed: {e}")
            return None
    
    async def handle_stdio(self):
        """Handle stdio communication."""
        while True:
            try:
                # Read line from stdin
                line = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
                if not line:
                    break
                
                line = line.strip()
                if not line:
                    continue
                
                # Parse JSON-RPC request
                try:
                    request = json.loads(line)
                except json.JSONDecodeError:
                    logger.error(f"Invalid JSON: {line}")
                    continue
                
                method = request.get("method")
                params = request.get("params", {})
                request_id = request.get("id")
                
                # Handle different MCP methods
                if method == "initialize":
                    response = await self.send_request("initialize", params)
                elif method == "tools/list":
                    response = await self.send_request("tools/list", params)
                elif method == "tools/call":
                    response = await self.send_request("tools/call", params)
                else:
                    response = {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {
                            "code": -32601,
                            "message": f"Method not found: {method}"
                        }
                    }
                
                # Send response to stdout
                if response:
                    response["id"] = request_id
                    response_line = json.dumps(response)
                    await asyncio.get_event_loop().run_in_executor(None, lambda: sys.stdout.write(response_line + "\n"))
                    await asyncio.get_event_loop().run_in_executor(None, sys.stdout.flush)
                
            except Exception as e:
                logger.error(f"Error handling request: {e}")
                error_response = {
                    "jsonrpc": "2.0",
                    "id": request_id if 'request_id' in locals() else None,
                    "error": {
                        "code": -32603,
                        "message": f"Internal error: {str(e)}"
                    }
                }
                error_line = json.dumps(error_response)
                await asyncio.get_event_loop().run_in_executor(None, lambda: sys.stdout.write(error_line + "\n"))
                await asyncio.get_event_loop().run_in_executor(None, sys.stdout.flush)

async def main():
    """Main function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='HTTP to stdio bridge for MCP protocol')
    parser.add_argument('--url', default='http://localhost:8082', help='HTTP MCP server URL')
    
    args = parser.parse_args()
    
    async with HTTPToStdioBridge(args.url) as bridge:
        await bridge.handle_stdio()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Bridge stopped by user")
    except Exception as e:
        logger.error(f"Bridge error: {e}")
        sys.exit(1) 