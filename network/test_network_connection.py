#!/usr/bin/env python3
"""
Simple Network Connection Test
"""

import asyncio
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_network_connection():
    """Test basic network connection to MCP server."""
    
    logger.info("Testing network connection to MCP server...")
    
    try:
        # Connect to the server
        reader, writer = await asyncio.open_connection('localhost', 8080)
        logger.info("Connected to server")
        
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
                    "name": "test-network-client",
                    "version": "1.0.0"
                }
            }
        }
        
        request_str = json.dumps(init_request) + "\n"
        logger.info(f"Sending: {request_str.strip()}")
        
        writer.write(request_str.encode())
        await writer.drain()
        
        # Read response
        response_line = await reader.readline()
        if response_line:
            logger.info(f"Received: {response_line.decode().strip()}")
            response = json.loads(response_line.decode().strip())
            logger.info(f"Parsed response: {response}")
        else:
            logger.error("No response received")
        
        # Send tools/list request
        tools_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }
        
        request_str = json.dumps(tools_request) + "\n"
        logger.info(f"Sending: {request_str.strip()}")
        
        writer.write(request_str.encode())
        await writer.drain()
        
        # Read response
        response_line = await reader.readline()
        if response_line:
            logger.info(f"Received: {response_line.decode().strip()}")
            response = json.loads(response_line.decode().strip())
            logger.info(f"Parsed response: {response}")
        else:
            logger.error("No response received")
        
    except Exception as e:
        logger.error(f"Error: {e}")
    
    finally:
        if 'writer' in locals():
            writer.close()
            await writer.wait_closed()
            logger.info("Connection closed")

if __name__ == "__main__":
    asyncio.run(test_network_connection()) 